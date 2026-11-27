package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAdminRecoveryInput struct {
	target                       sharedpg.WorkspaceRecoveryTarget
	kit, bundle, login, device   string
	appVersion                   string
	code, deployer, account, ask []byte
}

func sharedAdminRecoveryPath(database string) string { return database + ".shared-admin-recovery" }

func (i *sharedAdminRecoveryInput) wipe() {
	for _, factor := range [][]byte{i.code, i.deployer, i.account, i.ask} {
		vault.Wipe(factor)
	}
}

func decodeSharedAdminRecovery(payload []byte) (i sharedAdminRecoveryInput, err error) {
	var code, deployer, account, ask json.RawMessage
	var workspace string
	var consent bool
	defer func() {
		for _, encoded := range []json.RawMessage{code, deployer, account, ask} {
			vault.Wipe(encoded)
		}
		if err != nil {
			i.wipe()
		}
	}()
	target := &i.target
	if len(payload) > 32*1024 || decodeVaultObject(payload, map[string]any{
		"workspaceId": &workspace, "host": &target.Endpoint.Host, "port": &target.Endpoint.Port,
		"database": &target.Database, "role": &target.DeployerRole, "kitPath": &i.kit, "trustPath": &i.bundle,
		"loginName": &i.login, "deviceName": &i.device, "appVersion": &i.appVersion, "confirmed": &consent,
		"recoveryCode": &code, "deployerPassword": &deployer, "accountPassword": &account, "ask": &ask,
	}, "workspaceId", "host", "port", "database", "role", "kitPath", "trustPath", "loginName", "deviceName", "appVersion",
		"confirmed", "recoveryCode", "deployerPassword", "accountPassword") != nil ||
		!consent || !sharedFilePathValid(i.kit, ".whrecovery") || !sharedTLSBundlePathValid(i.bundle) {
		return i, vaultwire.ErrProtocol
	}
	for _, f := range []struct {
		raw json.RawMessage
		out *[]byte
	}{{code, &i.code}, {deployer, &i.deployer}, {account, &i.account}, {ask, &i.ask}} {
		if len(f.raw) != 0 && (f.raw[0] != '"' || json.Unmarshal(f.raw, f.out) != nil) {
			return i, vaultwire.ErrProtocol
		}
	}
	id, parseErr := uuid.Parse(workspace)
	if parseErr != nil || id == uuid.Nil || id.String() != workspace || len(i.code) != 76 ||
		!validSharedRecoveryPassword(i.deployer) || !validSharedRecoveryPassword(i.account) ||
		(len(ask) != 0 && len(i.ask) != 32) || len(i.device) == 0 || len(i.device) > 4096 ||
		!utf8.ValidString(i.device) || strings.IndexFunc(i.device, unicode.IsControl) >= 0 ||
		(sharedpg.AdmissionRequest{WorkspaceID: id, UserID: id, DeviceID: id, API: 1, AppVersion: i.appVersion, Source: "ui"}).Validate() != nil {
		return i, vaultwire.ErrProtocol
	}
	target.WorkspaceID = id
	return i, nil
}

func validSharedRecoveryPassword(value []byte) bool {
	return len(value) > 0 && len(value) <= 1024 && utf8.Valid(value) && bytes.IndexByte(value, 0) < 0
}

func (h *vaultFoundationHandler) recoverSharedAdministrator(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner != nil || h.shared != nil || h.sharedSelection != nil || h.enrollment != nil || h.rotationMaterial != nil || h.migrationQuiesced ||
		!filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath {
		return nil, vaultwire.ErrProtocol
	}
	input, err := decodeSharedAdminRecovery(payload)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(floor); err != nil {
		return nil, err
	}
	path := sharedAdminRecoveryPath(h.databasePath)
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		return nil, errSharedTrustConflict
	}
	defer release()
	sealed, err := readSharedTrustBytes(path, sharedpg.MaxWorkspaceAdminRecoveryCheckpointBytes)
	missing := errors.Is(err, errSharedTrustMissing)
	if err != nil && !missing {
		return nil, err
	}
	if missing {
		if err := requireNewVaultWorkspace(h.databasePath); err != nil {
			return nil, err
		}
	} else {
		if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
			return nil, err
		}
		for _, path := range []string{h.databasePath, vaultSlotPath(h.databasePath)} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return nil, errVaultOwnerRequired
			}
		}
	}
	kit, err := readSharedTrustBytes(input.kit, sharedpg.MaxWorkspaceRecoveryKitBytes)
	if err != nil {
		return nil, err
	}
	trust, err := readSharedTrustBytes(input.bundle, sharedpg.MaxTLSTrustBundleBytes)
	if err != nil {
		return nil, err
	}
	var draft *sharedpg.PreparedWorkspaceRecovery
	if missing {
		draft, err = sharedpg.PrepareWorkspaceRecovery(ctx, input.target, kit, input.code, trust, input.deployer, input.login)
	} else {
		draft, err = sharedpg.OpenWorkspaceRecoveryCheckpoint(input.target, kit, input.code, trust, sealed)
	}
	if err != nil {
		return nil, err
	}
	defer draft.Close()
	if draft.LoginName() != input.login {
		return nil, errSharedTrustConflict
	}
	if missing {
		if err := publishSharedSetupFile(path, draft.Checkpoint()); err != nil {
			return nil, errSharedTrustStorage
		}
	} else if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
		return nil, errSharedTrustStorage
	}
	if err := draft.Publish(ctx, input.deployer); err != nil {
		return nil, err
	}
	var receipt json.RawMessage
	err = draft.BorrowJoin(func(invitation sharedpg.Invitation, code []byte) error {
		join := sharedInitialJoinInput{invitation: invitation, code: code, password: input.account, ask: input.ask,
			deviceName: input.device, appVersion: input.appVersion}
		var err error
		receipt, err = h.admitSharedSetupDestination(ctx, join)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		return nil, h.retire(errSharedTrustStorage)
	}
	return receipt, nil
}
