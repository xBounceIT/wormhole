package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedAdminRecoveryDisplay struct {
	VaultID      string             `json:"vaultId"`
	EnrollmentID string             `json:"enrollmentId"`
	Groups       [2]int             `json:"groups"`
	Bundle       vault.SealedBundle `json:"bundle"`
}

type sharedAdminSetupInput struct {
	account, ask, dba, recipient, groups  []byte
	role, login, path, enrollment, device string
	appVersion                            string
	importConfirmation                    string
	profile                               vault.Profile
	directConnectionDevices               uint32
}

func (i *sharedAdminSetupInput) wipe() {
	vault.Wipe(i.account)
	vault.Wipe(i.ask)
	vault.Wipe(i.dba)
	vault.Wipe(i.groups)
}

func sharedAdminCheckpointPath(path string) string { return path + ".administrator" }

func sharedAdminCheckpointExists(path string) (bool, error) {
	info, err := os.Lstat(sharedAdminCheckpointPath(path))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > sharedpg.MaxWorkspaceBootstrapCheckpointBytes {
		return false, errSharedTrustStorage
	}
	return true, nil
}

func sharedAdminCheckpointScope(plan sharedSetupPlan) (sharedpg.WorkspaceBootstrapScope, error) {
	// SQL export and execution can change the public deployment stage. Only
	// immutable coordinates, including the local path and explicit CA, bind it.
	plan.Summary.State = setupPrepared
	plan.ServerKit = nil
	if plan.TLS != nil {
		draft := *plan.TLS
		draft.Protection = nil
		plan.TLS = &draft
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return sharedpg.WorkspaceBootstrapScope{}, err
	}
	return sharedpg.WorkspaceBootstrapScope{WorkspaceID: uuid.MustParse(plan.Summary.WorkspaceID), RoleTag: plan.Summary.RoleTag, PlanDigest: sha256.Sum256(raw)}, nil
}

func decodeSharedAdminSetup(op string, payload []byte, workspace string) (input sharedAdminSetupInput, err error) {
	var id string
	var account, ask, dba, recipient, groups json.RawMessage
	defer func() {
		for _, raw := range []json.RawMessage{account, ask, dba, groups} {
			vault.Wipe(raw)
		}
		if err != nil {
			input.wipe()
		}
	}()
	fields := map[string]any{"workspaceId": &id, "accountPassword": &account, "ask": &ask}
	required := []string{"workspaceId", "accountPassword"}
	add := func(key string, out any) {
		fields[key] = out
		required = append(required, key)
	}
	switch op {
	case "shared-setup-admin-prepare":
		add("loginName", &input.login)
		add("profile", &input.profile)
		fields["directConnectionDevices"] = &input.directConnectionDevices
		fallthrough
	case "shared-setup-admin-publish":
		add("role", &input.role)
		add("password", &dba)
	case "shared-setup-admin-recovery":
		add("path", &input.path)
		add("recipient", &recipient)
	case "shared-setup-admin-confirm":
		add("enrollmentId", &input.enrollment)
		add("groups", &groups)
	case "shared-setup-admin-join":
		add("deviceName", &input.device)
		add("appVersion", &input.appVersion)
		fields["importConfirmation"] = &input.importConfirmation
	case "shared-setup-admin-open", "shared-setup-admin-import-start":
	default:
		return input, vaultwire.ErrProtocol
	}
	if len(payload) > 12*1024 || decodeVaultObject(payload, fields, required...) != nil || id != workspace ||
		(input.importConfirmation != "" && !vaultCredentialID(input.importConfirmation)) {
		return input, vaultwire.ErrProtocol
	}
	for _, f := range []struct {
		raw json.RawMessage
		dst *[]byte
	}{{account, &input.account}, {ask, &input.ask}, {dba, &input.dba}, {recipient, &input.recipient}, {groups, &input.groups}} {
		if len(f.raw) != 0 && (f.raw[0] != '"' || json.Unmarshal(f.raw, f.dst) != nil) {
			return input, vaultwire.ErrProtocol
		}
	}
	if len(input.account) == 0 || len(input.account) > 1024 || (len(ask) != 0 && len(input.ask) != 32) ||
		(len(dba) != 0 && (len(input.dba) == 0 || len(input.dba) > 1024 || !utf8.Valid(input.dba) || bytes.ContainsRune(input.dba, 0))) ||
		(len(recipient) != 0 && len(input.recipient) != 32) || (len(groups) != 0 && len(input.groups) != 10) {
		return input, vaultwire.ErrProtocol
	}
	return input, nil
}

func persistSharedAdminCheckpoint(path string, checkpoint *sharedpg.WorkspaceBootstrapCheckpoint, create bool) error {
	raw, err := checkpoint.Seal()
	if err != nil {
		return err
	}
	path = sharedAdminCheckpointPath(path)
	if create {
		return publishSharedSetupFile(path, raw)
	}
	if err := writePrivateFileAtomic(path, raw); err != nil {
		if privateFileDestinationWasReplaced(err) {
			return errSharedTrustCommitUncertain
		}
		return errSharedTrustStorage
	}
	return nil
}

func openSharedAdminCheckpoint(ctx context.Context, path string, scope sharedpg.WorkspaceBootstrapScope, i sharedAdminSetupInput) (*sharedpg.WorkspaceBootstrapCheckpoint, error) {
	file, err := readSharedTrustBytes(sharedAdminCheckpointPath(path), sharedpg.MaxWorkspaceBootstrapCheckpointBytes)
	if err != nil {
		return nil, err
	}
	return sharedpg.OpenWorkspaceBootstrapCheckpoint(ctx, scope, file, i.account, i.ask)
}

func (h *vaultFoundationHandler) sharedSetupAdministrator(ctx context.Context, path string, plan sharedSetupPlan, operation string, payload []byte) (json.RawMessage, error) {
	if plan.Summary.State == setupPrepared || (plan.ServerKit != nil && plan.ServerKit.State == serverKitPending) {
		return nil, errSharedTrustConflict
	}
	input, err := decodeSharedAdminSetup(operation, payload, plan.Summary.WorkspaceID)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	scope, err := sharedAdminCheckpointScope(plan)
	if err != nil {
		return nil, err
	}
	if operation == "shared-setup-admin-prepare" {
		return prepareSharedSetupAdministrator(ctx, path, plan, scope, input, h.startupProtection())
	}
	checkpoint, err := openSharedAdminCheckpoint(ctx, path, scope, input)
	if err != nil {
		return nil, err
	}
	defer checkpoint.Close()
	if err := retireWorkspaceTLSDraft(path, plan, h.startupProtection()); err != nil {
		return nil, err
	}
	reply := sharedSetupReply{Plan: &plan.Summary, AdminPending: true}
	switch operation {
	case "shared-setup-admin-open":
	case "shared-setup-admin-import-start":
		return h.startSharedSetupImport(ctx, plan, checkpoint)
	case "shared-setup-admin-recovery":
		reply.Recovery, err = exportSharedAdminRecovery(path, plan, checkpoint, input)
	case "shared-setup-admin-confirm":
		if checkpoint.Status().EnrollmentID != input.enrollment {
			return nil, vaultwire.ErrProtocol
		}
		if err = checkpoint.ConfirmRecoveryCustody(input.groups); err == nil {
			err = persistSharedAdminCheckpoint(path, checkpoint, false)
		}
	case "shared-setup-admin-publish":
		floor, err := ospolicy.ReadFloor(ctx)
		if err != nil {
			return nil, err
		}
		if err := sharedAdmissionRuntimeProfile(floor); err != nil {
			return nil, err
		}
		// A confirmed rename can be visible even when its directory sync was
		// interrupted. Re-establish durability before dispatching to PostgreSQL.
		if err := privateFileDirectorySync(filepath.Dir(path)); err != nil {
			return nil, errSharedTrustStorage
		}
		if err := checkpoint.Publish(ctx, input.role, input.dba); err != nil {
			reply.Failure = setupFailure(err)
		} else if err := persistSharedAdminCheckpoint(path, checkpoint, false); err != nil {
			return nil, err
		}
	case "shared-setup-admin-join":
		return h.joinSharedSetupAdministrator(ctx, input, checkpoint)
	default:
		return nil, vaultwire.ErrProtocol
	}
	if err != nil {
		return nil, err
	}
	status := checkpoint.Status()
	reply.Administrator = &status
	return json.Marshal(reply)
}

func prepareSharedSetupAdministrator(ctx context.Context, path string, plan sharedSetupPlan, scope sharedpg.WorkspaceBootstrapScope, input sharedAdminSetupInput, protection sharedStartupProtection) (json.RawMessage, error) {
	if pending, err := sharedAdminCheckpointExists(path); pending || err != nil {
		return nil, errSharedTrustConflict
	}
	if input.profile != vault.Default && input.profile != vault.Standard {
		return nil, vault.ErrPolicy
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return nil, err
	}
	profile := vault.EffectiveProfile(floor, input.profile, vault.Default)
	if err := sharedAdmissionRuntimeProfile(profile); err != nil {
		return nil, err
	}
	s := &plan.Summary
	settings := sharedpg.Settings{Endpoints: []sharedpg.Endpoint{{Host: s.Host, Port: s.Port}}, Database: s.Database, DeviceRole: input.role, TLS: sharedpg.TLSVerified, CAPEM: plan.CAPEM, Profile: profile}
	settings.Changes = sharedpg.ChangePolicy{ConcurrentDevices: input.directConnectionDevices, TransactionPooler: input.directConnectionDevices == 0}
	var tls *sharedpg.WorkspaceTLSInstallation
	if plan.TLS != nil {
		tlsScope, err := sharedSetupTLSScope(plan)
		if err != nil {
			return nil, err
		}
		tls = &sharedpg.WorkspaceTLSInstallation{Scope: tlsScope, Draft: plan.TLS}
	}
	checkpoint, err := sharedpg.PrepareWorkspaceBootstrapCheckpoint(ctx, scope, settings, input.dba, input.account, input.ask, input.login, profile, tls)
	if err != nil {
		return json.Marshal(sharedSetupReply{Plan: s, Failure: setupFailure(err)})
	}
	defer checkpoint.Close()
	if err := persistSharedAdminCheckpoint(path, checkpoint, true); err != nil {
		return nil, err
	}
	if err := retireWorkspaceTLSDraft(path, plan, protection); err != nil {
		return nil, err
	}
	status := checkpoint.Status()
	return json.Marshal(sharedSetupReply{Plan: s, AdminPending: true, Administrator: &status})
}

func exportSharedAdminRecovery(path string, plan sharedSetupPlan, checkpoint *sharedpg.WorkspaceBootstrapCheckpoint, input sharedAdminSetupInput) (*sharedAdminRecoveryDisplay, error) {
	if !filepath.IsAbs(input.path) || filepath.Clean(input.path) != input.path || len(input.path) > 4096 ||
		!strings.EqualFold(filepath.Ext(input.path), ".whrecovery") || strings.ContainsRune(input.path, 0) {
		return nil, vaultwire.ErrProtocol
	}
	kit, groups, bundle, err := checkpoint.PrepareRecovery(input.recipient)
	if err != nil {
		return nil, err
	}
	if err := publishSharedSetupFile(input.path, kit); err != nil {
		return nil, errSharedTrustStorage
	}
	if err := checkpoint.MarkRecoveryExported(); err != nil {
		return nil, err
	}
	if err := persistSharedAdminCheckpoint(path, checkpoint, false); err != nil {
		return nil, err
	}
	return &sharedAdminRecoveryDisplay{plan.Summary.WorkspaceID, checkpoint.Status().EnrollmentID, groups, bundle}, nil
}

func (h *vaultFoundationHandler) joinSharedSetupAdministrator(ctx context.Context, input sharedAdminSetupInput, checkpoint *sharedpg.WorkspaceBootstrapCheckpoint) (json.RawMessage, error) {
	var receipt json.RawMessage
	err := checkpoint.BorrowJoin(func(i sharedpg.Invitation, code []byte) error {
		var err error
		join := sharedInitialJoinInput{invitation: i, code: code, password: input.account, ask: input.ask, deviceName: input.device, appVersion: input.appVersion}
		if input.importConfirmation != "" {
			review := h.setupImport
			if h.owner == nil || review == nil || review.prepared == nil || review.confirmation.String() != input.importConfirmation ||
				review.target != workspaceSetupImportTarget(i) {
				return vaultwire.ErrProtocol
			}
			join.importPlan = review.prepared
		}
		if h.owner != nil {
			receipt, err = h.selectLocalSharedDestination(ctx, join)
			if err == nil {
				h.setupImport = nil
			}
		} else {
			receipt, err = h.joinSharedInitialInput(ctx, join)
		}
		return err
	})
	return receipt, err
}
