package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedResetInput struct {
	code, password, ask               []byte
	offerPath, deviceName, appVersion string
}

func (input *sharedResetInput) wipe() {
	vault.Wipe(input.code)
	vault.Wipe(input.password)
	vault.Wipe(input.ask)
}

func (h *vaultFoundationHandler) redeemSharedAccountReset(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var input sharedResetInput
	defer input.wipe()
	if len(payload) > 64*1024 ||
		decodeVaultObject(payload, map[string]any{"offerPath": &input.offerPath, "code": &input.code, "password": &input.password,
			"ask": &input.ask, "deviceName": &input.deviceName, "appVersion": &input.appVersion},
			"offerPath", "code", "password", "ask", "deviceName", "appVersion") != nil ||
		!sharedFilePathValid(input.offerPath, ".whreset") || len(input.code) != vault.InviteCodeBytes || len(input.ask) != 32 ||
		len(input.password) == 0 || len(input.password) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	factors, err := h.stageAndRedeemAccountReset(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("stage and redeem account reset: %w", err)
	}
	reply, err := sharedEnrollmentReply(h.openSharedInput(ctx, "shared-recover-enrollment", factors, input.appVersion, nil, false, ""))
	if err != nil {
		return nil, fmt.Errorf("open reset device: %w", err)
	}
	return reply, nil
}

func (h *vaultFoundationHandler) stageAndRedeemAccountReset(ctx context.Context, input sharedResetInput) (factors vaultUnlockInput, err error) {
	if ctx == nil || h.closed || h.shared != nil || h.owner != nil || h.enrollment != nil || h.rotationMaterial != nil ||
		h.releaseWorkspace != nil || h.migrationQuiesced || h.sharedSelection != nil ||
		!filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath {
		return factors, vaultwire.ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return factors, err
	}
	if err := sharedAdmissionRuntimeProfile(floor); err != nil {
		return factors, err
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return factors, err
	}
	defer release()
	if err := requireNewVaultWorkspace(h.databasePath); err != nil {
		return factors, err
	}
	offer, err := readSharedTrustBytes(input.offerPath, sharedpg.MaxAccountResetOfferBytes)
	if err != nil || len(offer) == 0 || len(offer) > sharedpg.MaxAccountResetOfferBytes {
		return factors, sharedpg.ErrAccountRecovery
	}
	prepared, err := sharedpg.PrepareAccountResetRedemption(ctx, offer, input.code, input.ask, input.password, input.deviceName, floor, vault.Default)
	if prepared != nil {
		defer func() { err = errors.Join(err, prepared.Close()) }()
	}
	if err != nil {
		return factors, err
	}
	checkpoint, err := prepared.DeviceCheckpoint()
	if err != nil {
		return factors, err
	}
	binding := checkpoint.Binding
	request := sharedpg.AdmissionRequest{API: 1, Source: "ui", AppVersion: input.appVersion,
		WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, DeviceID: binding.DeviceID}
	if request.Validate() != nil {
		return factors, vaultwire.ErrProtocol
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(checkpoint.DeviceFile)
	if err != nil || len(slots.Slots) != 1 {
		return factors, sharedpg.ErrTrustState
	}
	_, err = prepared.Commit(ctx, func(p sharedpg.PendingAccountReset) error {
		if p.DeviceID != binding.DeviceID {
			return sharedpg.ErrTrustState
		}
		return publishSharedResetCheckpoint(ctx, sharedWorkspaceTrustPath(h.databasePath), checkpoint, h.startupProtection())
	})
	if err != nil {
		return factors, err
	}
	return vaultUnlockInput{VaultID: slots.VaultID, SlotID: slots.Slots[0].ID, Password: input.password, ASK: input.ask}, nil
}

func publishSharedResetCheckpoint(ctx context.Context, path string, checkpoint sharedpg.ResetDeviceCheckpoint, protection sharedStartupProtection) error {
	digest := sha256.Sum256([]byte(path))
	initial := sharedJoinStartup{Purpose: "wormhole/shared-account-reset/v1", FormatVersion: 4,
		PathDigest: digest[:], Binding: checkpoint.Binding, LoginName: checkpoint.LoginName, DeviceFile: checkpoint.DeviceFile,
		Transport: checkpoint.Transport, Pending: checkpoint.Pending}
	o := sharedAdmissionOptions{TrustPath: path, Binding: checkpoint.Binding, Settings: sharedpg.Settings{TLSBundle: checkpoint.TLS}}
	publication, err := publishSharedInitialBundle(ctx, o, initial, protection)
	if err != nil && publication != nil && !publication.published {
		return errors.Join(err, publication.cleanup())
	}
	return err
}
