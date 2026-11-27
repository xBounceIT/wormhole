package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type sharedWorkspaceRecoveryKitSession interface {
	sharedRuntimeStateSession
	RefreshWorkspaceRecoveryKit(context.Context, sharedpg.TrustState, *sharedpg.VerifiedTLSBundle, []byte, []byte, []byte) ([]byte, error)
}

func (h *vaultFoundationHandler) refreshSharedRecoveryKit(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var source, destination string
	var auth vaultUnlockInput
	defer auth.wipe()
	var encoded json.RawMessage
	defer func() { vault.Wipe(encoded) }()
	if len(payload) > 32*1024 || decodeVaultObject(payload, map[string]any{"source": &source, "destination": &destination, "authentication": &encoded}, "source", "destination") != nil ||
		!sharedFilePathValid(source, ".whrecovery") || !sharedFilePathValid(destination, ".whrecovery") {
		return nil, vaultwire.ErrProtocol
	}
	if encoded != nil {
		var err error
		auth, err = decodeSharedExportAuthentication(encoded)
		if err != nil {
			return nil, err
		}
	}
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := controller.session.(sharedWorkspaceRecoveryKitSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	status := "unavailable"
	err = controller.withWorkspaceTrust(ctx, session, func(ctx context.Context, trust sharedpg.TrustState, bundle *sharedpg.VerifiedTLSBundle) error {
		if bundle == nil || len(bundle.PendingServerCertificate()) != 0 {
			return nil
		}
		if source == destination {
			status = "save-failed"
			return nil
		}
		existing, err := readSharedTrustBytes(source, sharedpg.MaxWorkspaceRecoveryKitBytes)
		if err != nil || len(existing) == 0 || len(existing) > sharedpg.MaxWorkspaceRecoveryKitBytes {
			status = "invalid-kit"
			return nil
		}
		if controller.runtimeProfile == vault.Standard {
			if encoded == nil {
				status = "authentication-required"
				return nil
			}
			valid, err := h.verifySharedExportFactors(ctx, controller, trust.Revision, auth)
			if err != nil {
				return err
			}
			if !valid {
				status = "invalid-authentication"
				return nil
			}
		}
		var updated []byte
		err = controller.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrAuthentication
			}
			var err error
			updated, err = session.RefreshWorkspaceRecoveryKit(ctx, trust, bundle, existing, keys[:32:32], keys[32:])
			return err
		})
		switch {
		case errors.Is(err, sharedpg.ErrServerCertificateAuthority):
			return nil
		case errors.Is(err, sharedpg.ErrWorkspaceRecoveryKit):
			status = "invalid-kit"
			return nil
		case err != nil:
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		status = "updated"
		if err := publishSharedSetupFile(destination, updated); err != nil {
			status = "save-failed"
		}
		return nil
	})
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(status)
}

func decodeSharedExportAuthentication(encoded json.RawMessage) (vaultUnlockInput, error) {
	var authentication []byte
	defer func() { vault.Wipe(authentication) }()
	if len(encoded) == 0 || encoded[0] != '"' || json.Unmarshal(encoded, &authentication) != nil {
		return vaultUnlockInput{}, vaultwire.ErrProtocol
	}
	auth, err := decodeVaultUnlock(authentication)
	if err != nil || auth.VaultID == "" || auth.SlotID == "" || len(auth.Password) == 0 || len(auth.RecoveryKey) != 0 || len(auth.RecoveryCode) != 0 {
		auth.wipe()
		return vaultUnlockInput{}, vaultwire.ErrProtocol
	}
	return auth, nil
}

// Reopen the selected device from disk without a second PostgreSQL admission.
// The operation holds the controller gate and has already saved fresh trust.
// No reusable authorization or factor survives the export request.
func (h *vaultFoundationHandler) verifySharedExportFactors(ctx context.Context, c *sharedAdmissionController, revision uint64, auth vaultUnlockInput) (bool, error) {
	if h.shared.selected == nil {
		return false, sharedpg.ErrTrustState
	}
	if auth.VaultID != h.shared.vaultID {
		return false, nil
	}
	options := h.shared.selected.options
	protection := h.startupProtection()
	anchor, err := readSharedStartupAnchor(options.TrustPath, protection)
	if err != nil {
		return false, err
	}
	if anchor.Binding != c.trustBinding || anchor.VaultID != h.shared.vaultID || anchor.FileID != h.shared.fileID {
		return false, sharedpg.ErrTrustState
	}
	if anchor.ASKRequired != (len(auth.ASK) != 0) {
		return false, nil
	}
	options.OSFloor, options.UserFloor, options.MinimumRevision = c.runtimeOSFloor, c.runtimeUserFloor, revision
	candidate, err := unlockSharedSelectedDevice(ctx, options, auth.SlotID, auth.Password, auth.ASK, sharedDeviceOrdinary, protection)
	if err != nil {
		if candidate != nil {
			return false, errors.Join(err, candidate.Close())
		}
		if errors.Is(err, vault.ErrAuthentication) || errors.Is(err, vault.ErrPolicy) {
			return false, nil
		}
		return false, err
	}
	valid := false
	err = candidate.account.Borrow(func(_ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		if candidate.vaultID != h.shared.vaultID || candidate.options.MinimumRevision != revision || root.Binding() != c.trustBinding {
			return sharedpg.ErrTrustState
		}
		return root.Use(func(fresh []byte) error {
			return c.root.With(func(current []byte) error {
				valid = subtle.ConstantTimeCompare(current, fresh) == 1
				return nil
			})
		})
	})
	return valid, errors.Join(err, candidate.Close())
}
