package main

import (
	"context"
	"encoding/json"
	"math"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultSharedRuntime struct {
	VaultID        string                  `json:"vaultId"`
	WorkspaceID    string                  `json:"workspaceId"`
	Security       vaultSecurityProjection `json:"security"`
	TLS            sharedpg.TLSMode        `json:"tls"`
	RecoveryBackup bool                    `json:"recoveryBackup,omitempty"`
	Administrator  bool                    `json:"administrator,omitempty"`
}

// The personal choice belongs to the selected enrollment. Match the policy
// shown in the protected prompt and re-open this device's password/ASK slot.
func (h *vaultFoundationHandler) tightenSharedProfile(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var sequence string
	var encoded json.RawMessage
	defer func() { vault.Wipe(encoded) }()
	if len(payload) > 16384 || decodeVaultObject(payload, map[string]any{"sequence": &sequence, "authentication": &encoded}, "sequence", "authentication") != nil {
		vault.Wipe(payload)
		return nil, vaultwire.ErrProtocol
	}
	auth, err := decodeSharedExportAuthentication(encoded)
	vault.Wipe(encoded)
	vault.Wipe(payload)
	defer auth.wipe()
	if err != nil {
		return nil, err
	}
	c, err := h.sharedOwner(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(sharedRuntimeStateSession)
	if !ok {
		return nil, h.retire(sharedpg.ErrConfiguration)
	}
	var denial error
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		snapshot, err := c.observeRuntime(ctx, session, current, pending)
		if err != nil {
			return err
		}
		if !snapshot.Security.CanTightenToStandard || sequence != strconv.FormatUint(snapshot.Security.Sequence, 10) || current.Revision >= math.MaxInt64 {
			denial = vault.ErrPolicy
			return nil
		}
		valid, err := h.verifySharedExportFactors(ctx, c, current.Revision, auth)
		auth.wipe()
		if err != nil {
			return err
		}
		if !valid {
			denial = vault.ErrAuthentication
			return nil
		}
		pending.FormatVersion, pending.UserMinimum = max(pending.FormatVersion, 7), vault.Standard
		pending.Revision = current.Revision + 1
		return nil
	}, func(context.Context, sharedpg.TrustState) error {
		// Both the encrypted trust file and the OS-protected anchor are durable.
		// Revoke the old session before releasing the controller gate.
		if denial == nil {
			c.admitted.Store(false)
		}
		return nil
	}, false)
	if err != nil {
		return nil, h.retire(err)
	}
	if denial != nil {
		return nil, denial
	}
	h.closed = true
	return json.RawMessage("true"), nil
}

func (h *vaultFoundationHandler) readSharedRuntime(ctx context.Context) (vaultSharedRuntime, error) {
	controller, err := h.sharedOwner(ctx)
	if err != nil {
		return vaultSharedRuntime{}, err
	}
	if !vaultCredentialID(h.shared.vaultID) {
		return vaultSharedRuntime{}, vaultwire.ErrProtocol
	}
	p, err := controller.RuntimeSnapshot(ctx)
	if err != nil {
		return vaultSharedRuntime{}, h.retire(err)
	}
	if err := validateDesktopCrashPolicy(p.Security.Effective); err != nil {
		return vaultSharedRuntime{}, h.retire(err)
	}
	if p.Administrator && controller.rotationEpoch > 0 {
		controller.custodianMonitor.Do(func() {
			type custodianSession interface {
				suspensionInventorySession
				sharedSuspensionReceiptSession
			}
			if session, ok := controller.session.(custodianSession); ok {
				go controller.monitorCustodianSuspensions(session, session, controller.rotationPin)
			}
		})
	}
	return vaultSharedRuntime{VaultID: h.shared.vaultID, WorkspaceID: p.WorkspaceID.String(), Security: projectVaultSecurity(p.Security),
		TLS: p.TLS, RecoveryBackup: p.RecoveryBackup, Administrator: p.Administrator}, nil
}

// Main-only. The local device slot identity and remote protocol workspace
// identity are separate, and neither is chosen by this request.
func (h *vaultFoundationHandler) sharedRuntime(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	p, err := h.readSharedRuntime(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
