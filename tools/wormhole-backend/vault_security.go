package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Main receives only authenticated profile identities. It must derive controls
// from these fixed identifiers, never from legacy settings or renderer choices.
func (h *vaultFoundationHandler) security(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if h.shared != nil {
		p, err := h.readSharedRuntime(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(p.Security)
	}
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	p, err := h.owner.ReadSecurityProfile(ctx)
	if err != nil {
		return h.rejectLocalPolicy(ctx, err)
	}
	if err := validateDesktopCrashPolicy(p.Effective); err != nil {
		return h.rejectLocalPolicy(ctx, err)
	}
	return json.Marshal(projectVaultSecurity(p))
}

// Policy authentication can advance a valid profile floor even when effective
// protection is unsupported. Keep that observation before retiring the native
// owner. Cancellation alone must not mask a separate known security failure.
func (h *vaultFoundationHandler) rejectLocalPolicy(ctx context.Context, cause error) (json.RawMessage, error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := h.checkpointVPNSSO(cleanup); err != nil {
		return nil, h.retire(errors.Join(cause, err))
	}
	if cause == context.Canceled || cause == context.DeadlineExceeded {
		return nil, cause
	}
	return nil, h.retire(cause)
}

type vaultSecurityProjection struct {
	Sequence             string `json:"sequence"`
	Workspace            string `json:"workspace"`
	User                 string `json:"user"`
	OS                   string `json:"os"`
	Effective            string `json:"effective"`
	Source               string `json:"source"`
	RetainedUntilLock    bool   `json:"retainedUntilLock,omitempty"`
	CanTightenToStandard bool   `json:"canTightenToStandard,omitempty"`
}

func projectVaultSecurity(p localvault.SecurityProfile) vaultSecurityProjection {
	return vaultSecurityProjection{Sequence: strconv.FormatUint(p.Sequence, 10), Workspace: string(p.Workspace), User: string(p.User),
		OS: string(p.OS), Effective: string(p.Effective), Source: p.Source, RetainedUntilLock: p.RetainedUntilLock, CanTightenToStandard: p.CanTightenToStandard}
}

func (h *vaultFoundationHandler) tightenLocalProfile(ctx context.Context, payload []byte, authenticatedSlots vault.SlotFile) (json.RawMessage, error) {
	if h.enrollment != nil || h.rotationMaterial != nil {
		return nil, vault.ErrPolicy
	}
	var sequence string
	if len(payload) > 64 || decodeVaultObject(payload, map[string]any{"sequence": &sequence}, "sequence") != nil {
		return nil, vaultwire.ErrProtocol
	}
	expected, err := vaultCredentialRevision(sequence, false)
	if err != nil {
		return nil, err
	}
	if err := h.owner.TightenToStandard(ctx, expected); err != nil {
		return nil, err
	}
	// SQLite committed. Finish the slot high-water mark independently of a
	// cancelled caller. An uncertain checkpoint must retire this owner.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := h.persistVaultCheckpoint(cleanup, authenticatedSlots); err != nil {
		return nil, h.retire(err)
	}
	return json.RawMessage("true"), nil
}
