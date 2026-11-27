package main

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Re-read the machine floor at the native operation boundary. A stronger floor
// must retire this already-admitted owner before planning or borrowing any keys.
func (h *vaultFoundationHandler) sharedOwner(ctx context.Context) (*sharedAdmissionController, error) {
	if ctx == nil || h.closed || h.owner != nil || h.shared == nil || h.shared.controller == nil || !h.shared.controller.Unlocked() {
		return nil, vaultwire.ErrProtocol
	}
	return h.shared.controller, nil
}

func (h *vaultFoundationHandler) sharedProtocolController(ctx context.Context) (*sharedAdmissionController, error) {
	c, e := h.sharedOwner(ctx)
	if e != nil {
		return nil, e
	}
	floor, e := ospolicy.ReadFloor(ctx)
	if e != nil {
		return nil, h.retire(e)
	}
	if e := sharedProtocolFloor(c.runtimeProfile, floor); e != nil {
		return nil, h.retire(e)
	}
	return c, nil
}

func sharedProtocolFloor(admitted, floor vault.Profile) error {
	effective := vault.EffectiveProfile(floor, admitted, vault.Default)
	if err := sharedAdmissionRuntimeProfile(effective); err != nil {
		return err
	}
	// Even a supported stronger profile changes main-owned controls. The old
	// admission cannot silently continue before those controls are reactivated.
	if effective != admitted {
		return sharedpg.ErrProfileChanged
	}
	return nil
}
