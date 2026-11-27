package main

import (
	"context"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedRuntimeStateSession interface {
	RuntimeState(context.Context) (*sharedpg.UnverifiedRuntimeState, error)
}

type sharedRuntimeSnapshot struct {
	WorkspaceID    uuid.UUID
	Security       localvault.SecurityProfile
	TLS            sharedpg.TLSMode
	RecoveryBackup bool
	Administrator  bool
}

// RuntimeSnapshot authenticates current server policy/account state and publishes
// observations before main can activate or refresh its controls. It never asks
// for ciphertext or borrows the resident account private keys.
func (c *sharedAdmissionController) RuntimeSnapshot(ctx context.Context) (result sharedRuntimeSnapshot, err error) {
	if ctx == nil {
		return result, sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedRuntimeStateSession)
	if !ok {
		return result, sharedpg.ErrConfiguration
	}
	err = c.withCatalogOperation(ctx, func(ctx context.Context, current sharedpg.TrustState, pending *sharedpg.TrustState) error {
		var e error
		result, e = c.observeRuntime(ctx, session, current, pending)
		if e == nil && result.Administrator && c.rotationEpoch > 0 && c.rotationPin.Organisation == nil {
			c.rotationPin, e = pending.AccountTrust()
		}
		return e
	}, nil, false)
	if err != nil {
		return sharedRuntimeSnapshot{}, err
	}
	return result, nil
}

func (c *sharedAdmissionController) observeRuntime(ctx context.Context, session sharedRuntimeStateSession, current sharedpg.TrustState, pending *sharedpg.TrustState) (result sharedRuntimeSnapshot, err error) {
	switch c.runtimeTLS {
	case sharedpg.TLSOff, sharedpg.TLSEncrypted, sharedpg.TLSVerified:
	default:
		return result, sharedpg.ErrConfiguration
	}
	currentOSFloor, e := ospolicy.ReadFloor(ctx)
	if e != nil {
		return result, e
	}
	// Removing a machine floor cannot relax an already admitted owner. A
	// stronger floor requires fresh activation of the main-owned controls.
	floor := vault.EffectiveProfile(c.runtimeOSFloor, currentOSFloor, vault.Default)
	if e := sharedProtocolFloor(c.runtimeProfile, floor); e != nil {
		return result, e
	}
	input, e := session.RuntimeState(ctx)
	if e != nil {
		return result, e
	}
	if input == nil {
		return result, sharedpg.ErrAdmissionResponse
	}
	next, e := current.VerifyRuntimeState(ctx, input)
	if next.Revision != 0 {
		*pending = next
	}
	if e != nil {
		return result, e
	}
	policy, e := next.Policy()
	if e != nil {
		return result, e
	}
	security, e := c.admittedSecurity(policy, currentOSFloor)
	if e != nil {
		return result, e
	}
	if policy.Sequence > math.MaxInt64 {
		return result, sharedpg.ErrTrustState
	}
	security.CanTightenToStandard = security.Effective == vault.Default && c.runtimeTLS == sharedpg.TLSVerified &&
		input.StatementsPrivate() && next.Revision < math.MaxInt64 && validateSharedAccountDerivation(policy, vault.Standard, c.runtimeKDF, c.runtimeASK) == nil
	return sharedRuntimeSnapshot{
		WorkspaceID:    next.WorkspaceID,
		Security:       security,
		TLS:            c.runtimeTLS,
		RecoveryBackup: c.runtimeTLS == sharedpg.TLSVerified && c.tlsManaged && policy.OrgEscrow && input.WasAdmittedAsAdministrator(),
		Administrator:  c.runtimeTLS == sharedpg.TLSVerified && input.WasAdmittedAsAdministrator(),
	}, nil
}

func (c *sharedAdmissionController) admittedSecurity(policy vault.Policy, currentOS vault.Profile) (localvault.SecurityProfile, error) {
	security := localvault.ResolveSecurityProfile(policy, c.runtimeUserFloor, currentOS)
	security.RetainMinimum(c.runtimeOSFloor, "os")
	if err := sharedAdmissionRuntimeProfile(security.Effective); err != nil {
		return localvault.SecurityProfile{}, err
	}
	if security.Effective != c.runtimeProfile {
		return localvault.SecurityProfile{}, sharedpg.ErrProfileChanged
	}
	return security, nil
}
