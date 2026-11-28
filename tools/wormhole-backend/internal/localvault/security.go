package localvault

import (
	"context"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type SecurityProfile struct {
	Sequence                       uint64
	Workspace, User, OS, Effective vault.Profile
	Source                         string
	RetainedUntilLock              bool
	CanTightenToStandard           bool
}

// Keep only the authenticated slot properties used for policy admission.
func (o *Owner) rememberSecuritySlots(slots []vault.Slot) {
	o.securitySlots = make([]vault.Slot, len(slots))
	for i, slot := range slots {
		o.securitySlots[i] = vault.Slot{Kind: slot.Kind, Preset: slot.Preset, ASKRequired: slot.ASKRequired}
	}
}

// ReadProtection exposes only the protection of the authenticated live owner.
// The public startup slot hint is never sufficient to render this assurance.
func (o *Owner) ReadProtection(ctx context.Context) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.readSecurityProfile(ctx); err != nil {
		return false, err
	}
	return !(len(o.securitySlots) == 1 && o.securitySlots[0].Kind == vault.SlotUnprotected), nil
}

// ReadSecurityProfile re-authenticates policy and re-reads the machine floor.
// The projection contains no key identities, MACs, slots or authentication data.
func (o *Owner) ReadSecurityProfile(ctx context.Context) (SecurityProfile, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readSecurityProfile(ctx)
}

func (o *Owner) readSecurityProfile(ctx context.Context) (SecurityProfile, error) {
	p, _, err := o.readLocalPolicy(ctx)
	if err != nil {
		return SecurityProfile{}, err
	}
	return o.checkSecurityProfile(ctx, p, vault.SlotFile{Slots: o.securitySlots})
}

func (o *Owner) checkSecurityProfile(ctx context.Context, p vault.LocalPolicy, slots vault.SlotFile) (SecurityProfile, error) {
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return SecurityProfile{}, err
	}
	return o.applySecurityProfile(p, slots, floor)
}

// An owner may acquire stricter controls during use. Revalidate slots and KDF
// against that minimum even when a newer signed policy or the OS floor relaxes.
func (o *Owner) applySecurityProfile(p vault.LocalPolicy, slots vault.SlotFile, osFloor vault.Profile) (SecurityProfile, error) {
	next := ResolveSecurityProfile(p.Policy, p.UserProfile, osFloor)
	next.RetainMinimum(o.sessionSecurity.Effective, o.sessionSecurity.Source)
	if err := validateLocalSecurity(p, slots, next.Effective); err != nil {
		return SecurityProfile{}, err
	}
	next.CanTightenToStandard = next.Effective == vault.Default && p.Policy.Sequence < math.MaxInt64 &&
		validateLocalSecurity(p, slots, vault.Standard) == nil
	o.sessionSecurity = next
	return next, nil
}

// ResolveSecurityProfile applies both local and shared authority precedence.
func ResolveSecurityProfile(policy vault.Policy, user, floor vault.Profile) SecurityProfile {
	effective := vault.EffectiveProfile(floor, policy.Profile, user)
	source := "workspace"
	if floor != vault.Default && effective == floor {
		source = "os"
	} else if effective != policy.Profile {
		source = "user"
	}
	return SecurityProfile{Sequence: policy.Sequence, Workspace: policy.Profile, User: user, OS: floor, Effective: effective, Source: source}
}

// RetainMinimum preserves a previously applied floor and its authority only
// while the currently configured profile is strictly weaker.
func (p *SecurityProfile) RetainMinimum(minimum vault.Profile, source string) {
	if minimum != "" && minimum != p.Effective && vault.EffectiveProfile(minimum, p.Effective, vault.Default) == minimum {
		p.Effective, p.Source, p.RetainedUntilLock = minimum, source, true
	}
}

// This gate runs after authentication, before an owner is released to callers.
// Unsupported protection must not become a successful weaker unlock. Future
// hardware/VFS controllers can extend this gate when their guarantees exist.
func validateLocalSecurity(p vault.LocalPolicy, slots vault.SlotFile, osFloor vault.Profile) error {
	if p.Policy.MinAPI > 1 || p.Policy.MaxAPI < 1 {
		return vault.ErrNewerFormat
	}
	effective := p.Policy
	effective.Profile = vault.EffectiveProfile(osFloor, p.Policy.Profile, p.UserProfile)
	if err := effective.Validate(); err != nil {
		return err
	}
	if effective.Profile == vault.Hardened || effective.Profile == vault.Paranoid {
		// Admission requires verified conversion and rekey on all supported
		// platforms. Paranoid also requires an attested AND slot.
		return vault.ErrPolicy
	}
	minimum, err := vault.Parameters(effective.KDF)
	if err != nil {
		return err
	}
	password, recovery := false, false
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotUnprotected && (effective.Profile != vault.Default || effective.ASKRequired || len(slots.Slots) != 1) {
			// An OS-accessible root must never coexist with protected slots or
			// satisfy a policy that requires a user-held factor.
			return vault.ErrPolicy
		}
		if slot.Kind == vault.SlotRecovery {
			recovery = true
		}
		if slot.Kind != vault.SlotPassword {
			continue
		}
		password = true
		params, err := vault.Parameters(slot.Preset)
		if err != nil || params.MemoryKiB < minimum.MemoryKiB || params.Iterations < minimum.Iterations || params.Parallelism < minimum.Parallelism || (effective.ASKRequired && !slot.ASKRequired) {
			return vault.ErrPolicy
		}
	}
	if effective.Profile != vault.Default && (!password || !recovery) {
		return vault.ErrPolicy
	}
	return nil
}
