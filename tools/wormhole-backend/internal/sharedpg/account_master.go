package sharedpg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrAccountMasterCleanup = errors.New("shared account master cleanup is unconfirmed")

// AccountDerivation comes from authenticated enrollment or invitation state,
// never renderer assertions or an unauthenticated server's suggested parameters.
// LoginName is the immutable canonical name, not a display name.
type AccountDerivation struct {
	WorkspaceID      uuid.UUID
	LoginName        string
	Preset           vault.KDFPreset
	ASKRequired      bool
	EffectiveProfile vault.Profile
	Administrator    bool
	Custodian        bool
}

type accountMasterMemory interface {
	With(func([]byte) error) error
	Close() error
	Locked() bool
}

// AccountMaster owns only the mixed account master in native memory. It has no
// serialization or raw-buffer accessor. Use must not retain its borrowed slice.
// Its callback must not call Use, Locked or Close on this same owner.
// Always Close, including a nonnil owner returned alongside a cleanup error.
type AccountMaster struct {
	memory        accountMasterMemory
	preset        vault.KDFPreset
	askUsed       bool
	workspaceID   uuid.UUID
	loginName     string
	requireLocked bool
}

func (m *AccountMaster) Use(use func([]byte, vault.KDFPreset, bool) error) error {
	if m == nil || m.memory == nil || use == nil {
		return securemem.ErrClosed
	}
	return m.memory.With(func(master []byte) error { return use(master, m.preset, m.askUsed) })
}

func (m *AccountMaster) Locked() bool { return m != nil && m.memory != nil && m.memory.Locked() }
func (m *AccountMaster) WorkspaceID() uuid.UUID {
	if m == nil {
		return uuid.Nil
	}
	return m.workspaceID
}

func (m *AccountMaster) LoginName() string {
	if m == nil {
		return ""
	}
	return m.loginName
}
func (m *AccountMaster) Close() error {
	if m == nil || m.memory == nil {
		return nil
	}
	return m.memory.Close()
}

// DeriveAccountMaster borrows password/ASK until return; their native input owner
// must wipe them. No network or file operation occurs here. The caller must already
// have authenticated policy and enrollment before selecting these derivation facts.
func DeriveAccountMaster(ctx context.Context, d AccountDerivation, policy vault.Policy, password, ask []byte) (*AccountMaster, error) {
	return deriveAccountMaster(ctx, d, policy, password, ask, func(required bool) (accountMasterMemory, error) { return securemem.New(32, required) })
}

func deriveAccountMaster(ctx context.Context, d AccountDerivation, policy vault.Policy, password, ask []byte, allocate func(bool) (accountMasterMemory, error)) (result *AccountMaster, err error) {
	if ctx == nil || len(password) == 0 || len(password) > 1024 || d.WorkspaceID == uuid.Nil || policy.WorkspaceID != d.WorkspaceID.String() ||
		(d.ASKRequired && len(ask) != 32) || (!d.ASKRequired && len(ask) != 0) {
		return nil, ErrConfiguration
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if vault.EffectiveProfile(vault.Default, policy.Profile, d.EffectiveProfile) != d.EffectiveProfile {
		return nil, vault.ErrPolicy
	}
	actual := policy
	actual.Profile = d.EffectiveProfile
	actual.KDF = d.Preset
	actual.ASKRequired = d.ASKRequired
	if err := actual.Validate(); err != nil {
		return nil, err
	}
	floor, err := vault.Parameters(policy.KDF)
	if err != nil {
		return nil, err
	}
	params, err := vault.Parameters(d.Preset)
	if err != nil {
		return nil, err
	}
	if params.MemoryKiB < floor.MemoryKiB || params.Iterations < floor.Iterations || (policy.ASKRequired && !d.ASKRequired) ||
		(d.EffectiveProfile == vault.Hardened && (d.Administrator || d.Custodian) && !d.ASKRequired) {
		return nil, vault.ErrPolicy
	}
	salt, err := vault.SharedSalt(d.WorkspaceID.String(), d.LoginName)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(salt)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory, err := allocate(d.EffectiveProfile == vault.Hardened || d.EffectiveProfile == vault.Paranoid)
	if err != nil {
		return nil, err
	}
	owner := &AccountMaster{memory: memory, preset: d.Preset, askUsed: d.ASKRequired, workspaceID: d.WorkspaceID, loginName: d.LoginName, requireLocked: d.EffectiveProfile == vault.Hardened || d.EffectiveProfile == vault.Paranoid}
	defer func() {
		if err != nil {
			if owner.Close() != nil {
				result = owner
				err = errors.Join(err, ErrAccountMasterCleanup)
			} else {
				result = nil
			}
		}
	}()
	passwordMaster, err := vault.DerivePassword(ctx, password, salt, d.Preset)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(passwordMaster)
	mixed, err := vault.MixAccountSecret(passwordMaster, ask, d.ASKRequired)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(mixed)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := memory.With(func(value []byte) error { copy(value, mixed); return nil }); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return owner, nil
}
