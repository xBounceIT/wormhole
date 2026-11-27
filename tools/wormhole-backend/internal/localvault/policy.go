package localvault

import (
	"context"
	"errors"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func (o *Owner) readLocalPolicy(ctx context.Context) (vault.LocalPolicy, []byte, error) {
	if o.closed {
		return vault.LocalPolicy{}, nil, vaultstore.ErrClosed
	}
	s, ok := o.store.(vaultstore.ProfileStore)
	if !ok {
		return vault.LocalPolicy{}, nil, vaultstore.ErrStorage
	}
	raw, err := s.ReadProfile(ctx)
	if err != nil {
		return vault.LocalPolicy{}, nil, err
	}
	p, err := vault.DecodeLocalPolicy(raw)
	if err != nil {
		return vault.LocalPolicy{}, nil, err
	}
	i := s.Identity()
	err = o.root.With(func(key []byte) error {
		return vault.VerifyLocalPolicy(key, p, i.WorkspaceID, i.FileID, i.Root.ID, i.Root.Version, o.profileFloor)
	})
	if err != nil {
		return vault.LocalPolicy{}, nil, err
	}
	o.profileFloor = p.Policy.Sequence
	return p, raw, nil
}

func (o *Owner) ReadLocalPolicy(ctx context.Context) (vault.LocalPolicy, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	p, _, err := o.readLocalPolicy(ctx)
	return p, err
}

// This native primitive requires fresh authentication at its eventual controller
// call site. It is not exposed through renderer or generic transport operations.
// Missing/invalid policy can never be repaired into a weaker policy by this API.
func (o *Owner) PutLocalPolicy(ctx context.Context, policy vault.Policy, userFloor vault.Profile, expected uint64) (vault.LocalPolicy, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if expected == 0 || expected >= math.MaxInt64 || policy.Sequence != expected+1 {
		return vault.LocalPolicy{}, vault.ErrFormat
	}
	current, old, err := o.readLocalPolicy(ctx)
	if err != nil {
		return vault.LocalPolicy{}, err
	}
	if current.Policy.Sequence != expected {
		return vault.LocalPolicy{}, vaultstore.ErrConflict
	}
	if policy.WorkspaceID != current.Policy.WorkspaceID {
		return vault.LocalPolicy{}, vault.ErrAuthentication
	}
	next := current
	next.Policy = policy
	next.UserProfile = userFloor
	return o.writeLocalPolicy(ctx, next, old)
}

// TightenToStandard changes only the personal floor of the authenticated policy.
// The service binds the sequence to fresh authentication and checkpoints it
// before acknowledging the change.
func (o *Owner) TightenToStandard(ctx context.Context, expected uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	p, old, err := o.readLocalPolicy(ctx)
	if err != nil {
		return err
	}
	if p.Policy.Sequence != expected {
		return vaultstore.ErrConflict
	}
	security, err := o.checkSecurityProfile(ctx, p, vault.SlotFile{Slots: o.securitySlots})
	if err != nil {
		return err
	}
	if !security.CanTightenToStandard {
		return vault.ErrPolicy
	}
	p.UserProfile = vault.Standard
	p.Policy.Sequence++
	if _, err := o.writeLocalPolicy(ctx, p, old); err != nil {
		return err
	}
	// Enforce the commit even if the caller loses its reply before the next read.
	o.sessionSecurity = ResolveSecurityProfile(p.Policy, p.UserProfile, security.OS)
	return nil
}

func (o *Owner) writeLocalPolicy(ctx context.Context, next vault.LocalPolicy, old []byte) (vault.LocalPolicy, error) {
	var raw []byte
	err := o.root.With(func(key []byte) error { var err error; raw, err = vault.EncodeLocalPolicy(key, next); return err })
	if err != nil {
		return vault.LocalPolicy{}, err
	}
	if err := o.store.(vaultstore.ProfileStore).WriteProfile(ctx, raw, old); err != nil {
		return vault.LocalPolicy{}, err
	}
	o.profileFloor = next.Policy.Sequence
	// Return the actual signed representation, never an obsolete authentication tag.
	return vault.DecodeLocalPolicy(raw)
}

func (o *Owner) seedLocalPolicy(ctx context.Context, slots vault.SlotFile) error {
	s, ok := o.store.(interface {
		vaultstore.ProfileStore
		SeedProfile(context.Context, []byte) error
	})
	if !ok {
		return vaultstore.ErrStorage
	}
	if _, err := s.ReadProfile(ctx); !errors.Is(err, vaultstore.ErrMissing) {
		return err
	}
	sequence := slots.ProfileSequence
	if sequence == 0 {
		sequence = 1
	}
	preset := vault.KDFV1
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotPassword && slot.Preset == vault.KDFLow {
			preset = vault.KDFLow
		}
	}
	i := s.Identity()
	p := vault.LocalPolicy{Policy: vault.Policy{FormatVersion: 1, WorkspaceID: i.WorkspaceID, Sequence: sequence, Profile: vault.Default, KDF: preset, LowKDFApproved: preset == vault.KDFLow, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}, FileID: i.FileID, RootKeyID: i.Root.ID, RootKeyVersion: i.Root.Version, UserProfile: vault.Default}
	var raw []byte
	err := o.root.With(func(key []byte) error { var err error; raw, err = vault.EncodeLocalPolicy(key, p); return err })
	if err != nil {
		return err
	}
	return s.SeedProfile(ctx, raw)
}
