package localvault

import (
	"context"
	"math"
	"slices"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// EnrollHelloSlot requires a fresh software factor at its native call site. The
// atomic writer borrows the resident key only until it publishes the new slots.
func (o *Owner) EnrollHelloSlot(ctx context.Context, document vault.SlotFile, id string, credential vault.HelloCredential, persist func(vault.SlotFile, []byte) error) error {
	if credential == nil {
		return vault.ErrFormat
	}
	return o.editPlatformSlots(ctx, document, vault.SlotFileHelloVersion, persist, func(root []byte, policy vault.LocalPolicy) ([]vault.Slot, error) {
		if policy.Policy.ASKRequired || len(document.Slots) >= 16 {
			return nil, vault.ErrPolicy
		}
		for _, slot := range document.Slots {
			if slot.Kind == vault.SlotHello || slot.Kind == vault.SlotUnprotected {
				return nil, vault.ErrPolicy
			}
		}
		slot, err := vault.CreateHelloSlot(ctx, document.VaultID, document.FileID, id, document.RootKeyVersion, root, credential)
		if err != nil {
			return nil, err
		}
		return append(slices.Clone(document.Slots), slot), nil
	})
}

// EnrollTouchIDSlot provisions Keychain custody only after verifying the current
// document and policy. The provisioning callback never receives resident keys.
func (o *Owner) EnrollTouchIDSlot(ctx context.Context, document vault.SlotFile, id string, provision func(context.Context) ([]byte, error), persist func(vault.SlotFile, []byte) error) error {
	if provision == nil {
		return vault.ErrFormat
	}
	return o.editPlatformSlots(ctx, document, vault.SlotFileTouchIDVersion, persist, func(root []byte, policy vault.LocalPolicy) ([]vault.Slot, error) {
		if policy.Policy.ASKRequired || len(document.Slots) >= 16 {
			return nil, vault.ErrPolicy
		}
		for _, slot := range document.Slots {
			if slot.Kind == vault.SlotTouchID || slot.Kind == vault.SlotUnprotected {
				return nil, vault.ErrPolicy
			}
		}
		factor, err := provision(ctx)
		defer vault.Wipe(factor)
		if err != nil {
			return nil, err
		}
		slot, err := vault.CreateTouchIDSlot(document.VaultID, document.FileID, id, document.RootKeyVersion, root, factor)
		if err != nil {
			return nil, err
		}
		return append(slices.Clone(document.Slots), slot), nil
	})
}

// Removal withdraws the exact authenticated slot even if the platform cannot
// confirm deletion of the backing credential.
func (o *Owner) RemovePlatformSlot(ctx context.Context, document vault.SlotFile, id string, kind vault.SlotKind, cleanup func(context.Context) bool, persist func(vault.SlotFile, []byte) error) (bool, error) {
	if cleanup == nil || (kind != vault.SlotHello && kind != vault.SlotTouchID) {
		return false, vault.ErrFormat
	}
	var removedKey bool
	err := o.editPlatformSlots(ctx, document, document.FormatVersion, persist, func(_ []byte, _ vault.LocalPolicy) ([]vault.Slot, error) {
		index := slices.IndexFunc(document.Slots, func(slot vault.Slot) bool {
			return slot.ID == id && slot.Kind == kind
		})
		if index == -1 {
			return nil, vault.ErrPolicy
		}
		removedKey = cleanup(ctx)
		return slices.Delete(slices.Clone(document.Slots), index, index+1), nil
	})
	return removedKey, err
}

func (o *Owner) editPlatformSlots(ctx context.Context, document vault.SlotFile, formatVersion uint16, persist func(vault.SlotFile, []byte) error, edit func([]byte, vault.LocalPolicy) ([]vault.Slot, error)) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil || persist == nil {
		return vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	profile, err := o.readSecurityProfile(ctx)
	if err != nil {
		return err
	}
	policy, _, err := o.readLocalPolicy(ctx)
	if err != nil {
		return err
	}
	if (profile.Effective != vault.Default && profile.Effective != vault.Standard) || document.Sequence == math.MaxUint64 ||
		document.Initializing || document.Migration != nil || document.Rotation != nil {
		return vault.ErrPolicy
	}
	identity := o.store.Identity()
	if document.RootKeyID != identity.Root.ID || document.RootKeyVersion != identity.Root.Version || document.Encrypted != o.encrypted {
		return vault.ErrAuthentication
	}
	return o.root.With(func(root []byte) error {
		if err := vault.VerifySlotFile(root, document, identity.WorkspaceID, identity.FileID, o.slotFloor); err != nil {
			return err
		}
		slots, err := edit(root, policy)
		if err != nil {
			return err
		}
		if floor, err := ospolicy.ReadFloor(ctx); err != nil || floor != profile.OS {
			return vault.ErrPolicy
		}
		next := document
		next.Sequence++
		next.FormatVersion = max(next.FormatVersion, formatVersion)
		if slices.ContainsFunc(slots, func(slot vault.Slot) bool {
			return slot.Kind == vault.SlotHello && slot.Hello != nil && slot.Hello.Attestation == vault.HelloAttestationTPMVerified
		}) {
			next.FormatVersion = max(next.FormatVersion, vault.SlotFileTPMAttestationVersion)
		}
		next.ProfileSequence = max(next.ProfileSequence, o.profileFloor)
		next.Slots = slots
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := persist(next, root); err != nil {
			return err
		}
		o.slotFloor = next.Sequence
		o.rememberSecuritySlots(next.Slots)
		return nil
	})
}
