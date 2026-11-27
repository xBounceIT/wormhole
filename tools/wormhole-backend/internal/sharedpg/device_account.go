package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Selection is native enrollment state plus the explicitly selected password
// slot. Unauthenticated file descriptors may not replace vault/file/floor values.
type DeviceUnlockSelection struct {
	VaultID, FileID, SlotID string
	MinimumSequence         uint64
}

// UnlockedDeviceAccount owns independent native storage/account/device roots.
// Serialize Borrow/Close. Callbacks may not retain keys or close this owner.
// Always Close a nonnil result, including one returned with a cleanup error.
type UnlockedDeviceAccount struct {
	master         *AccountMaster
	root           *DeviceTrustRoot
	storage        accountMasterMemory
	file, journal  []byte // authenticated ciphertext only
	previousDigest []byte // present only on a prepared password-change owner
	closed         bool
}

func (a *UnlockedDeviceAccount) Borrow(use func(*AccountMaster, *DeviceTrustRoot) error) error {
	if a == nil || a.closed || a.master == nil || a.root == nil || use == nil {
		return ErrConfiguration
	}
	return use(a.master, a.root)
}

// BorrowDeviceStorage lends storage independently of the account/root owners.
// Borrow may be nested; do not reenter storage borrowing, Locked or Close.
func (a *UnlockedDeviceAccount) BorrowDeviceStorage(use func([]byte, []byte) error) error {
	if a == nil || a.closed || a.storage == nil || len(a.file) == 0 || use == nil {
		return ErrConfiguration
	}
	return a.storage.With(func(key []byte) error {
		slots, envelope, err := DecodeDeviceEnrollmentFile(a.file)
		if err != nil {
			return err
		}
		if _, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, slots.Sequence, envelope); err != nil {
			return err
		}
		return use(key, bytes.Clone(a.file))
	})
}

// BorrowTransition re-authenticates the retained journal and releases the root
// memory lock before lending native owners to recovery. It proves no remote result.
func (a *UnlockedDeviceAccount) BorrowTransition(use func(*AccountMaster, *DeviceTrustRoot, TrustRootTransition) error) error {
	if a == nil || a.closed || len(a.journal) == 0 || use == nil {
		return ErrConfiguration
	}
	return a.Borrow(func(master *AccountMaster, root *DeviceTrustRoot) error {
		var record TrustRootTransition
		err := root.Use(func(key []byte) error {
			var e error
			record, e = OpenTrustRootTransition(key, root.Binding(), a.journal)
			return e
		})
		if err != nil {
			return err
		}
		return use(master, root, record)
	})
}

func (a *UnlockedDeviceAccount) Locked() bool {
	return a != nil && !a.closed && a.master != nil && a.root != nil && a.storage != nil && a.master.Locked() && a.root.Locked() && a.storage.Locked()
}

func (a *UnlockedDeviceAccount) Close() error {
	if a == nil {
		return nil
	}
	a.closed = true
	a.file, a.journal, a.previousDigest = nil, nil, nil
	var err error
	if a.storage != nil {
		if e := a.storage.Close(); e != nil {
			err = errors.Join(err, ErrDeviceStorageCleanup)
		} else {
			a.storage = nil
		}
	}
	if a.root != nil {
		if e := a.root.Close(); e != nil {
			err = errors.Join(err, ErrDeviceTrustRootCleanup)
		} else {
			a.root = nil
		}
	}
	if a.master != nil {
		if e := a.master.Close(); e != nil {
			err = errors.Join(err, ErrAccountMasterCleanup)
		} else {
			a.master = nil
		}
	}
	return err
}

// PreparePasswordChange produces both the next slot file and account keys from
// the same borrowed factors. It neither mutates this owner nor publishes anything.
// ASK must be the existing native factor; changing its mode is not permitted.
func (a *UnlockedDeviceAccount) PreparePasswordChange(ctx context.Context, password, ask []byte, osFloor, userFloor vault.Profile) (result *UnlockedDeviceAccount, err error) {
	if a == nil || a.closed || len(a.journal) != 0 || len(a.previousDigest) != 0 {
		return nil, ErrConfiguration
	}
	err = a.BorrowDeviceStorage(func(key, source []byte) error {
		slots, _, e := DecodeDeviceEnrollmentFile(source)
		if e != nil {
			return e
		}
		next, e := PrepareDevicePasswordFile(ctx, key, source, slots.VaultID, slots.FileID, slots.Sequence, password, ask, osFloor, userFloor)
		if e != nil {
			return e
		}
		updated, envelope, e := DecodeDeviceEnrollmentFile(next)
		if e != nil {
			return e
		}
		metadata, e := OpenDeviceEnrollment(key, updated, slots.VaultID, slots.FileID, updated.Sequence, envelope)
		if e != nil {
			return e
		}
		// The slot was just created with these factors and the still-borrowed
		// storage key. Authenticate its file without repeating the slot KDF.
		result, e = deriveDeviceAccount(ctx, key, next, nil, metadata, password, ask, osFloor, userFloor, allocateDeviceStorage)
		if e != nil {
			return e
		}
		digest := sha256.Sum256(source)
		result.previousDigest = bytes.Clone(digest[:])
		return nil
	})
	return result, err
}

// BorrowPasswordChange links this prepared owner to its exact unlocked source.
// The callback may borrow the independent masters/root, but must not reenter
// storage borrowing, call Locked on this owner or close either owner.
// No caller can substitute raw factors.
func (a *UnlockedDeviceAccount) BorrowPasswordChange(previous *UnlockedDeviceAccount, use func(*AccountMaster, *AccountMaster, *DeviceTrustRoot, []byte, []byte, DeviceUnlockSelection) error) error {
	if a == nil || previous == nil || a == previous || a.closed || previous.closed || len(a.previousDigest) != sha256.Size || len(a.journal) != 0 || len(previous.journal) != 0 || use == nil {
		return ErrConfiguration
	}
	digest := sha256.Sum256(previous.file)
	if !bytes.Equal(digest[:], a.previousDigest) {
		return ErrTrustState
	}
	return previous.Borrow(func(old *AccountMaster, oldRoot *DeviceTrustRoot) error {
		return a.Borrow(func(next *AccountMaster, nextRoot *DeviceTrustRoot) error {
			if oldRoot.Binding() != nextRoot.Binding() {
				return ErrTrustState
			}
			return a.BorrowDeviceStorage(func(key, raw []byte) error {
				slots, _, err := DecodeDeviceEnrollmentFile(raw)
				if err != nil {
					return err
				}
				selection := DeviceUnlockSelection{VaultID: slots.VaultID, FileID: slots.FileID, MinimumSequence: slots.Sequence - 1}
				return use(old, next, nextRoot, key, raw, selection)
			})
		})
	})
}

// OpenDeviceAccount authenticates selection and the slot/envelope before deriving
// account facts. Password/ASK are borrowed and never retained. No I/O occurs.
func OpenDeviceAccount(ctx context.Context, raw []byte, selection DeviceUnlockSelection, password, ask []byte, osFloor, userFloor vault.Profile) (*UnlockedDeviceAccount, error) {
	return openDeviceAccount(ctx, raw, nil, selection, password, ask, osFloor, userFloor, allocateDeviceStorage)
}

// OpenDeviceTransitionAccount starts from an UNTRUSTED candidate, then verifies
// the root-encrypted journal and exact candidate commitment before returning.
func OpenDeviceTransitionAccount(ctx context.Context, journal []byte, selection DeviceUnlockSelection, password, ask []byte, osFloor, userFloor vault.Profile) (*UnlockedDeviceAccount, error) {
	raw, err := UnverifiedTransitionDevice(journal)
	if err != nil {
		return nil, err
	}
	return openDeviceAccount(ctx, raw, journal, selection, password, ask, osFloor, userFloor, allocateDeviceStorage)
}

func openDeviceAccount(ctx context.Context, raw, journal []byte, selection DeviceUnlockSelection, password, ask []byte, osFloor, userFloor vault.Profile, allocate func(bool) (accountMasterMemory, error)) (result *UnlockedDeviceAccount, err error) {
	if ctx == nil || selection.MinimumSequence == 0 || selection.SlotID == "" || len(password) == 0 || len(password) > 1024 || (len(ask) != 0 && len(ask) != 32) {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local := vault.EffectiveProfile(vault.Default, osFloor, userFloor)
	if local != vault.Default && local != vault.Standard {
		return nil, vault.ErrPolicy
	}
	slots, envelope, err := DecodeDeviceEnrollmentFile(raw)
	if err != nil {
		return nil, err
	}
	if slots.VaultID != selection.VaultID || slots.FileID != selection.FileID || slots.Sequence < selection.MinimumSequence {
		return nil, ErrTrustState
	}
	var selected *vault.Slot
	for i := range slots.Slots {
		if slots.Slots[i].ID == selection.SlotID {
			selected = &slots.Slots[i]
			break
		}
	}
	if selected == nil || selected.Kind != vault.SlotPassword {
		return nil, ErrConfiguration
	}
	parameters, e := vault.Parameters(selected.Preset)
	floor, _ := vault.Parameters(vault.KDFV1)
	if e != nil || parameters.MemoryKiB < floor.MemoryKiB || parameters.Iterations < floor.Iterations {
		return nil, vault.ErrPolicy
	}
	key, err := vault.OpenPasswordSlot(ctx, selection.VaultID, *selected, password, ask)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	metadata, err := OpenDeviceEnrollment(key, slots, selection.VaultID, selection.FileID, selection.MinimumSequence, envelope)
	if err != nil {
		return nil, err
	}
	return deriveDeviceAccount(ctx, key, raw, journal, metadata, password, ask, osFloor, userFloor, allocate)
}

// metadata and storage key were authenticated together by the caller. Shared
// ownership/cleanup logic also serves freshly generated password candidates.
func deriveDeviceAccount(ctx context.Context, key, raw, journal []byte, metadata *DeviceEnrollment, password, ask []byte, osFloor, userFloor vault.Profile, allocate func(bool) (accountMasterMemory, error)) (result *UnlockedDeviceAccount, err error) {
	d, policy, err := metadata.Derivation(osFloor, userFloor)
	if err != nil {
		return nil, err
	}
	if d.EffectiveProfile != vault.Default && d.EffectiveProfile != vault.Standard {
		return nil, vault.ErrPolicy
	}
	owner := &UnlockedDeviceAccount{}
	defer func() {
		if err != nil {
			if cleanup := owner.Close(); cleanup != nil {
				result = owner
				err = errors.Join(err, cleanup)
			} else {
				result = nil
			}
		}
	}()
	owner.storage, err = allocate(false)
	if err != nil {
		return nil, err
	}
	if err = owner.storage.With(func(value []byte) error { copy(value, key); return nil }); err != nil {
		return nil, err
	}
	owner.master, err = DeriveAccountMaster(ctx, d, policy, password, ask)
	if err != nil {
		return nil, err
	}
	owner.root, err = owner.master.DeriveTrustRoot(ctx, metadata.Binding())
	if err != nil {
		return nil, err
	}
	if len(journal) != 0 {
		err = owner.root.Use(func(root []byte) error { _, e := OpenTrustRootTransition(root, metadata.Binding(), journal); return e })
		if err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	owner.file, owner.journal = bytes.Clone(raw), bytes.Clone(journal)
	return owner, nil
}
