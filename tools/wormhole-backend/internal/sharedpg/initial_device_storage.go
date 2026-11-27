package sharedpg

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrDeviceStorageCleanup = errors.New("shared device storage cleanup is unconfirmed")

func allocateDeviceStorage(required bool) (accountMasterMemory, error) {
	return securemem.New(32, required)
}

// Called only by native initial preparation while its original factors remain
// borrowed. Failure leaves allocated ownership with p.Close, including uncertain
// release. No factor is retained. The random storage root is generated directly
// in native memory; wrapping and metadata sealing borrow that buffer.
func (p *PreparedInitialEnrollment) prepareDeviceStorage(ctx context.Context, password, ask []byte, allocate func(bool) (accountMasterMemory, error)) error {
	if ctx == nil || p == nil || p.closed || p.master == nil || p.root == nil || p.commit == nil || p.storage != nil || len(p.deviceFile) != 0 {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.commit.ValidateAccountMaster(p.master); err != nil {
		return err
	}
	storage, err := allocate(p.master.requireLocked)
	if err != nil {
		return err
	}
	p.storage = storage
	err = storage.With(func(key []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rand.Read(key)
		slots, err := newDevicePasswordSlots(ctx, key, password, ask, p.master.preset)
		if err != nil {
			return err
		}
		envelope, err := p.SealDeviceEnrollment(key, slots)
		if err != nil {
			return err
		}
		p.deviceFile, err = EncodeDeviceEnrollmentFile(key, slots, envelope)
		return err
	})
	if err != nil {
		return err
	}
	return ctx.Err()
}

func newDevicePasswordSlots(ctx context.Context, root, password, ask []byte, preset vault.KDFPreset) (vault.SlotFile, error) {
	// The signed Default-only low-KDF exception is inside encrypted metadata.
	// A pre-unlock slot must always use V1 or stronger.
	if preset == vault.KDFLow {
		preset = vault.KDFV1
	}
	slots := vault.SlotFile{FormatVersion: 1, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(),
		RootKeyVersion: 1, Sequence: 1, FileEpoch: 1}
	slot, err := vault.CreatePasswordSlot(ctx, slots.VaultID, uuid.NewString(), 1, root, password, ask, preset)
	if err != nil {
		return vault.SlotFile{}, err
	}
	slots.Slots = []vault.Slot{slot}
	raw, err := vault.EncodeSlotFile(root, slots)
	if err != nil {
		return vault.SlotFile{}, err
	}
	return vault.DecodeSlotFile(raw)
}

// BorrowDeviceStorage lends the prepared random root and authenticated slot/
// metadata pair for durable publication. The callback must not retain the root,
// close this owner or reenter BorrowDeviceStorage. Borrow may be nested because
// its account master and device root have independent lifetimes and locks.
// Serialize all borrowing with Close. The decoded
// metadata belongs to this call, so mutations cannot change the prepared file.
func (p *PreparedInitialEnrollment) BorrowDeviceStorage(use func([]byte, vault.SlotFile, []byte) error) error {
	if p == nil || p.closed || p.storage == nil || use == nil || len(p.deviceFile) == 0 {
		return ErrConfiguration
	}
	slots, envelope, err := DecodeDeviceEnrollmentFile(p.deviceFile)
	if err != nil {
		return err
	}
	return p.storage.With(func(key []byte) error {
		if _, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, slots.Sequence, envelope); err != nil {
			return err
		}
		return use(key, slots, envelope)
	})
}

func (p *PreparedInitialEnrollment) DeviceStorageLocked() bool {
	return p != nil && !p.closed && p.storage != nil && p.storage.Locked()
}
