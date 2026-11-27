package sharedpg

import (
	"context"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// PrepareDevicePasswordFile creates a candidate, never publishes it or changes
// PostgreSQL. Selection and its sequence floor must come from native enrollment.
// The caller must use the same borrowed new password and existing ASK for account
// derivation and coordinate publication through the password-change journal.
// Account KDF/ASK mode, identity, recovery slots and the storage root are preserved.
func PrepareDevicePasswordFile(ctx context.Context, storageRoot, previous []byte, vaultID, fileID string, minimumSequence uint64, password, ask []byte, osFloor, userFloor vault.Profile) ([]byte, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slots, envelope, err := DecodeDeviceEnrollmentFile(previous)
	if err != nil {
		return nil, err
	}
	metadata, err := OpenDeviceEnrollment(storageRoot, slots, vaultID, fileID, minimumSequence, envelope)
	if err != nil {
		return nil, err
	}
	if _, _, err := metadata.Derivation(osFloor, userFloor); err != nil {
		return nil, err
	}
	if slots.Sequence == math.MaxUint64 || (metadata.record.ASKRequired && len(ask) != 32) || (!metadata.record.ASKRequired && len(ask) != 0) {
		return nil, ErrConfiguration
	}
	// Unlocked policy cannot justify a low pre-unlock KDF on the next launch.
	preset := metadata.record.KDF
	if preset == vault.KDFLow {
		preset = vault.KDFV1
	}
	var retained []vault.Slot
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotRecovery {
			retained = append(retained, slot)
			continue
		}
		// Preserve stronger existing password-slot costs, even when the account
		// was derived at a lower authenticated KDF floor.
		selected, _ := vault.Parameters(preset)
		old, _ := vault.Parameters(slot.Preset)
		if old.MemoryKiB >= selected.MemoryKiB && old.Iterations >= selected.Iterations {
			preset = slot.Preset
		}
	}
	if len(retained) >= 16 {
		return nil, ErrConfiguration
	}
	slot, err := vault.CreatePasswordSlot(ctx, slots.VaultID, uuid.NewString(), 1, storageRoot, password, ask, preset)
	if err != nil {
		return nil, err
	}
	slots.Slots = append(retained, slot)
	slots.Sequence++
	raw, err := vault.EncodeSlotFile(storageRoot, slots)
	if err != nil {
		return nil, err
	}
	slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return nil, err
	}
	metadata.record.SlotSequence = slots.Sequence
	envelope, err = sealDeviceEnrollmentRecord(storageRoot, slots, metadata.record)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return EncodeDeviceEnrollmentFile(storageRoot, slots, envelope)
}
