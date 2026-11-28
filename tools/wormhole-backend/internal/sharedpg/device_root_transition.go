package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// DeviceRootTransition commits exact source bytes and the encrypted candidate.
// Only a remotely confirmed transition may publish Next as the active device.
type DeviceRootTransition struct {
	PreviousDigest []byte          `json:"previousDigest"`
	Next           json.RawMessage `json:"next"`
}

func (d *DeviceRootTransition) valid() bool {
	if d == nil || len(d.PreviousDigest) != sha256.Size {
		return false
	}
	_, _, err := DecodeDeviceEnrollmentFile(d.Next)
	return err == nil
}

type deviceTransitionFile struct {
	FormatVersion uint16          `json:"formatVersion"`
	Device        json.RawMessage `json:"device"`
	Transition    json.RawMessage `json:"transition"`
}

func decodeDeviceTransitionFile(raw []byte) ([]byte, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxTrustRootTransitionBytes {
		return nil, nil, ErrTrustState
	}
	var header struct {
		FormatVersion uint16 `json:"formatVersion"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, nil, ErrTrustState
	}
	if header.FormatVersion != 3 {
		return raw, nil, nil
	}
	var file deviceTransitionFile
	if json.Unmarshal(raw, &file) != nil || len(file.Transition) == 0 {
		return nil, nil, ErrTrustState
	}
	canonical, err := json.Marshal(file)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, nil, ErrTrustState
	}
	if _, _, err := DecodeDeviceEnrollmentFile(file.Device); err != nil {
		return nil, nil, ErrTrustState
	}
	return file.Transition, file.Device, nil
}

// UnverifiedTransitionDevice returns only untrusted slot/ciphertext candidates.
// Authenticate native selection, the password slot and device metadata before
// deriving the account root; then OpenTrustRootTransition must authenticate the
// journal and its exact candidate commitment before any use or network access.
func UnverifiedTransitionDevice(raw []byte) ([]byte, error) {
	_, candidate, err := decodeDeviceTransitionFile(raw)
	if err != nil || candidate == nil {
		return nil, ErrTrustState
	}
	return bytes.Clone(candidate), nil
}

// PrepareTrustRootTransitionWithDevice binds a previously authenticated device
// selection to a candidate produced with the SAME new password/ASK as newRoot.
// It authenticates both files; neither the candidate nor the journal is published.
// setupRaw may be absent for legacy trust without protected connection settings.
func PrepareTrustRootTransitionWithDevice(oldRoot, newRoot []byte, b TrustBinding, previousRaw, setupRaw, storageRoot, previousDevice, nextDevice []byte, vaultID, fileID string, minimumSequence, expectedRevision uint64) (TrustRootTransition, []byte, error) {
	oldSlots, oldEnvelope, err := DecodeDeviceEnrollmentFile(previousDevice)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	old, err := OpenDeviceEnrollment(storageRoot, oldSlots, vaultID, fileID, minimumSequence, oldEnvelope)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	if old.Binding() != b || oldSlots.Sequence == math.MaxUint64 {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	nextSlots, nextEnvelope, err := DecodeDeviceEnrollmentFile(nextDevice)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	next, err := OpenDeviceEnrollment(storageRoot, nextSlots, vaultID, fileID, oldSlots.Sequence+1, nextEnvelope)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	if nextSlots.Sequence != oldSlots.Sequence+1 {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	old.record.SlotSequence++
	if !reflect.DeepEqual(old.record, next.record) {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	if !devicePasswordSlotsAdvance(oldSlots.Slots, nextSlots.Slots, next.record.ASKRequired) {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	// Slot updates may change only the slot set, its MAC and its sequence.
	oldSlots.Sequence = nextSlots.Sequence
	oldSlots.Slots, nextSlots.Slots = nil, nil
	oldSlots.Authentication, nextSlots.Authentication = nil, nil
	if !reflect.DeepEqual(oldSlots, nextSlots) {
		return TrustRootTransition{}, nil, ErrTrustState
	}
	var record TrustRootTransition
	if len(setupRaw) == 0 {
		record, _, err = PrepareTrustRootTransition(oldRoot, newRoot, b, previousRaw, expectedRevision)
	} else {
		record, _, err = PrepareTrustRootTransitionWithSetup(oldRoot, newRoot, b, previousRaw, setupRaw, expectedRevision)
	}
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	digest := sha256.Sum256(previousDevice)
	record.FormatVersion = 3
	record.Device = &DeviceRootTransition{PreviousDigest: bytes.Clone(digest[:]), Next: bytes.Clone(nextDevice)}
	raw, err := SealTrustRootTransition(newRoot, b, record)
	if err != nil {
		return TrustRootTransition{}, nil, err
	}
	return record, raw, nil
}

func devicePasswordSlotsAdvance(previous, next []vault.Slot, askRequired bool) bool {
	var oldRecovery, newRecovery []vault.Slot
	var password *vault.Slot
	for i := range next {
		if next[i].Kind == vault.SlotRecovery {
			newRecovery = append(newRecovery, next[i])
		} else if next[i].Kind != vault.SlotPassword || password != nil {
			return false
		} else {
			password = &next[i]
		}
	}
	if password == nil || password.ASKRequired != askRequired {
		return false
	}
	selected, err := vault.Parameters(password.Preset)
	floor, _ := vault.Parameters(vault.KDFV1)
	if err != nil || selected.MemoryKiB < floor.MemoryKiB || selected.Iterations < floor.Iterations {
		return false
	}
	for _, slot := range previous {
		if slot.Kind == vault.SlotRecovery {
			oldRecovery = append(oldRecovery, slot)
			continue
		}
		cost, err := vault.Parameters(slot.Preset)
		if err != nil || selected.MemoryKiB < cost.MemoryKiB || selected.Iterations < cost.Iterations || password.ID == slot.ID || bytes.Equal(password.Salt, slot.Salt) {
			return false
		}
	}
	return reflect.DeepEqual(oldRecovery, newRecovery)
}
