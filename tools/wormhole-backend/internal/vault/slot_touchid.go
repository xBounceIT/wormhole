package vault

import "encoding/binary"

func (slot Slot) validTouchID() bool {
	return slot.Kind == SlotTouchID && slot.Preset == "" && len(slot.Salt) == 0 &&
		!slot.ASKRequired && len(slot.FactorIDs) == 0 && slot.Hello == nil
}

func touchIDWrappingKey(factor []byte, vaultID, fileID string, slot Slot) ([]byte, error) {
	if len(factor) != 32 || !canonicalID(vaultID) || !canonicalID(fileID) || !canonicalID(slot.ID) || slot.WrappedKey.KeyVersion == 0 {
		return nil, ErrFormat
	}
	coordinates := binary.BigEndian.AppendUint32([]byte(vaultID+fileID+slot.ID), slot.WrappedKey.KeyVersion)
	return DeriveKey(factor, coordinates, PurposeTouchID)
}

// factor is the caller-owned, device-only random value held by the signed
// Keychain helper. The helper never receives the vault root.
func CreateTouchIDSlot(vaultID, fileID, id string, version uint32, root, factor []byte) (Slot, error) {
	if len(root) != 32 {
		return Slot{}, ErrFormat
	}
	slot := Slot{ID: id, Kind: SlotTouchID, WrappedKey: Envelope{KeyVersion: version}}
	key, err := touchIDWrappingKey(factor, vaultID, fileID, slot)
	if err != nil {
		return Slot{}, err
	}
	defer Wipe(key)
	slot.WrappedKey, err = Seal(key, slotBinding(vaultID, slot), root)
	return slot, err
}

func OpenTouchIDSlot(vaultID, fileID string, slot Slot, factor []byte) ([]byte, error) {
	if !slot.validTouchID() || len(slot.WrappedKey.Ciphertext) != 48 {
		return nil, ErrFormat
	}
	key, err := touchIDWrappingKey(factor, vaultID, fileID, slot)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return openSlot(key, vaultID, slot)
}
