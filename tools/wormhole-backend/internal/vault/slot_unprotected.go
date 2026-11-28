package vault

// An unprotected slot is OS custody, never a user-presence or password factor.
// The native caller owns a random 32-byte platform key in DPAPI/Keychain/Secret
// Service. Neither that key nor the root may enter a renderer or a plaintext file.
// This primitive does not publish a slot or choose its policy/storage authority.
func CreateUnprotectedSlot(vaultID, id string, version uint32, vaultKey, platformKey []byte) (Slot, error) {
	slot := Slot{ID: id, Kind: SlotUnprotected, WrappedKey: Envelope{KeyVersion: version}}
	if len(vaultKey) != 32 || len(platformKey) != 32 {
		return Slot{}, ErrFormat
	}
	key, err := DeriveKey(platformKey, []byte(vaultID), PurposeUnlock)
	if err != nil {
		return Slot{}, err
	}
	defer Wipe(key)
	slot.WrappedKey, err = Seal(key, slotBinding(vaultID, slot), vaultKey)
	return slot, err
}

// The slot kind participates in authenticated data. Recovery/password packets
// cannot be retagged as OS-only custody even if a caller reuses the same factor.
func OpenUnprotectedSlot(vaultID string, slot Slot, platformKey []byte) ([]byte, error) {
	if slot.Kind != SlotUnprotected || slot.Preset != "" || len(slot.Salt) != 0 || slot.ASKRequired || len(slot.FactorIDs) != 0 || len(platformKey) != 32 {
		return nil, ErrFormat
	}
	key, err := DeriveKey(platformKey, []byte(vaultID), PurposeUnlock)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return openSlot(key, vaultID, slot)
}
