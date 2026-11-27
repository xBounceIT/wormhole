package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
)

type SlotKind string

const (
	SlotPassword    SlotKind = "password"
	SlotRecovery    SlotKind = "recovery"
	SlotUnprotected SlotKind = "unprotected"
	SlotHello       SlotKind = "hello"
	SlotTouchID     SlotKind = "touch-id"
	SlotAND         SlotKind = "and"
)

// Factor IDs reserve the AND-composite shape without pretending that a software
// factor is a hardware presence check. Unsupported slot kinds always fail closed.
type Slot struct {
	ID          string             `json:"id"`
	Kind        SlotKind           `json:"kind"`
	Preset      KDFPreset          `json:"preset,omitempty"`
	Salt        []byte             `json:"salt,omitempty"`
	ASKRequired bool               `json:"askRequired"`
	FactorIDs   []string           `json:"factorIds,omitempty"`
	Hello       *HelloSlotMetadata `json:"hello,omitempty"`
	WrappedKey  Envelope           `json:"wrappedKey"`
}

func slotBinding(vaultID string, slot Slot) Binding {
	return Binding{vaultID, "Slots", slot.ID, string(slot.Kind) + "/" + string(slot.Preset), "vault", slot.WrappedKey.KeyVersion}
}

func CreatePasswordSlot(ctx context.Context, vaultID, id string, version uint32, vaultKey, password, ask []byte, preset KDFPreset) (Slot, error) {
	slot := Slot{ID: id, Kind: SlotPassword, Preset: preset, Salt: make([]byte, 32), ASKRequired: len(ask) != 0, WrappedKey: Envelope{KeyVersion: version}}
	if len(vaultKey) != 32 || (len(ask) != 0 && len(ask) != 32) {
		return Slot{}, ErrFormat
	}
	if _, err := slotBinding(vaultID, slot).aad(); err != nil {
		return Slot{}, err
	}
	rand.Read(slot.Salt)
	key, err := passwordSlotKey(ctx, slot, password, ask)
	if err != nil {
		return Slot{}, err
	}
	defer Wipe(key)
	slot.WrappedKey, err = Seal(key, slotBinding(vaultID, slot), vaultKey)
	return slot, err
}

func passwordSlotKey(ctx context.Context, slot Slot, password, ask []byte) ([]byte, error) {
	if slot.Kind != SlotPassword || slot.Hello != nil || len(slot.FactorIDs) != 0 || len(slot.Salt) != 32 || (slot.ASKRequired && len(ask) != 32) || (!slot.ASKRequired && len(ask) != 0) {
		return nil, ErrFormat
	}
	master, err := DerivePassword(ctx, password, slot.Salt, slot.Preset)
	if err != nil {
		return nil, err
	}
	defer Wipe(master)
	mixed, err := MixAccountSecret(master, ask, slot.ASKRequired)
	if err != nil {
		return nil, err
	}
	defer Wipe(mixed)
	return DeriveKey(mixed, nil, PurposeUnlock)
}

// The caller must check the authenticated profile's KDF floor before deriving.
// Unlocking only authenticates a slot; VerifyKeyCheck must precede opening a DB.
func OpenPasswordSlot(ctx context.Context, vaultID string, slot Slot, password, ask []byte) ([]byte, error) {
	if _, err := slotBinding(vaultID, slot).aad(); err != nil {
		return nil, err
	}
	if err := validateEnvelope(slotBinding(vaultID, slot), slot.WrappedKey); err != nil {
		return nil, err
	}
	if len(slot.WrappedKey.Ciphertext) != 32+16 {
		return nil, ErrFormat
	}
	key, err := passwordSlotKey(ctx, slot, password, ask)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return openSlot(key, vaultID, slot)
}

func openSlot(key []byte, vaultID string, slot Slot) ([]byte, error) {
	plaintext, err := Open(key, slotBinding(vaultID, slot), slot.WrappedKey)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != 32 {
		Wipe(plaintext)
		return nil, ErrFormat
	}
	return plaintext, nil
}

func CreateRecoverySlot(vaultID, id string, version uint32, vaultKey, recoveryKey []byte) (Slot, error) {
	slot := Slot{ID: id, Kind: SlotRecovery, WrappedKey: Envelope{KeyVersion: version}}
	if len(vaultKey) != 32 || len(recoveryKey) != 32 {
		return Slot{}, ErrFormat
	}
	key, err := DeriveKey(recoveryKey, []byte(vaultID), PurposeUnlock)
	if err != nil {
		return Slot{}, err
	}
	defer Wipe(key)
	slot.WrappedKey, err = Seal(key, slotBinding(vaultID, slot), vaultKey)
	return slot, err
}

func OpenRecoverySlot(vaultID string, slot Slot, recoveryKey []byte) ([]byte, error) {
	if slot.Kind != SlotRecovery || slot.Hello != nil || slot.Preset != "" || len(slot.Salt) != 0 || slot.ASKRequired || len(slot.FactorIDs) != 0 {
		return nil, ErrFormat
	}
	key, err := DeriveKey(recoveryKey, []byte(vaultID), PurposeUnlock)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return openSlot(key, vaultID, slot)
}

// Recovery material stays in byte slices. Formatting must only be used in the
// display-once path; callers own wiping both the raw and formatted buffers.
func NewRecoveryKey() []byte { key := make([]byte, 32); rand.Read(key); return key }

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func recoveryChecksum(key []byte) [32]byte {
	const domain = "wormhole/v1/recovery"
	var input [len(domain) + 32]byte
	defer Wipe(input[:])
	copy(input[:], domain)
	copy(input[len(domain):], key)
	return sha256.Sum256(input[:])
}

func FormatRecoveryKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrFormat
	}
	checksum := recoveryChecksum(key)
	payload := make([]byte, 36)
	copy(payload, key)
	copy(payload[32:], checksum[:4])
	defer Wipe(payload)
	encoded := make([]byte, recoveryEncoding.EncodedLen(len(payload)))
	recoveryEncoding.Encode(encoded, payload)
	defer Wipe(encoded)
	result := make([]byte, 0, 76)
	result = append(result, "WHREC1-"...)
	for i, c := range encoded {
		if i > 0 && i%5 == 0 {
			result = append(result, '-')
		}
		result = append(result, c)
	}
	return result, nil
}

func ParseRecoveryKey(formatted []byte) ([]byte, error) {
	if len(formatted) != 76 || string(formatted[:7]) != "WHREC1-" {
		return nil, ErrFormat
	}
	encoded := make([]byte, 0, 58)
	defer func() { Wipe(encoded) }()
	for i, c := range formatted[7:] {
		if i%6 == 5 {
			if c != '-' {
				return nil, ErrFormat
			}
			continue
		}
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", rune(c)) {
			return nil, ErrFormat
		}
		encoded = append(encoded, c)
	}
	decoded := make([]byte, recoveryEncoding.DecodedLen(len(encoded)))
	defer Wipe(decoded)
	n, err := recoveryEncoding.Decode(decoded, encoded)
	if err != nil || n != 36 {
		return nil, ErrFormat
	}
	// Reject alternate encodings with nonzero unused base32 tail bits. Otherwise
	// some last-character typos decode to the same payload and evade the checksum.
	reencoded := make([]byte, len(encoded))
	defer Wipe(reencoded)
	recoveryEncoding.Encode(reencoded, decoded)
	if subtle.ConstantTimeCompare(reencoded, encoded) != 1 {
		return nil, ErrFormat
	}
	checksum := recoveryChecksum(decoded[:32])
	if subtle.ConstantTimeCompare(checksum[:4], decoded[32:]) != 1 {
		return nil, ErrAuthentication
	}
	return append([]byte(nil), decoded[:32]...), nil
}
