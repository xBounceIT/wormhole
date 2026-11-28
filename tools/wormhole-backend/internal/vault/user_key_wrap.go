package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"

	"github.com/google/uuid"
)

const userKeyPlaintextBytes = 1 + 32 + ed25519.SeedSize

// UserKeyBinding comes from the authenticated account/key graph, not from an
// envelope's self-description. Revision is the account wrapping revision.
type UserKeyBinding struct {
	WorkspaceID uuid.UUID `json:"workspaceId"`
	UserID      uuid.UUID `json:"userId"`
	Encryption  KeyRef    `json:"encryption"`
	Signing     KeyRef    `json:"signing"`
	Revision    uint64    `json:"revision"`
}

func (b UserKeyBinding) binding() (Binding, []byte, error) {
	if b.WorkspaceID == uuid.Nil || b.UserID == uuid.Nil || b.Encryption.ID == uuid.Nil || b.Signing.ID == uuid.Nil || b.Encryption.ID == b.Signing.ID || b.Encryption.Version == 0 || b.Signing.Version == 0 || b.Encryption.Version > math.MaxInt32 || b.Signing.Version > math.MaxInt32 || b.Revision == 0 || b.Revision > math.MaxInt64 {
		return Binding{}, nil, ErrFormat
	}
	info := canonical("wormhole/v1/user-key-context", b.WorkspaceID[:], b.UserID[:], b.Encryption.ID[:], binary.BigEndian.AppendUint32(nil, b.Encryption.Version), b.Signing.ID[:], binary.BigEndian.AppendUint32(nil, b.Signing.Version), binary.BigEndian.AppendUint64(nil, b.Revision))
	salt := sha256.Sum256(info)
	return Binding{WorkspaceID: b.WorkspaceID.String(), Table: "Users", OwnerID: b.UserID.String(), Field: "private-keys/" + hex.EncodeToString(salt[:]), KeyID: b.Encryption.ID.String(), KeyVersion: b.Encryption.Version}, salt[:], nil
}

// SealUserKeys accepts the 32-byte account master after password derivation and
// the policy-required ASK mix. Passwords and ASK are never serialized here.
func SealUserKeys(accountMaster []byte, b UserKeyBinding, keys *UserKeys) (Envelope, error) {
	if keys == nil || len(keys.EncryptionPrivate) != 32 || len(keys.SigningSeed) != ed25519.SeedSize {
		return Envelope{}, ErrFormat
	}
	binding, salt, err := b.binding()
	if err != nil {
		return Envelope{}, err
	}
	unlock, err := DeriveKey(accountMaster, salt, PurposeUnlock)
	if err != nil {
		return Envelope{}, err
	}
	defer Wipe(unlock)
	plain := make([]byte, userKeyPlaintextBytes)
	defer Wipe(plain)
	plain[0] = 1
	copy(plain[1:33], keys.EncryptionPrivate)
	copy(plain[33:], keys.SigningSeed)
	return Seal(unlock, binding, plain)
}

// OpenUserKeys releases temporary private material only when both derived public
// keys match the independently certified keys. The owner must wipe the result.
func OpenUserKeys(accountMaster []byte, b UserKeyBinding, envelope Envelope, expected UserPublicKeys) (*UserKeys, error) {
	if len(envelope.Ciphertext) != userKeyPlaintextBytes+16 || len(expected.Signing) != ed25519.PublicKeySize {
		return nil, ErrFormat
	}
	if err := validateX25519Public(expected.Encryption); err != nil {
		return nil, err
	}
	binding, salt, err := b.binding()
	if err != nil {
		return nil, err
	}
	unlock, err := DeriveKey(accountMaster, salt, PurposeUnlock)
	if err != nil {
		return nil, err
	}
	defer Wipe(unlock)
	plain, err := Open(unlock, binding, envelope)
	if err != nil {
		return nil, err
	}
	defer Wipe(plain)
	if len(plain) != userKeyPlaintextBytes || plain[0] != 1 {
		return nil, ErrFormat
	}
	keys := &UserKeys{EncryptionPrivate: append([]byte(nil), plain[1:33]...), SigningSeed: append([]byte(nil), plain[33:]...)}
	public, err := keys.Public()
	if err != nil || !bytes.Equal(public.Encryption, expected.Encryption) || !bytes.Equal(public.Signing, expected.Signing) {
		keys.Wipe()
		return nil, ErrAuthentication
	}
	return keys, nil
}

// RewrapUserKeys prepares a password change without rotating the user keys.
// The caller must atomically publish this revision and every device SCRAM verifier.
func RewrapUserKeys(oldMaster, newMaster []byte, b UserKeyBinding, envelope Envelope, expected UserPublicKeys) (UserKeyBinding, Envelope, error) {
	if len(oldMaster) != 32 || len(newMaster) != 32 || b.Revision >= math.MaxInt64 {
		return UserKeyBinding{}, Envelope{}, ErrFormat
	}
	keys, err := OpenUserKeys(oldMaster, b, envelope, expected)
	if err != nil {
		return UserKeyBinding{}, Envelope{}, err
	}
	defer keys.Wipe()
	b.Revision++
	wrapped, err := SealUserKeys(newMaster, b, keys)
	if err != nil {
		return UserKeyBinding{}, Envelope{}, err
	}
	return b, wrapped, nil
}
