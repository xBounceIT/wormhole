package vault

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/uuid"
)

// OrganisationRecoveryBinding identifies the two organisation keys sealed to
// an offline 256-bit recovery key. Obtain it and the expected public keys from
// authenticated recovery metadata before opening a server-supplied capsule.
type OrganisationRecoveryBinding struct {
	WorkspaceID uuid.UUID
	Encryption  KeyRef
	Signing     KeyRef
}

func (b OrganisationRecoveryBinding) envelopeBinding() (Binding, error) {
	if b.WorkspaceID == uuid.Nil || b.Encryption.ID == uuid.Nil || b.Signing.ID == uuid.Nil || b.Encryption.ID == b.Signing.ID || b.Encryption.Version == 0 || b.Signing.Version == 0 {
		return Binding{}, ErrFormat
	}
	return Binding{WorkspaceID: b.WorkspaceID.String(), Table: "OrganisationRecovery", OwnerID: b.Encryption.ID.String(), Field: "keys", KeyID: b.Signing.ID.String(), KeyVersion: b.Signing.Version}, nil
}

func organisationRecoveryKey(key []byte, b OrganisationRecoveryBinding) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrFormat
	}
	// The capsule authenticates both key IDs and the signing version. Include
	// the encryption version here so changing either reference also fails.
	var salt [36]byte
	copy(salt[:16], b.WorkspaceID[:])
	copy(salt[16:32], b.Encryption.ID[:])
	binary.BigEndian.PutUint32(salt[32:], b.Encryption.Version)
	return hkdf.Key(sha256.New, key, salt[:], "wormhole/v1/organisation-recovery", 32)
}

// SealOrganisationRecovery seals the organisation X25519 private key and
// Ed25519 seed together. The result can be stored with workspace ciphertext.
func SealOrganisationRecovery(recoveryKey []byte, b OrganisationRecoveryBinding, keys *UserKeys) (Envelope, error) {
	binding, err := b.envelopeBinding()
	if err != nil {
		return Envelope{}, err
	}
	if keys == nil || len(keys.EncryptionPrivate) != 32 || len(keys.SigningSeed) != 32 {
		return Envelope{}, ErrFormat
	}
	key, err := organisationRecoveryKey(recoveryKey, b)
	if err != nil {
		return Envelope{}, err
	}
	defer Wipe(key)
	var plaintext [64]byte
	defer Wipe(plaintext[:])
	copy(plaintext[:32], keys.EncryptionPrivate)
	copy(plaintext[32:], keys.SigningSeed)
	return Seal(key, binding, plaintext[:])
}

// OpenOrganisationRecovery verifies both derived public keys. The returned
// native key pair must be wiped by its caller.
func OpenOrganisationRecovery(recoveryKey []byte, b OrganisationRecoveryBinding, capsule Envelope, expected UserPublicKeys) (*UserKeys, error) {
	binding, err := b.envelopeBinding()
	if err != nil {
		return nil, err
	}
	if len(capsule.Ciphertext) != 64+16 {
		return nil, ErrFormat
	}
	key, err := organisationRecoveryKey(recoveryKey, b)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	plaintext, err := Open(key, binding, capsule)
	if err != nil {
		return nil, err
	}
	keys := &UserKeys{EncryptionPrivate: plaintext[:32:32], SigningSeed: plaintext[32:]}
	public, err := keys.Public()
	if err != nil || !bytes.Equal(public.Encryption, expected.Encryption) || !bytes.Equal(public.Signing, expected.Signing) {
		keys.Wipe()
		return nil, ErrAuthentication
	}
	return keys, nil
}
