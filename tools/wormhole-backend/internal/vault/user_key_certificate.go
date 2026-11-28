package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

// UserKeyCertificate binds one user's public key to an independently pinned
// organisation signer. It is not a capability or an administrator-role grant.
// Issuance requires the owning admin flow to verify enrollment/rekey possession.
type UserKeyCertificate struct {
	FormatVersion uint16    `json:"formatVersion"`
	WorkspaceID   uuid.UUID `json:"workspaceId"`
	UserID        uuid.UUID `json:"userId"`
	Key           KeyRef    `json:"key"`
	Kind          string    `json:"kind"`
	Suite         uint16    `json:"suite"`
	PublicKey     []byte    `json:"publicKey"`
	Revision      uint64    `json:"revision"`
	Signer        KeyRef    `json:"signer"`
	Signature     []byte    `json:"signature"`
}

func (c UserKeyCertificate) signingBytes() ([]byte, error) {
	if c.FormatVersion > FormatVersion {
		return nil, ErrNewerFormat
	}
	if c.FormatVersion != FormatVersion || c.WorkspaceID == uuid.Nil || c.UserID == uuid.Nil || c.Key.ID == uuid.Nil || c.Signer.ID == uuid.Nil || c.Key.ID == c.Signer.ID || c.Key.Version == 0 || c.Key.Version > math.MaxInt32 || c.Signer.Version == 0 || c.Signer.Version > math.MaxInt32 || c.Revision == 0 || c.Revision > math.MaxInt64 {
		return nil, ErrFormat
	}
	switch c.Kind {
	case "user-enc":
		if c.Suite != SuiteX25519HKDFSHA256AES256GCM {
			return nil, ErrFormat
		}
		if err := validateX25519Public(c.PublicKey); err != nil {
			return nil, err
		}
	case "user-sign":
		if c.Suite != 1 || len(c.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrFormat
		}
	default:
		return nil, ErrFormat
	}
	c.Signature = nil
	body, err := json.Marshal(c)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/user-key-certificate", body), nil
}

func SignUserKeyCertificate(c UserKeyCertificate, organisation ed25519.PrivateKey) (UserKeyCertificate, error) {
	if len(organisation) != ed25519.PrivateKeySize {
		return UserKeyCertificate{}, ErrFormat
	}
	body, err := c.signingBytes()
	if err != nil {
		return UserKeyCertificate{}, err
	}
	c.PublicKey = append([]byte(nil), c.PublicKey...)
	c.Signature = ed25519.Sign(organisation, body)
	return c, nil
}

// VerifyUserKeyCertificate takes identity, key reference, signer and rollback
// floors from trusted state, never from c itself. Revocation/current key state
// must also be checked against authenticated graph high-water marks by the caller.
func VerifyUserKeyCertificate(c UserKeyCertificate, workspace, user uuid.UUID, key KeyRef, kind string, signer KeyRef, organisation ed25519.PublicKey, minimumRevision uint64) error {
	body, err := c.signingBytes()
	if err != nil {
		return err
	}
	if len(organisation) != ed25519.PublicKeySize || c.WorkspaceID != workspace || c.UserID != user || c.Key != key || c.Kind != kind || c.Signer != signer || !ed25519.Verify(organisation, body, c.Signature) {
		return ErrAuthentication
	}
	if c.Revision < minimumRevision {
		return ErrRollback
	}
	return nil
}

// OpenCertifiedUserKeys requires independently authenticated identity/key binding,
// organisation pin and certificate revision floors. It verifies both certificates
// before decrypting and checks that both private keys derive the certified public
// keys. The returned private material remains caller-owned and must be wiped.
func OpenCertifiedUserKeys(master []byte, binding UserKeyBinding, envelope Envelope, encryption, signing UserKeyCertificate, signer KeyRef, organisation ed25519.PublicKey, minimumEncryptionRevision, minimumSigningRevision uint64) (*UserKeys, error) {
	if err := VerifyUserKeyCertificate(encryption, binding.WorkspaceID, binding.UserID, binding.Encryption, "user-enc", signer, organisation, minimumEncryptionRevision); err != nil {
		return nil, err
	}
	if err := VerifyUserKeyCertificate(signing, binding.WorkspaceID, binding.UserID, binding.Signing, "user-sign", signer, organisation, minimumSigningRevision); err != nil {
		return nil, err
	}
	return OpenUserKeys(master, binding, envelope, UserPublicKeys{Encryption: encryption.PublicKey, Signing: signing.PublicKey})
}
