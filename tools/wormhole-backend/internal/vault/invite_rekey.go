package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"

	"github.com/google/uuid"
)

// UserKeys are temporary native inputs. Long-lived ownership requires securemem.
// They must never be persisted directly, and their owner must call Wipe.
type UserKeys struct {
	EncryptionPrivate []byte `json:"-"`
	SigningSeed       []byte `json:"-"`
}

type UserPublicKeys struct {
	Encryption []byte `json:"encryption"`
	Signing    []byte `json:"signing"`
}

func (k *UserKeys) Wipe() {
	if k == nil {
		return
	}
	Wipe(k.EncryptionPrivate)
	Wipe(k.SigningSeed)
	k.EncryptionPrivate, k.SigningSeed = nil, nil
}

func (k *UserKeys) Public() (UserPublicKeys, error) {
	if k == nil || len(k.EncryptionPrivate) != 32 || len(k.SigningSeed) != ed25519.SeedSize {
		return UserPublicKeys{}, ErrFormat
	}
	x, err := ecdh.X25519().NewPrivateKey(k.EncryptionPrivate)
	if err != nil {
		return UserPublicKeys{}, ErrFormat
	}
	s := ed25519.NewKeyFromSeed(k.SigningSeed)
	defer Wipe(s)
	return UserPublicKeys{Encryption: x.PublicKey().Bytes(), Signing: append([]byte(nil), s[32:]...)}, nil
}

// InviteRekeyProof is public. The verifier supplies the expected invite context
// and previously certified bootstrap keys independently, never from this proof.
type InviteRekeyProof struct {
	FormatVersion   uint16         `json:"formatVersion"`
	EncryptionKeyID uuid.UUID      `json:"encryptionKeyId"`
	SigningKeyID    uuid.UUID      `json:"signingKeyId"`
	KeyVersion      uint32         `json:"keyVersion"`
	Public          UserPublicKeys `json:"public"`
	Signature       []byte         `json:"signature"`
}

func (p InviteRekeyProof) signingBytes(c InviteContext) ([]byte, error) {
	_, salt, err := c.binding()
	if err != nil {
		return nil, err
	}
	if p.FormatVersion != 1 || p.EncryptionKeyID == uuid.Nil || p.EncryptionKeyID == c.KeyID || p.SigningKeyID == uuid.Nil || p.SigningKeyID == c.KeyID || p.SigningKeyID == p.EncryptionKeyID || p.KeyVersion != 1 || len(p.Public.Signing) != ed25519.PublicKeySize {
		return nil, ErrFormat
	}
	if err := validateX25519Public(p.Public.Encryption); err != nil {
		return nil, err
	}
	return canonical("wormhole/v1/invite-rekey", salt, binary.BigEndian.AppendUint16(nil, p.FormatVersion), p.EncryptionKeyID[:], p.SigningKeyID[:], binary.BigEndian.AppendUint32(nil, p.KeyVersion), p.Public.Encryption, p.Public.Signing), nil
}

func validateX25519Public(key []byte) error {
	if !canonicalX25519Public(key) {
		return ErrFormat
	}
	// Reject X25519 low-order points before committing an unusable recipient key.
	public, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return ErrFormat
	}
	probe, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	shared, err := probe.ECDH(public)
	Wipe(shared)
	if err != nil {
		return ErrFormat
	}
	return nil
}

// Require the unique little-endian representative below 2^255-19. Otherwise
// high-bit/reduction aliases can bypass the bootstrap-key freshness comparison.
func canonicalX25519Public(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	for i := 31; i >= 0; i-- {
		limit := byte(255)
		if i == 31 {
			limit = 127
		} else if i == 0 {
			limit = 237
		}
		if key[i] < limit {
			return true
		}
		if key[i] > limit {
			return false
		}
	}
	return false
}

// PrepareInviteRekey creates fresh final user keys and certifies both public
// keys with the bootstrap signing key. Bootstrap keys remain available for
// rewrapping their issued key copies; the owner retires them after that step.
// The caller must first authenticate bootstrap material with OpenInviteBootstrap.
func PrepareInviteRekey(c InviteContext, bootstrap *InviteBootstrap) (*UserKeys, InviteRekeyProof, error) {
	if bootstrap == nil {
		return nil, InviteRekeyProof{}, ErrFormat
	}
	old, err := (&UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		return nil, InviteRekeyProof{}, err
	}
	if _, _, err = c.binding(); err != nil {
		return nil, InviteRekeyProof{}, err
	}
	k := &UserKeys{EncryptionPrivate: make([]byte, 32), SigningSeed: make([]byte, ed25519.SeedSize)}
	rand.Read(k.EncryptionPrivate)
	rand.Read(k.SigningSeed)
	pub, err := k.Public()
	if err != nil {
		k.Wipe()
		return nil, InviteRekeyProof{}, err
	}
	p := InviteRekeyProof{FormatVersion: 1, EncryptionKeyID: uuid.New(), SigningKeyID: uuid.New(), KeyVersion: 1, Public: pub}
	raw, err := p.signingBytes(c)
	if err != nil {
		k.Wipe()
		return nil, InviteRekeyProof{}, err
	}
	signer := ed25519.NewKeyFromSeed(bootstrap.SigningSeed)
	defer Wipe(signer)
	p.Signature = ed25519.Sign(signer, raw)
	if err = VerifyInviteRekey(c, p, old); err != nil {
		k.Wipe()
		return nil, InviteRekeyProof{}, err
	}
	return k, p, nil
}

// VerifyInviteRekey authenticates the transition only. It does not authorize a
// device, certify the user as an admin, or replace transactional single-use checks.
func VerifyInviteRekey(c InviteContext, p InviteRekeyProof, bootstrap UserPublicKeys) error {
	if !canonicalX25519Public(bootstrap.Encryption) || len(bootstrap.Signing) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return ErrFormat
	}
	raw, err := p.signingBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(bootstrap.Signing, raw, p.Signature) {
		return ErrAuthentication
	}
	if bytes.Equal(bootstrap.Encryption, p.Public.Encryption) || bytes.Equal(bootstrap.Signing, p.Public.Signing) {
		return ErrAuthentication
	}
	return nil
}
