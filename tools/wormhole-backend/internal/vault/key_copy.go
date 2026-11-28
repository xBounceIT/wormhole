package vault

import (
	"crypto/ed25519"
	"encoding/binary"
	"math"

	"github.com/google/uuid"
)

type KeyRef struct {
	ID      uuid.UUID `json:"id"`
	Version uint32    `json:"version"`
}

// KeyCopyBinding is expected, authenticated key-graph metadata. Never obtain the
// trusted issuer key or authorization merely from a returned copy's fields.
type KeyCopyBinding struct {
	WorkspaceID uuid.UUID `json:"workspaceId"`
	Key         KeyRef    `json:"key"`
	Holder      KeyRef    `json:"holder"`
	Issuer      KeyRef    `json:"issuer"`
}

type SignedKeyCopy struct {
	Envelope  SealedBundle `json:"envelope"`
	Signature []byte       `json:"signature"`
}

func (b KeyCopyBinding) info() ([]byte, error) {
	if b.WorkspaceID == uuid.Nil || b.Key == b.Holder {
		return nil, ErrFormat
	}
	fields := [][]byte{b.WorkspaceID[:]}
	for _, ref := range []KeyRef{b.Key, b.Holder, b.Issuer} {
		if ref.ID == uuid.Nil || ref.Version == 0 || ref.Version > math.MaxInt32 {
			return nil, ErrFormat
		}
		fields = append(fields, ref.ID[:], binary.BigEndian.AppendUint32(nil, ref.Version))
	}
	return canonical("wormhole/v1/key-copy", fields...), nil
}

func keyCopySigningBytes(info []byte, copy SignedKeyCopy) ([]byte, error) {
	if err := validateSealedBundle(copy.Envelope); err != nil {
		return nil, err
	}
	if len(copy.Envelope.Ciphertext) != 32+16 {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/key-copy-signature", info, binary.BigEndian.AppendUint16(nil, copy.Envelope.FormatVersion), binary.BigEndian.AppendUint16(nil, copy.Envelope.SuiteID), copy.Envelope.Enc, copy.Envelope.Ciphertext), nil
}

// SealKeyCopy wraps one 256-bit key/seed for a user or organisation encryption
// key. Both the HPKE context and issuer signature bind every key-graph coordinate.
func SealKeyCopy(key []byte, b KeyCopyBinding, recipientPublic, issuerSigningSeed []byte) (SignedKeyCopy, error) {
	if len(key) != 32 || len(issuerSigningSeed) != ed25519.SeedSize || !canonicalX25519Public(recipientPublic) {
		return SignedKeyCopy{}, ErrFormat
	}
	info, err := b.info()
	if err != nil {
		return SignedKeyCopy{}, err
	}
	envelope, err := sealBundlePayload(recipientPublic, info, key)
	if err != nil {
		return SignedKeyCopy{}, err
	}
	copy := SignedKeyCopy{Envelope: envelope}
	raw, err := keyCopySigningBytes(info, copy)
	if err != nil {
		return SignedKeyCopy{}, err
	}
	signer := ed25519.NewKeyFromSeed(issuerSigningSeed)
	defer Wipe(signer)
	copy.Signature = ed25519.Sign(signer, raw)
	return copy, nil
}

// VerifyKeyCopy authenticates a copy before any private key is used. The issuer
// public key and every binding coordinate must be independently trusted.
func VerifyKeyCopy(b KeyCopyBinding, copy SignedKeyCopy, issuerPublic ed25519.PublicKey) error {
	_, err := verifiedKeyCopyInfo(b, copy, issuerPublic)
	return err
}

func verifiedKeyCopyInfo(b KeyCopyBinding, copy SignedKeyCopy, issuerPublic ed25519.PublicKey) ([]byte, error) {
	if len(issuerPublic) != ed25519.PublicKeySize || len(copy.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	info, err := b.info()
	if err != nil {
		return nil, err
	}
	raw, err := keyCopySigningBytes(info, copy)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(issuerPublic, raw, copy.Signature) {
		return nil, ErrAuthentication
	}
	return info, nil
}

// OpenKeyCopy verifies the independently pinned issuer before invoking HPKE.
// The caller owns and must wipe the returned temporary key.
func OpenKeyCopy(private []byte, b KeyCopyBinding, copy SignedKeyCopy, issuerPublic ed25519.PublicKey) ([]byte, error) {
	if len(private) != 32 {
		return nil, ErrFormat
	}
	info, err := verifiedKeyCopyInfo(b, copy, issuerPublic)
	if err != nil {
		return nil, err
	}
	return openBundlePayload(private, info, copy.Envelope)
}

// RewrapKeyCopy preserves the workspace and copied key identity while moving to
// a different holder. The caller must authenticate the new holder/issuer through
// the rekey certificate and commit all replacement copies atomically.
func RewrapKeyCopy(private []byte, b KeyCopyBinding, copy SignedKeyCopy, issuerPublic ed25519.PublicKey, newHolder KeyRef, newHolderPublic []byte, newIssuer KeyRef, newIssuerSeed []byte) (SignedKeyCopy, error) {
	if newHolder == b.Holder {
		return SignedKeyCopy{}, ErrFormat
	}
	key, err := OpenKeyCopy(private, b, copy, issuerPublic)
	if err != nil {
		return SignedKeyCopy{}, err
	}
	defer Wipe(key)
	b.Holder, b.Issuer = newHolder, newIssuer
	return SealKeyCopy(key, b, newHolderPublic, newIssuerSeed)
}
