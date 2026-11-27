package vault

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
)

var ErrHelloNondeterministic = errors.New("vault_hello_nondeterministic_signature")

type HelloAttestation string

const (
	HelloAttestationPresent     HelloAttestation = "evidence-present"
	HelloAttestationUnsupported HelloAttestation = "unsupported"
	HelloAttestationTPMVerified HelloAttestation = "tpm-verified"
)

// Attestation records the certificate and key proof result at enrollment. An
// older evidence-present value does not carry hardware authority.
type HelloSlotMetadata struct {
	PublicKeyHash []byte           `json:"publicKeyHash"`
	Attestation   HelloAttestation `json:"attestation"`
}

// HelloCredential is owned by native code. A returned signature is an owned
// mutable buffer, wiped after verification and derivation.
type HelloCredential interface {
	PublicKey() ([]byte, error)
	Attestation(context.Context, *rsa.PublicKey) (HelloAttestation, error)
	Sign(context.Context, []byte) ([]byte, error)
}

func (slot Slot) validHello() bool {
	return slot.Kind == SlotHello && slot.Hello != nil && len(slot.Hello.PublicKeyHash) == sha256.Size &&
		(slot.Hello.Attestation == HelloAttestationPresent || slot.Hello.Attestation == HelloAttestationUnsupported ||
			slot.Hello.Attestation == HelloAttestationTPMVerified) &&
		slot.Preset == "" && len(slot.Salt) == 0 && !slot.ASKRequired && len(slot.FactorIDs) == 0
}

func helloChallenge(vaultID, fileID, slotID string, version uint32) ([32]byte, error) {
	if !canonicalID(vaultID) || !canonicalID(fileID) || !canonicalID(slotID) || version == 0 {
		return [32]byte{}, ErrFormat
	}
	context := []byte(vaultID + fileID + slotID)
	context = binary.BigEndian.AppendUint32(context, version)
	return sha256.Sum256(canonical("wormhole/v1/hello-challenge", context)), nil
}

func helloPublicKey(credential HelloCredential) (*rsa.PublicKey, [32]byte, error) {
	der, err := credential.PublicKey()
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(der) < 256 || len(der) > 512 {
		return nil, [32]byte{}, ErrFormat
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || key.N.BitLen() != 2048 || key.E != 65537 {
		return nil, [32]byte{}, ErrFormat
	}
	return key, sha256.Sum256(der), nil
}

// The v1 proof accepts SHA-256 with PKCS#1 v1.5. An arbitrary or randomized
// response cannot become a repeatable vault factor.
func verifyHelloSignature(key *rsa.PublicKey, challenge, signature []byte) error {
	digest := sha256.Sum256(challenge)
	if len(signature) != key.Size() || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return ErrAuthentication
	}
	return nil
}

func helloWrappingKey(signature, challenge []byte) ([]byte, error) {
	digest := sha256.Sum256(signature)
	defer Wipe(digest[:])
	return DeriveKey(digest[:], challenge, PurposeHello)
}

func CreateHelloSlot(ctx context.Context, vaultID, fileID, slotID string, version uint32, root []byte, credential HelloCredential) (Slot, error) {
	if ctx == nil || credential == nil || len(root) != 32 {
		return Slot{}, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return Slot{}, err
	}
	challenge, err := helloChallenge(vaultID, fileID, slotID, version)
	if err != nil {
		return Slot{}, err
	}
	public, fingerprint, err := helloPublicKey(credential)
	if err != nil {
		return Slot{}, err
	}
	attestation, err := credential.Attestation(ctx, public)
	if err != nil {
		return Slot{}, err
	}
	slot := Slot{ID: slotID, Kind: SlotHello, Hello: &HelloSlotMetadata{PublicKeyHash: fingerprint[:], Attestation: attestation}, WrappedKey: Envelope{KeyVersion: version}}
	if !slot.validHello() {
		return Slot{}, ErrPolicy
	}
	first, err := credential.Sign(ctx, challenge[:])
	defer Wipe(first)
	if err != nil {
		return Slot{}, err
	}
	second, err := credential.Sign(ctx, challenge[:])
	defer Wipe(second)
	if err != nil {
		return Slot{}, err
	}
	if err = ctx.Err(); err != nil {
		return Slot{}, err
	}
	if subtle.ConstantTimeCompare(first, second) != 1 {
		return Slot{}, ErrHelloNondeterministic
	}
	if err := verifyHelloSignature(public, challenge[:], first); err != nil {
		return Slot{}, err
	}
	key, err := helloWrappingKey(first, challenge[:])
	if err != nil {
		return Slot{}, err
	}
	defer Wipe(key)
	slot.WrappedKey, err = Seal(key, slotBinding(vaultID, slot), root)
	return slot, err
}

func OpenHelloSlot(ctx context.Context, vaultID, fileID string, slot Slot, credential HelloCredential) ([]byte, error) {
	if ctx == nil || credential == nil || !slot.validHello() || len(slot.WrappedKey.Ciphertext) != 48 {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	challenge, err := helloChallenge(vaultID, fileID, slot.ID, slot.WrappedKey.KeyVersion)
	if err != nil {
		return nil, err
	}
	if err := validateEnvelope(slotBinding(vaultID, slot), slot.WrappedKey); err != nil {
		return nil, err
	}
	public, fingerprint, err := helloPublicKey(credential)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(fingerprint[:], slot.Hello.PublicKeyHash) != 1 {
		return nil, ErrAuthentication
	}
	signature, err := credential.Sign(ctx, challenge[:])
	defer Wipe(signature)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err := verifyHelloSignature(public, challenge[:], signature); err != nil {
		return nil, err
	}
	key, err := helloWrappingKey(signature, challenge[:])
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return openSlot(key, vaultID, slot)
}
