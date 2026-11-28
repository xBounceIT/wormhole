package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type helloProofFixture struct {
	key      *rsa.PrivateKey
	der      []byte
	keyErr   error
	status   HelloAttestation
	proofErr error
	sign     func(*rsa.PrivateKey, []byte) ([]byte, error)
	observed [][]byte
}

func (f *helloProofFixture) PublicKey() ([]byte, error) { return f.der, f.keyErr }
func (f *helloProofFixture) Attestation(context.Context, *rsa.PublicKey) (HelloAttestation, error) {
	return f.status, f.proofErr
}
func (f *helloProofFixture) Sign(_ context.Context, challenge []byte) ([]byte, error) {
	digest := sha256.Sum256(challenge)
	proof, err := f.sign(f.key, digest[:])
	f.observed = append(f.observed, proof)
	return proof, err
}

func newHelloProofFixture(t *testing.T) *helloProofFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &helloProofFixture{key: key, der: der, status: HelloAttestationUnsupported,
		sign: func(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
			return rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest)
		}}
}

func TestHelloSlotBindsProofVaultFileAndSoftwareFallback(t *testing.T) {
	ctx := context.Background()
	document, root := slotFileFixture(t)
	proof := newHelloProofFixture(t)
	slot, err := CreateHelloSlot(ctx, document.VaultID, document.FileID, uuid.NewString(), document.RootKeyVersion, root, proof)
	if err != nil || len(proof.observed) != 2 || slot.Hello == nil {
		t.Fatal("deterministic provider did not produce one valid slot", err)
	}
	for _, borrowed := range proof.observed {
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("enrollment retained a provider proof")
		}
	}
	legacy := document
	legacy.Slots = append(legacy.Slots, slot)
	if _, err := EncodeSlotFile(root, legacy); err != ErrFormat {
		t.Fatal("legacy readers could be offered an unversioned Hello slot", err)
	}
	document.FormatVersion = SlotFileHelloVersion
	document.Slots = append(document.Slots, slot)
	raw, err := EncodeSlotFile(root, document)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeSlotFile(raw)
	if err != nil || VerifySlotFile(root, restored, document.VaultID, document.FileID, 1) != nil {
		t.Fatal("Hello metadata did not authenticate in its versioned slot file", err)
	}
	projection, _ := json.Marshal(restored.Descriptor())
	if !bytes.Contains(projection, []byte(`"kind":"hello"`)) || bytes.Contains(projection, []byte(`"publicKeyHash"`)) || bytes.Contains(projection, []byte(`"attestation"`)) {
		t.Fatal("startup projection exposed Hello material")
	}
	got, err := OpenHelloSlot(ctx, restored.VaultID, restored.FileID, restored.Slots[1], proof)
	defer Wipe(got)
	if err != nil || !bytes.Equal(got, root) || !bytes.Equal(proof.observed[2], make([]byte, 256)) {
		t.Fatal("matching fresh proof failed to open root or was retained", err)
	}
	if _, err := OpenHelloSlot(ctx, restored.VaultID, uuid.NewString(), slot, proof); err != ErrAuthentication {
		t.Fatal("a different file accepted the same Hello slot", err)
	}
	if _, err := OpenHelloSlot(ctx, restored.VaultID, restored.FileID, slot, newHelloProofFixture(t)); err != ErrAuthentication {
		t.Fatal("a Windows key replacement opened the slot", err)
	}
	document.Slots = []Slot{slot}
	if _, err := EncodeSlotFile(root, document); err != ErrPolicy {
		t.Fatal("Hello became the only unlock method", err)
	}
	changed := restored.Slots[1]
	changed.Hello.Attestation = HelloAttestationPresent
	if err := VerifySlotFile(root, restored, document.VaultID, document.FileID, 1); err != ErrAuthentication {
		t.Fatal("attestation metadata could be changed after publication", err)
	}
}

func TestHelloSlotRefusesNondeterministicOrInvalidProofs(t *testing.T) {
	ctx := context.Background()
	vaultID, fileID, slot := uuid.NewString(), uuid.NewString(), uuid.NewString()
	proof := newHelloProofFixture(t)
	operErr := errors.New("provider canceled")
	software := proof.sign
	for _, tc := range []struct {
		name string
		sign func(*rsa.PrivateKey, []byte) ([]byte, error)
		want error
	}{
		{"randomized", func(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
			return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}, ErrHelloNondeterministic},
		{"forged", func(*rsa.PrivateKey, []byte) ([]byte, error) { return make([]byte, 256), nil }, ErrAuthentication},
		{"canceled", func(*rsa.PrivateKey, []byte) ([]byte, error) { return make([]byte, 256), operErr }, operErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof.sign, proof.observed = tc.sign, nil
			if saved, err := CreateHelloSlot(ctx, vaultID, fileID, slot, 1, testKey(), proof); !errors.Is(err, tc.want) || saved.ID != "" {
				t.Fatal("noneligible provider created a slot", err)
			}
			for _, borrowed := range proof.observed {
				if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
					t.Fatal("rejected proof was retained")
				}
			}
		})
	}
	proof.sign, proof.proofErr = software, operErr
	if _, err := CreateHelloSlot(ctx, vaultID, fileID, slot, 1, testKey(), proof); err != operErr {
		t.Fatal("attestation transport failure silently approved", err)
	}
	proof.proofErr, proof.status = nil, "self-asserted-tpm"
	if _, err := CreateHelloSlot(ctx, vaultID, fileID, slot, 1, testKey(), proof); err != ErrPolicy {
		t.Fatal("unrecognized attestation result silently approved", err)
	}
}

func TestOpenHelloSlotRejectsMalformedSlotsAndCanceledPresence(t *testing.T) {
	ctx := context.Background()
	vaultID, fileID, slotID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	provider := newHelloProofFixture(t)
	slot, err := CreateHelloSlot(ctx, vaultID, fileID, slotID, 1, testKey(), provider)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		change func(*Slot)
		want   error
	}{
		{func(slot *Slot) { slot.Hello = nil }, ErrFormat},
		{func(slot *Slot) { slot.ID = "unnamed" }, ErrFormat},
		{func(slot *Slot) { slot.WrappedKey.Ciphertext = nil }, ErrFormat},
		{func(slot *Slot) { slot.WrappedKey.SuiteID = 0 }, ErrFormat},
	} {
		bad := slot
		invalid.change(&bad)
		if root, err := OpenHelloSlot(ctx, vaultID, fileID, bad, provider); root != nil || err != invalid.want {
			t.Fatalf("invalid slot reached native opening: %v", err)
		}
	}
	badDER := *provider
	badDER.der = []byte("invalid")
	if root, err := OpenHelloSlot(ctx, vaultID, fileID, slot, &badDER); root != nil || err != ErrFormat {
		t.Fatal("invalid public key reached proof", err)
	}
	probeErr := errors.New("could not retrieve public key")
	badDER.keyErr = probeErr
	if root, err := OpenHelloSlot(ctx, vaultID, fileID, slot, &badDER); root != nil || err != probeErr {
		t.Fatal("public key transport failure disappeared", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	validSignature := provider.sign
	provider.sign = func(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
		cancel()
		return validSignature(key, digest)
	}
	if root, err := OpenHelloSlot(cancelled, vaultID, fileID, slot, provider); root != nil || err != context.Canceled {
		t.Fatal("a proof received after cancel opened the slot", err)
	}
	if root, err := OpenHelloSlot(cancelled, vaultID, fileID, slot, provider); root != nil || err != context.Canceled {
		t.Fatal("a canceled call opened the slot", err)
	}
	provider.sign = func(*rsa.PrivateKey, []byte) ([]byte, error) { return nil, probeErr }
	if root, err := OpenHelloSlot(ctx, vaultID, fileID, slot, provider); root != nil || err != probeErr {
		t.Fatal("a failed presence operation was not propagated", err)
	}
	provider.sign = func(*rsa.PrivateKey, []byte) ([]byte, error) { return make([]byte, 256), nil }
	if root, err := OpenHelloSlot(ctx, vaultID, fileID, slot, provider); root != nil || err != ErrAuthentication {
		t.Fatal("a forged native signature opened the slot", err)
	}
}
