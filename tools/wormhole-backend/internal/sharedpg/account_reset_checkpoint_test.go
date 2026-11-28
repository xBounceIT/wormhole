package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestAccountResetCheckpointRequiresDeviceRootAndExactWrapper(t *testing.T) {
	b := TrustBinding{WorkspaceID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1}
	root := bytes.Repeat([]byte{71}, 32)
	defer vault.Wipe(root)
	verifier, err := NewSCRAMVerifier(bytes.Repeat([]byte{33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	e := vault.Envelope{FormatVersion: 1, SuiteID: vault.SuiteAES256GCM, Nonce: make([]byte, 12), Ciphertext: make([]byte, 81)}
	p := PendingAccountReset{Offer: []byte("fixture"), DeviceID: b.DeviceID, KDF: vault.KDFV1, CapsuleDigest: enrollmentCapsuleDigest(e)}
	request := resetDeviceRequest{Version: 1, Pending: p, Envelope: e, Verifier: verifier, Name: "fixture device"}
	ciphertext, err := sealResetDeviceRequest(root, b, request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, verifier) {
		t.Fatal("local marker exposes verifier")
	}
	got, err := OpenPendingResetDevice(root, b, ciphertext)
	if err != nil || got.DeviceID != p.DeviceID || !bytes.Equal(got.CapsuleDigest, p.CapsuleDigest) {
		t.Fatal("exact pending selection did not reopen", err)
	}
	other := b
	other.DeviceID = uuid.New()
	var envelope vault.Envelope
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	request.Pending.CapsuleDigest = make([]byte, sha256.Size)
	mismatched, err := sealResetDeviceRequest(root, b, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		root    []byte
		binding TrustBinding
		raw     []byte
	}{
		{make([]byte, 32), b, ciphertext},
		{root, other, ciphertext},
		{root, b, nil},
		{root, b, []byte("{")},
		{root, b, tampered},
		{root, b, mismatched},
	} {
		if got, err := OpenPendingResetDevice(tc.root, tc.binding, tc.raw); err == nil || got.DeviceID != uuid.Nil {
			t.Fatal("invalid staging authorized continuation", err)
		}
	}
}
