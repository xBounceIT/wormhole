package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func unlockStateFixture(t *testing.T) ([][][]byte, vault.UserKeyState, ed25519.PrivateKey) {
	t.Helper()
	material, err := parseAccountKeyMaterial(accountMaterialRows(), admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{79}, 32))
	t.Cleanup(func() { vault.Wipe(private) })
	state := vault.UserKeyState{FormatVersion: 1, WorkspaceID: material.Binding.WorkspaceID, UserID: material.Binding.UserID, Sequence: 4, Active: true, Encryption: material.Binding.Encryption, Signing: material.Binding.Signing, MinimumEncryptionCertificate: 3, MinimumSigningCertificate: 3, Signer: material.EncryptionCertificate.Signer}
	state, err = vault.SignUserKeyState(state, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := vault.EncodeUserKeyState(state)
	if err != nil {
		t.Fatal(err)
	}
	return [][][]byte{{hex.AppendEncode(nil, raw), []byte("4")}}, state, private
}

func TestAccountStateParsing(t *testing.T) {
	rows, state, private := unlockStateFixture(t)
	got, err := parseAccountKeyState(rows, admissionRequest())
	if err != nil || got.Sequence != state.Sequence {
		t.Fatal("valid state rejected")
	}
	for _, bad := range [][][][]byte{nil, {{}}, {{[]byte("z"), []byte("4")}}, {{[]byte("00"), []byte("4")}}, {{bytes.Repeat([]byte{'0'}, 2*vault.MaxUserKeyStateBytes+1), []byte("4")}}, {{rows[0][0], []byte("04")}}, {{rows[0][0], []byte("5")}}} {
		if value, err := parseAccountKeyState(bad, admissionRequest()); value != nil || err != ErrAdmissionResponse {
			t.Fatal("malformed/mismatched state accepted")
		}
	}
	for _, mutate := range []func(*vault.UserKeyState){func(s *vault.UserKeyState) { s.WorkspaceID = uuid.New() }, func(s *vault.UserKeyState) { s.UserID = uuid.New() }} {
		wrong := state
		mutate(&wrong)
		wrong, _ = vault.SignUserKeyState(wrong, private)
		raw, _ := vault.EncodeUserKeyState(wrong)
		if value, err := parseAccountKeyState([][][]byte{{hex.AppendEncode(nil, raw), []byte("4")}}, admissionRequest()); value != nil || err != ErrAdmissionResponse {
			t.Fatal("cross-account state accepted")
		}
	}
	combined := accountMaterialRows()
	combined[0] = append(combined[0], rows[0]...)
	material, err := parseAccountUnlockMaterial(combined, admissionRequest(), 1)
	if err != nil || material.State == nil {
		t.Fatal("complete unlock material rejected")
	}
	for _, bad := range [][][][]byte{nil, accountMaterialRows()} {
		if _, err := parseAccountUnlockMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
			t.Fatal("bad combined shape accepted")
		}
	}
	copyRow := func() [][][]byte { return [][][]byte{append([][]byte(nil), combined[0]...)} }
	bad := copyRow()
	bad[0][0] = []byte("bad")
	if _, err := parseAccountUnlockMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
		t.Fatal("bad capsule accepted")
	}
	bad = copyRow()
	bad[0][24] = []byte("00")
	if _, err := parseAccountUnlockMaterial(bad, admissionRequest(), 1); err != ErrAdmissionResponse {
		t.Fatal("bad combined state accepted")
	}
	for _, mutate := range []func(*vault.UserKeyState){func(s *vault.UserKeyState) { s.Encryption.ID = uuid.New() }, func(s *vault.UserKeyState) { s.Signing.Version++ }, func(s *vault.UserKeyState) { s.Signer.ID = uuid.New() }} {
		wrong := state
		mutate(&wrong)
		wrong, _ = vault.SignUserKeyState(wrong, private)
		raw, _ := vault.EncodeUserKeyState(wrong)
		bad := copyRow()
		bad[0][24] = hex.AppendEncode(nil, raw)
		if value, err := parseAccountUnlockMaterial(bad, admissionRequest(), 1); value != nil || err != ErrAdmissionResponse {
			t.Fatal("mixed account materials accepted")
		}
	}
	wipeQueryRows(rows)
	if !bytes.Equal(got.Signature, state.Signature) {
		t.Fatal("decoded state aliases wire data")
	}
}
