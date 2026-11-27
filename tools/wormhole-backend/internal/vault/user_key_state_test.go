package vault

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"testing"

	"github.com/google/uuid"
)

func userStateFixture(t *testing.T) ([]byte, UserKeyBinding, *UserKeys, Envelope, ed25519.PrivateKey, UserKeyCertificate, UserKeyCertificate, UserKeyState, UserKeyTrust) {
	t.Helper()
	master, binding, keys, envelope, org, enc, sign := userCertificateFixture(t)
	state := UserKeyState{FormatVersion: FormatVersion, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Sequence: 7, Active: true, Encryption: binding.Encryption, Signing: binding.Signing, MinimumEncryptionCertificate: 3, MinimumSigningCertificate: 3, Signer: enc.Signer}
	state, err := SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	trust := UserKeyTrust{WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Signer: enc.Signer, Organisation: org.Public().(ed25519.PublicKey), MinimumSequence: 7, MinimumWrappingRevision: 1}
	return master, binding, keys, envelope, org, enc, sign, state, trust
}

func TestCurrentUserKeysAndRevocation(t *testing.T) {
	master, binding, keys, envelope, org, enc, sign, state, trust := userStateFixture(t)
	opened, err := OpenCurrentUserKeys(master, binding, envelope, enc, sign, state, trust)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("unexpected private pair")
	}
	opened.Wipe()
	revoked := state
	revoked.Active = false
	revoked.Sequence++
	revoked, err = SignUserKeyState(revoked, org)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUserKeyState(revoked, trust); err != nil {
		t.Fatal("cannot authenticate revocation for persistence")
	}
	if value, err := OpenCurrentUserKeys(master, binding, envelope, enc, sign, revoked, trust); value != nil || err != ErrPolicy {
		t.Fatal("revoked account opened")
	}
	trust.MinimumSequence = revoked.Sequence
	if value, err := OpenCurrentUserKeys(master, binding, envelope, enc, sign, state, trust); value != nil || err != ErrRollback {
		t.Fatal("old active state replayed after revocation")
	}
	trust.MinimumSequence = 7
	trust.MinimumWrappingRevision = 2
	if value, err := OpenCurrentUserKeys(master, binding, envelope, enc, sign, state, trust); value != nil || err != ErrRollback {
		t.Fatal("old password wrapper replayed")
	}
	trust.MinimumWrappingRevision = 1
	for _, mutate := range []func(*UserKeyState){func(s *UserKeyState) { s.Encryption.ID = uuid.New() }, func(s *UserKeyState) { s.Signing.Version++ }, func(s *UserKeyState) { s.MinimumEncryptionCertificate++ }, func(s *UserKeyState) { s.MinimumSigningCertificate++ }} {
		next := state
		mutate(&next)
		next.Sequence++
		next, err = SignUserKeyState(next, org)
		if err != nil {
			t.Fatal(err)
		}
		if value, err := OpenCurrentUserKeys(master, binding, envelope, enc, sign, next, trust); value != nil || err == nil {
			t.Fatal("superseded keys/certificates accepted")
		}
	}
	if value, err := OpenCurrentUserKeys(make([]byte, 32), binding, envelope, enc, sign, state, trust); value != nil || err != ErrAuthentication {
		t.Fatal("wrong master accepted")
	}
}

func TestUserKeyStateAuthentication(t *testing.T) {
	_, _, _, _, _, _, _, state, trust := userStateFixture(t)
	for _, mutate := range []func(*UserKeyState){
		func(s *UserKeyState) { s.WorkspaceID = uuid.New() }, func(s *UserKeyState) { s.UserID = uuid.New() }, func(s *UserKeyState) { s.Sequence++ }, func(s *UserKeyState) { s.Active = false }, func(s *UserKeyState) { s.Encryption.ID = uuid.New() }, func(s *UserKeyState) { s.Encryption.Version++ }, func(s *UserKeyState) { s.Signing.ID = uuid.New() }, func(s *UserKeyState) { s.Signing.Version++ }, func(s *UserKeyState) { s.Signer.ID = uuid.New() }, func(s *UserKeyState) { s.Signer.Version++ }, func(s *UserKeyState) { s.MinimumEncryptionCertificate++ }, func(s *UserKeyState) { s.MinimumSigningCertificate++ }, func(s *UserKeyState) { s.Signature = nil },
	} {
		changed := state
		mutate(&changed)
		if err := VerifyUserKeyState(changed, trust); err != ErrAuthentication {
			t.Fatalf("state mutation accepted: %v", err)
		}
	}
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 32)} {
		changed := trust
		changed.Organisation = key
		if err := VerifyUserKeyState(state, changed); err != ErrAuthentication {
			t.Fatal("untrusted organisation accepted")
		}
	}
}

func TestUserKeyStateFormat(t *testing.T) {
	_, _, _, _, org, _, _, state, trust := userStateFixture(t)
	for _, mutate := range []func(*UserKeyState){
		func(s *UserKeyState) { s.FormatVersion = 0 }, func(s *UserKeyState) { s.FormatVersion = 2 }, func(s *UserKeyState) { s.WorkspaceID = uuid.Nil }, func(s *UserKeyState) { s.UserID = uuid.Nil }, func(s *UserKeyState) { s.Sequence = 0 }, func(s *UserKeyState) { s.Sequence = math.MaxInt64 + 1 }, func(s *UserKeyState) { s.MinimumEncryptionCertificate = 0 }, func(s *UserKeyState) { s.MinimumSigningCertificate = math.MaxInt64 + 1 }, func(s *UserKeyState) { s.Encryption.ID = s.Signing.ID }, func(s *UserKeyState) { s.Signing.ID = s.Signer.ID }, func(s *UserKeyState) { s.Encryption.ID = s.Signer.ID }, func(s *UserKeyState) { s.Encryption.ID = uuid.Nil }, func(s *UserKeyState) { s.Signing.Version = 0 }, func(s *UserKeyState) { s.Signer.Version = math.MaxInt32 + 1 },
	} {
		changed := state
		mutate(&changed)
		if _, err := SignUserKeyState(changed, org); err == nil {
			t.Fatal("invalid state signed")
		}
		if err := VerifyUserKeyState(changed, trust); err == nil {
			t.Fatal("invalid state verified")
		}
	}
	if _, err := SignUserKeyState(state, nil); err != ErrFormat {
		t.Fatal("missing private signer accepted")
	}
}
