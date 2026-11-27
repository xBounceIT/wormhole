package vault

import (
	"bytes"
	"math"
	"testing"

	"github.com/google/uuid"
)

func userWrapFixture(t *testing.T) ([]byte, UserKeyBinding, *UserKeys, UserPublicKeys) {
	t.Helper()
	_, c, bootstrap, _ := inviteFixture(t)
	keys, proof, err := PrepareInviteRekey(c, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Wipe)
	b := UserKeyBinding{WorkspaceID: c.WorkspaceID, UserID: c.UserID, Encryption: KeyRef{proof.EncryptionKeyID, 1}, Signing: KeyRef{proof.SigningKeyID, 1}, Revision: 1}
	return bytes.Repeat([]byte{17}, 32), b, keys, proof.Public
}

func TestUserKeysWrapAndPasswordChange(t *testing.T) {
	master, b, keys, pub := userWrapFixture(t)
	envelope, err := SealUserKeys(master, b, keys)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenUserKeys(master, b, envelope, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("private keys changed")
	}
	opened.Wipe()
	nextMaster := bytes.Repeat([]byte{18}, 32)
	next, nextEnvelope, err := RewrapUserKeys(master, nextMaster, b, envelope, pub)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != 2 || next.WorkspaceID != b.WorkspaceID || next.UserID != b.UserID || next.Encryption != b.Encryption || next.Signing != b.Signing {
		t.Fatal("password change rotated key identity")
	}
	opened, err = OpenUserKeys(nextMaster, next, nextEnvelope, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("password change rotated private keys")
	}
	opened.Wipe()
	if k, err := OpenUserKeys(master, next, nextEnvelope, pub); err != ErrAuthentication || k != nil {
		t.Fatal("old master opens replacement")
	}
	if k, err := OpenUserKeys(nextMaster, b, nextEnvelope, pub); err == nil || k != nil {
		t.Fatal("stale revision accepted")
	}
	if k, err := OpenUserKeys(nextMaster, b, envelope, pub); err != ErrAuthentication || k != nil {
		t.Fatal("new master opens old envelope")
	}
	if !bytes.Equal(master, bytes.Repeat([]byte{17}, 32)) || !bytes.Equal(nextMaster, bytes.Repeat([]byte{18}, 32)) {
		t.Fatal("borrowed master mutated")
	}
}

func TestUserKeysWrapContextAndPublicKeys(t *testing.T) {
	master, b, keys, pub := userWrapFixture(t)
	envelope, _ := SealUserKeys(master, b, keys)
	for _, change := range []func(*UserKeyBinding){func(b *UserKeyBinding) { b.WorkspaceID = uuid.New() }, func(b *UserKeyBinding) { b.UserID = uuid.New() }, func(b *UserKeyBinding) { b.Encryption.ID = uuid.New() }, func(b *UserKeyBinding) { b.Encryption.Version++ }, func(b *UserKeyBinding) { b.Signing.ID = uuid.New() }, func(b *UserKeyBinding) { b.Signing.Version++ }, func(b *UserKeyBinding) { b.Revision++ }} {
		bad := b
		change(&bad)
		if k, err := OpenUserKeys(master, bad, envelope, pub); err == nil || k != nil {
			t.Fatal("context substitution accepted")
		}
	}
	_, _, _, other := userWrapFixture(t)
	for _, wrong := range []UserPublicKeys{{Encryption: other.Encryption, Signing: pub.Signing}, {Encryption: pub.Encryption, Signing: other.Signing}} {
		if k, err := OpenUserKeys(master, b, envelope, wrong); err != ErrAuthentication || k != nil {
			t.Fatal("uncertified private keys returned")
		}
	}
	// Login and unlock material remain purpose-separated even for identical salt.
	binding, salt, _ := b.binding()
	login, _ := DeriveKey(master, salt, PurposeLogin)
	defer Wipe(login)
	if _, err := Open(login, binding, envelope); err != ErrAuthentication {
		t.Fatal("login key opens user keys")
	}
}

func TestUserKeysWrapRejectsInvalidInput(t *testing.T) {
	master, b, keys, pub := userWrapFixture(t)
	envelope, _ := SealUserKeys(master, b, keys)
	for _, change := range []func(*UserKeyBinding){func(b *UserKeyBinding) { b.WorkspaceID = uuid.Nil }, func(b *UserKeyBinding) { b.UserID = uuid.Nil }, func(b *UserKeyBinding) { b.Encryption.ID = uuid.Nil }, func(b *UserKeyBinding) { b.Signing.ID = uuid.Nil }, func(b *UserKeyBinding) { b.Signing.ID = b.Encryption.ID }, func(b *UserKeyBinding) { b.Encryption.Version = 0 }, func(b *UserKeyBinding) { b.Signing.Version = 0 }, func(b *UserKeyBinding) { b.Encryption.Version = math.MaxUint32 }, func(b *UserKeyBinding) { b.Signing.Version = math.MaxUint32 }, func(b *UserKeyBinding) { b.Revision = 0 }, func(b *UserKeyBinding) { b.Revision = math.MaxUint64 }} {
		bad := b
		change(&bad)
		if _, err := SealUserKeys(master, bad, keys); err != ErrFormat {
			t.Fatal("invalid binding sealed")
		}
		if k, err := OpenUserKeys(master, bad, envelope, pub); err != ErrFormat || k != nil {
			t.Fatal("invalid binding opened")
		}
	}
	for _, bad := range []*UserKeys{nil, {}, {EncryptionPrivate: make([]byte, 32)}} {
		if _, err := SealUserKeys(master, b, bad); err != ErrFormat {
			t.Fatal("invalid private material sealed")
		}
	}
	if _, err := SealUserKeys(nil, b, keys); err != ErrFormat {
		t.Fatal("missing master")
	}
	if k, err := OpenUserKeys(nil, b, envelope, pub); err != ErrFormat || k != nil {
		t.Fatal("missing opening master")
	}
	if k, err := OpenUserKeys(master, b, Envelope{}, pub); err != ErrFormat || k != nil {
		t.Fatal("empty envelope")
	}
	if k, err := OpenUserKeys(master, b, envelope, UserPublicKeys{}); err != ErrFormat || k != nil {
		t.Fatal("empty expected keys")
	}
	if k, err := OpenUserKeys(master, b, envelope, UserPublicKeys{Encryption: make([]byte, 32), Signing: pub.Signing}); err != ErrFormat || k != nil {
		t.Fatal("low-order expected key")
	}
	badEnvelope := envelope
	badEnvelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	badEnvelope.Ciphertext[0] ^= 1
	if k, err := OpenUserKeys(master, b, badEnvelope, pub); err != ErrAuthentication || k != nil {
		t.Fatal("tamper accepted")
	}
	binding, salt, _ := b.binding()
	unlock, _ := DeriveKey(master, salt, PurposeUnlock)
	defer Wipe(unlock)
	badEnvelope, _ = Seal(unlock, binding, make([]byte, userKeyPlaintextBytes))
	if k, err := OpenUserKeys(master, b, badEnvelope, pub); err != ErrFormat || k != nil {
		t.Fatal("invalid inner format")
	}
	max := b
	max.Revision = math.MaxInt64
	maxEnvelope, err := SealUserKeys(master, max, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		old, new []byte
		binding  UserKeyBinding
		envelope Envelope
	}{{nil, master, b, envelope}, {master, nil, b, envelope}, {master, master, max, maxEnvelope}, {master, master, b, badEnvelope}} {
		got, wrapped, err := RewrapUserKeys(tc.old, tc.new, tc.binding, tc.envelope, pub)
		if err == nil || got != (UserKeyBinding{}) || len(wrapped.Ciphertext) != 0 {
			t.Fatal("failed rewrap exposed partial result")
		}
	}
}
