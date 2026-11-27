package vault

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"testing"

	"github.com/google/uuid"
)

func keyCopyFixture(t *testing.T) ([]byte, KeyCopyBinding, *InviteBootstrap, ed25519.PublicKey) {
	t.Helper()
	_, _, holder, _ := inviteFixture(t)
	b := KeyCopyBinding{WorkspaceID: uuid.New(), Key: KeyRef{uuid.New(), 1}, Holder: KeyRef{uuid.New(), 1}, Issuer: KeyRef{uuid.New(), 1}}
	signer := ed25519.NewKeyFromSeed(holder.SigningSeed)
	defer Wipe(signer)
	return bytes.Repeat([]byte{23}, 32), b, holder, signer.Public().(ed25519.PublicKey)
}

func TestKeyCopyRoundTripAndInviteRewrap(t *testing.T) {
	key, b, bootstrap, issuer := keyCopyFixture(t)
	oldPublic, _ := (&UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	copy, err := SealKeyCopy(key, b, oldPublic.Encryption, bootstrap.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenKeyCopy(bootstrap.EncryptionPrivate, b, copy, issuer)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("open: %v", err)
	}
	Wipe(opened)
	c := InviteContext{WorkspaceID: b.WorkspaceID, UserID: uuid.New(), InviteID: uuid.New(), KeyID: b.Holder.ID, KeyVersion: 1, LoginName: "alice"}
	next, proof, err := PrepareInviteRekey(c, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Wipe()
	if err := VerifyInviteRekey(c, proof, oldPublic); err != nil {
		t.Fatal(err)
	}
	nextHolder := KeyRef{proof.EncryptionKeyID, proof.KeyVersion}
	nextIssuer := KeyRef{proof.SigningKeyID, proof.KeyVersion}
	rewrapped, err := RewrapKeyCopy(bootstrap.EncryptionPrivate, b, copy, issuer, nextHolder, proof.Public.Encryption, nextIssuer, next.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	nextBinding := b
	nextBinding.Holder, nextBinding.Issuer = nextHolder, nextIssuer
	opened, err = OpenKeyCopy(next.EncryptionPrivate, nextBinding, rewrapped, proof.Public.Signing)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("rewrap: %v", err)
	}
	Wipe(opened)
	if got, err := OpenKeyCopy(bootstrap.EncryptionPrivate, nextBinding, rewrapped, proof.Public.Signing); err != ErrAuthentication || got != nil {
		t.Fatal("old key opens replacement")
	}
	if got, err := OpenKeyCopy(next.EncryptionPrivate, b, copy, issuer); err != ErrAuthentication || got != nil {
		t.Fatal("new key opens old copy")
	}
	if bytes.Equal(copy.Envelope.Ciphertext, rewrapped.Envelope.Ciphertext) {
		t.Fatal("ciphertext not replaced")
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{23}, 32)) || len(bootstrap.EncryptionPrivate) != 32 {
		t.Fatal("borrowed inputs modified")
	}
}

func TestKeyCopyBindsEveryCoordinate(t *testing.T) {
	key, b, holder, issuer := keyCopyFixture(t)
	pub, _ := (&UserKeys{EncryptionPrivate: holder.EncryptionPrivate, SigningSeed: holder.SigningSeed}).Public()
	copy, _ := SealKeyCopy(key, b, pub.Encryption, holder.SigningSeed)
	wrongIssuer := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer Wipe(wrongIssuer)
	if got, err := OpenKeyCopy(holder.EncryptionPrivate, b, copy, wrongIssuer.Public().(ed25519.PublicKey)); err != ErrAuthentication || got != nil {
		t.Fatal("wrong issuer accepted")
	}
	for _, change := range []func(*KeyCopyBinding){func(b *KeyCopyBinding) { b.WorkspaceID = uuid.New() }, func(b *KeyCopyBinding) { b.Key.ID = uuid.New() }, func(b *KeyCopyBinding) { b.Key.Version++ }, func(b *KeyCopyBinding) { b.Holder.ID = uuid.New() }, func(b *KeyCopyBinding) { b.Holder.Version++ }, func(b *KeyCopyBinding) { b.Issuer.ID = uuid.New() }, func(b *KeyCopyBinding) { b.Issuer.Version++ }} {
		bad := b
		change(&bad)
		if got, err := OpenKeyCopy(holder.EncryptionPrivate, bad, copy, issuer); err != ErrAuthentication || got != nil {
			t.Fatal("coordinate substitution accepted")
		}
		// Even a fresh signature over changed metadata cannot move the HPKE context.
		info, _ := bad.info()
		raw, _ := keyCopySigningBytes(info, copy)
		priv := ed25519.NewKeyFromSeed(holder.SigningSeed)
		changed := copy
		changed.Signature = ed25519.Sign(priv, raw)
		Wipe(priv)
		if got, err := OpenKeyCopy(holder.EncryptionPrivate, bad, changed, issuer); err != ErrAuthentication || got != nil {
			t.Fatal("HPKE context not bound")
		}
	}
}

func TestKeyCopyRejectsInvalidMetadataAndMaterial(t *testing.T) {
	key, b, holder, issuer := keyCopyFixture(t)
	pub, _ := (&UserKeys{EncryptionPrivate: holder.EncryptionPrivate, SigningSeed: holder.SigningSeed}).Public()
	copy, _ := SealKeyCopy(key, b, pub.Encryption, holder.SigningSeed)
	for _, change := range []func(*KeyCopyBinding){func(b *KeyCopyBinding) { b.WorkspaceID = uuid.Nil }, func(b *KeyCopyBinding) { b.Key.ID = uuid.Nil }, func(b *KeyCopyBinding) { b.Holder.ID = uuid.Nil }, func(b *KeyCopyBinding) { b.Issuer.ID = uuid.Nil }, func(b *KeyCopyBinding) { b.Key.Version = 0 }, func(b *KeyCopyBinding) { b.Holder.Version = 0 }, func(b *KeyCopyBinding) { b.Issuer.Version = 0 }, func(b *KeyCopyBinding) { b.Holder = b.Key }, func(b *KeyCopyBinding) { b.Key.Version = math.MaxInt32 + 1 }, func(b *KeyCopyBinding) { b.Holder.Version = math.MaxInt32 + 1 }, func(b *KeyCopyBinding) { b.Issuer.Version = math.MaxInt32 + 1 }} {
		bad := b
		change(&bad)
		if _, err := SealKeyCopy(key, bad, pub.Encryption, holder.SigningSeed); err != ErrFormat {
			t.Fatal("bad seal binding")
		}
		if got, err := OpenKeyCopy(holder.EncryptionPrivate, bad, copy, issuer); err != ErrFormat || got != nil {
			t.Fatal("bad open binding")
		}
	}
	if _, err := SealKeyCopy(nil, b, pub.Encryption, holder.SigningSeed); err != ErrFormat {
		t.Fatal("empty key")
	}
	if _, err := SealKeyCopy(key, b, pub.Encryption, nil); err != ErrFormat {
		t.Fatal("missing signer")
	}
	if _, err := SealKeyCopy(key, b, nil, holder.SigningSeed); err != ErrFormat {
		t.Fatal("missing recipient")
	}
	if _, err := SealKeyCopy(key, b, make([]byte, 32), holder.SigningSeed); err == nil {
		t.Fatal("low-order recipient")
	}
	if _, err := OpenKeyCopy(nil, b, copy, issuer); err != ErrFormat {
		t.Fatal("missing private")
	}
	if _, err := OpenKeyCopy(holder.EncryptionPrivate, b, copy, nil); err != ErrFormat {
		t.Fatal("missing issuer")
	}
	bad := copy
	bad.Signature = nil
	if _, err := OpenKeyCopy(holder.EncryptionPrivate, b, bad, issuer); err != ErrFormat {
		t.Fatal("missing signature")
	}
	for _, change := range []func(*SignedKeyCopy){func(c *SignedKeyCopy) { c.Envelope.Ciphertext = nil }, func(c *SignedKeyCopy) { c.Envelope.Ciphertext = make([]byte, 49) }, func(c *SignedKeyCopy) { c.Envelope.Enc = nil }, func(c *SignedKeyCopy) { c.Envelope.SuiteID = 99 }} {
		bad := copy
		change(&bad)
		if got, err := OpenKeyCopy(holder.EncryptionPrivate, b, bad, issuer); err != ErrFormat || got != nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	bad = copy
	bad.Envelope.FormatVersion++
	if _, err := OpenKeyCopy(holder.EncryptionPrivate, b, bad, issuer); err != ErrNewerFormat {
		t.Fatal("newer format accepted")
	}
	bad = copy
	bad.Envelope.Ciphertext = append([]byte(nil), copy.Envelope.Ciphertext...)
	bad.Envelope.Ciphertext[0] ^= 1
	if _, err := OpenKeyCopy(holder.EncryptionPrivate, b, bad, issuer); err != ErrAuthentication {
		t.Fatal("tamper accepted")
	}
	if _, err := RewrapKeyCopy(holder.EncryptionPrivate, b, copy, issuer, b.Holder, pub.Encryption, b.Issuer, holder.SigningSeed); err != ErrFormat {
		t.Fatal("same holder accepted")
	}
	newHolder := KeyRef{uuid.New(), 1}
	if _, err := RewrapKeyCopy(nil, b, copy, issuer, newHolder, pub.Encryption, b.Issuer, holder.SigningSeed); err != ErrFormat {
		t.Fatal("invalid rewrap source")
	}
	if _, err := RewrapKeyCopy(holder.EncryptionPrivate, b, copy, issuer, newHolder, nil, b.Issuer, holder.SigningSeed); err != ErrFormat {
		t.Fatal("invalid rewrap target")
	}
}
