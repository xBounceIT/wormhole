package vault

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"testing"

	"github.com/google/uuid"
)

func userCertificateFixture(t *testing.T) ([]byte, UserKeyBinding, *UserKeys, Envelope, ed25519.PrivateKey, UserKeyCertificate, UserKeyCertificate) {
	t.Helper()
	master, binding, keys, public := userWrapFixture(t)
	envelope, err := SealUserKeys(master, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	organisation := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	t.Cleanup(func() { Wipe(organisation) })
	signer := KeyRef{ID: uuid.New(), Version: 1}
	enc := UserKeyCertificate{FormatVersion: FormatVersion, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: binding.Encryption, Kind: "user-enc", Suite: SuiteX25519HKDFSHA256AES256GCM, PublicKey: public.Encryption, Revision: 3, Signer: signer}
	sign := enc
	sign.Key = binding.Signing
	sign.Kind = "user-sign"
	sign.Suite = 1
	sign.PublicKey = public.Signing
	enc, err = SignUserKeyCertificate(enc, organisation)
	if err != nil {
		t.Fatal(err)
	}
	sign, err = SignUserKeyCertificate(sign, organisation)
	if err != nil {
		t.Fatal(err)
	}
	return master, binding, keys, envelope, organisation, enc, sign
}

func TestCertifiedUserKeys(t *testing.T) {
	master, binding, keys, envelope, org, enc, sign := userCertificateFixture(t)
	public := org.Public().(ed25519.PublicKey)
	opened, err := OpenCertifiedUserKeys(master, binding, envelope, enc, sign, enc.Signer, public, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("certified private keys changed")
	}
	opened.Wipe()
	for _, test := range []struct {
		enc, sign           UserKeyCertificate
		encFloor, signFloor uint64
		want                error
	}{
		{enc, sign, 4, 3, ErrRollback}, {enc, sign, 3, 4, ErrRollback}, {sign, enc, 3, 3, ErrAuthentication},
	} {
		value, err := OpenCertifiedUserKeys(master, binding, envelope, test.enc, test.sign, enc.Signer, public, test.encFloor, test.signFloor)
		if value != nil || err != test.want {
			t.Fatalf("invalid certificate set: %v", err)
		}
	}
	badSign := sign
	badSign.Signature = nil
	if value, err := OpenCertifiedUserKeys(master, binding, envelope, enc, badSign, enc.Signer, public, 3, 3); value != nil || err != ErrAuthentication {
		t.Fatal("unsigned signing key accepted")
	}
	if value, err := OpenCertifiedUserKeys(make([]byte, 32), binding, envelope, enc, sign, enc.Signer, public, 3, 3); value != nil || err != ErrAuthentication {
		t.Fatal("wrong master accepted")
	}
	// An authentic certificate for a different public key still cannot open this
	// private capsule; organisation signature alone is insufficient.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	defer Wipe(other)
	changed := sign
	changed.PublicKey = other.Public().(ed25519.PublicKey)
	changed, err = SignUserKeyCertificate(changed, org)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := OpenCertifiedUserKeys(master, binding, envelope, enc, changed, enc.Signer, public, 3, 3); value != nil || err != ErrAuthentication {
		t.Fatal("mismatched certified public key accepted")
	}
}

func TestUserCertificateBindingAndSignature(t *testing.T) {
	_, _, _, _, org, enc, sign := userCertificateFixture(t)
	for _, original := range []UserKeyCertificate{enc, sign} {
		verify := func(c UserKeyCertificate) error {
			return VerifyUserKeyCertificate(c, original.WorkspaceID, original.UserID, original.Key, original.Kind, original.Signer, org.Public().(ed25519.PublicKey), 3)
		}
		if err := verify(original); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*UserKeyCertificate){
			func(c *UserKeyCertificate) { c.WorkspaceID = uuid.New() }, func(c *UserKeyCertificate) { c.UserID = uuid.New() }, func(c *UserKeyCertificate) { c.Key.ID = uuid.New() }, func(c *UserKeyCertificate) { c.Key.Version++ }, func(c *UserKeyCertificate) { c.Signer.ID = uuid.New() }, func(c *UserKeyCertificate) { c.Signer.Version++ }, func(c *UserKeyCertificate) { c.Revision++ }, func(c *UserKeyCertificate) { c.PublicKey = bytes.Repeat([]byte{19}, 32) }, func(c *UserKeyCertificate) { c.Signature = nil },
		} {
			changed := original
			mutate(&changed)
			if err := verify(changed); err == nil {
				t.Fatal("certificate mutation accepted")
			}
		}
		if err := VerifyUserKeyCertificate(original, original.WorkspaceID, original.UserID, original.Key, original.Kind, original.Signer, nil, 3); err != ErrAuthentication {
			t.Fatal("missing organisation pin accepted")
		}
		wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, 32))
		defer Wipe(wrong)
		if err := VerifyUserKeyCertificate(original, original.WorkspaceID, original.UserID, original.Key, original.Kind, original.Signer, wrong.Public().(ed25519.PublicKey), 3); err != ErrAuthentication {
			t.Fatal("substituted organisation key accepted")
		}
	}
	original := enc
	original.PublicKey = bytes.Clone(enc.PublicKey)
	signed, err := SignUserKeyCertificate(original, org)
	if err != nil {
		t.Fatal(err)
	}
	original.PublicKey[0] ^= 1
	if bytes.Equal(original.PublicKey, signed.PublicKey) {
		t.Fatal("signed key aliases caller buffer")
	}
}

func TestUserCertificateFormat(t *testing.T) {
	_, _, _, _, org, enc, sign := userCertificateFixture(t)
	for _, mutate := range []func(*UserKeyCertificate){
		func(c *UserKeyCertificate) { c.FormatVersion = 0 }, func(c *UserKeyCertificate) { c.FormatVersion = 2 }, func(c *UserKeyCertificate) { c.WorkspaceID = uuid.Nil }, func(c *UserKeyCertificate) { c.UserID = uuid.Nil }, func(c *UserKeyCertificate) { c.Key.ID = uuid.Nil }, func(c *UserKeyCertificate) { c.Signer.ID = uuid.Nil }, func(c *UserKeyCertificate) { c.Signer.ID = c.Key.ID }, func(c *UserKeyCertificate) { c.Key.Version = 0 }, func(c *UserKeyCertificate) { c.Key.Version = math.MaxInt32 + 1 }, func(c *UserKeyCertificate) { c.Signer.Version = 0 }, func(c *UserKeyCertificate) { c.Signer.Version = math.MaxInt32 + 1 }, func(c *UserKeyCertificate) { c.Revision = 0 }, func(c *UserKeyCertificate) { c.Revision = math.MaxInt64 + 1 }, func(c *UserKeyCertificate) { c.Kind = "org-sign" }, func(c *UserKeyCertificate) { c.Suite = 99 }, func(c *UserKeyCertificate) { c.PublicKey = nil }, func(c *UserKeyCertificate) { c.PublicKey = make([]byte, 32) },
	} {
		c := enc
		mutate(&c)
		if _, err := SignUserKeyCertificate(c, org); err == nil {
			t.Fatal("invalid certificate signed")
		}
		if err := VerifyUserKeyCertificate(c, enc.WorkspaceID, enc.UserID, enc.Key, enc.Kind, enc.Signer, org.Public().(ed25519.PublicKey), 0); err == nil {
			t.Fatal("invalid certificate verified")
		}
	}
	for _, c := range []UserKeyCertificate{func() UserKeyCertificate { c := sign; c.Suite = 2; return c }(), func() UserKeyCertificate { c := sign; c.PublicKey = nil; return c }()} {
		if _, err := SignUserKeyCertificate(c, org); err != ErrFormat {
			t.Fatal("invalid signing key accepted")
		}
	}
	if _, err := SignUserKeyCertificate(enc, nil); err != ErrFormat {
		t.Fatal("missing signer private key accepted")
	}
}
