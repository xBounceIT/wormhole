package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// Vector independently computed with Python hashlib/hmac and RFC 5869
// extract/expand, not by calling the Go implementation under test.
func TestInviteDerivationVector(t *testing.T) {
	c := InviteContext{WorkspaceID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), UserID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), InviteID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), KeyID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), KeyVersion: 1, LoginName: "alice"}
	code := make([]byte, 16)
	for i := range code {
		code[i] = byte(i)
	}
	login, err := DeriveInviteLogin(code, c)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(login)
	if hex.EncodeToString(login) != "95d45a82b0553449ace1ffcf4353f00791d60783a17a59d6817f61d2ed6e6d16" {
		t.Fatal("login vector changed")
	}
	_, salt, _ := c.binding()
	unlock, err := deriveInviteKey(code, salt, "wormhole/v1/invite-unlock")
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(unlock)
	if hex.EncodeToString(unlock) != "6aa227a75c1269ef2d1c6ce34fe37376bc7f68d5af0eb54bfb49aba06018880c" {
		t.Fatal("unlock vector changed")
	}
}

func inviteFixture(t *testing.T) ([]byte, InviteContext, *InviteBootstrap, []byte) {
	t.Helper()
	code := bytes.Repeat([]byte{7}, InviteCodeBytes)
	c := InviteContext{WorkspaceID: uuid.New(), UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: "élise"}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)).Public().(ed25519.PublicKey)
	b, err := NewInviteBootstrap(public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Wipe)
	fp := sha256.Sum256(public)
	return code, c, b, fp[:]
}

func TestInviteBootstrapRoundTripAndWipe(t *testing.T) {
	code, c, b, fp := inviteFixture(t)
	envelope, err := SealInviteBootstrap(code, c, b)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenInviteBootstrap(code, c, envelope, fp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.EncryptionPrivate, b.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, b.SigningSeed) || !bytes.Equal(opened.OrganisationPublic, b.OrganisationPublic) {
		t.Fatal("wrong material")
	}
	enc, sign, pub := opened.EncryptionPrivate, opened.SigningSeed, opened.OrganisationPublic
	encoded, _ := json.Marshal(opened)
	if string(encoded) != "{}" {
		t.Fatal("secret JSON serialization")
	}
	opened.Wipe()
	opened.Wipe()
	(*InviteBootstrap)(nil).Wipe()
	if !bytes.Equal(enc, make([]byte, 32)) || !bytes.Equal(sign, make([]byte, 32)) || !bytes.Equal(pub, make([]byte, 32)) || opened.EncryptionPrivate != nil {
		t.Fatal("not wiped")
	}
	if !bytes.Equal(code, bytes.Repeat([]byte{7}, InviteCodeBytes)) || bytes.Equal(b.EncryptionPrivate, make([]byte, 32)) {
		t.Fatal("borrowed input changed")
	}
	other, err := NewInviteBootstrap(b.OrganisationPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Wipe()
	if bytes.Equal(b.EncryptionPrivate, other.EncryptionPrivate) || bytes.Equal(b.SigningSeed, other.SigningSeed) {
		t.Fatal("reused keys")
	}
}

func TestInviteDomainSeparationAndContext(t *testing.T) {
	code, c, b, fp := inviteFixture(t)
	envelope, _ := SealInviteBootstrap(code, c, b)
	login, err := DeriveInviteLogin(code, c)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(login)
	binding, _, _ := c.binding()
	if _, err := Open(login, binding, envelope); err != ErrAuthentication {
		t.Fatal("login key unlocks bootstrap")
	}
	for n, change := range []func(*InviteContext){
		func(c *InviteContext) { c.WorkspaceID = uuid.New() }, func(c *InviteContext) { c.UserID = uuid.New() },
		func(c *InviteContext) { c.InviteID = uuid.New() }, func(c *InviteContext) { c.KeyID = uuid.New() },
		func(c *InviteContext) { c.KeyVersion++ }, func(c *InviteContext) { c.LoginName = "another" },
	} {
		changed := c
		change(&changed)
		key, err := DeriveInviteLogin(code, changed)
		if err != nil || bytes.Equal(login, key) {
			t.Fatalf("context %d not bound", n)
		}
		Wipe(key)
		if got, err := OpenInviteBootstrap(code, changed, envelope, fp); err == nil || got != nil {
			t.Fatalf("context %d accepted", n)
		}
	}
	wrongCode := append([]byte(nil), code...)
	wrongCode[0] ^= 1
	if got, err := OpenInviteBootstrap(wrongCode, c, envelope, fp); err != ErrAuthentication || got != nil {
		t.Fatal("wrong code accepted")
	}
	fp[0] ^= 1
	if got, err := OpenInviteBootstrap(code, c, envelope, fp); err != ErrAuthentication || got != nil {
		t.Fatal("wrong org accepted")
	}
}

func TestInviteInvalidInputs(t *testing.T) {
	code, c, b, fp := inviteFixture(t)
	envelope, _ := SealInviteBootstrap(code, c, b)
	for _, change := range []func(*InviteContext){func(c *InviteContext) { c.WorkspaceID = uuid.Nil }, func(c *InviteContext) { c.UserID = uuid.Nil }, func(c *InviteContext) { c.InviteID = uuid.Nil }, func(c *InviteContext) { c.KeyID = uuid.Nil }, func(c *InviteContext) { c.KeyVersion = 0 }, func(c *InviteContext) { c.LoginName = "ELISE" }} {
		bad := c
		change(&bad)
		if _, err := DeriveInviteLogin(code, bad); err != ErrFormat {
			t.Fatal("invalid context login")
		}
		if _, err := SealInviteBootstrap(code, bad, b); err != ErrFormat {
			t.Fatal("invalid context seal")
		}
		if _, err := OpenInviteBootstrap(code, bad, envelope, fp); err != ErrFormat {
			t.Fatal("invalid context open")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 15), make([]byte, 17), make([]byte, 32)} {
		if _, err := DeriveInviteLogin(bad, c); err != ErrFormat {
			t.Fatal("invalid code login")
		}
		if _, err := SealInviteBootstrap(bad, c, b); err != ErrFormat {
			t.Fatal("invalid code seal")
		}
		if _, err := OpenInviteBootstrap(bad, c, envelope, fp); err != ErrFormat {
			t.Fatal("invalid code open")
		}
	}
	if _, err := NewInviteBootstrap(nil); err != ErrFormat {
		t.Fatal("invalid org")
	}
	for _, bad := range []*InviteBootstrap{nil, {}, {EncryptionPrivate: make([]byte, 32)}, {EncryptionPrivate: make([]byte, 32), SigningSeed: make([]byte, 32)}} {
		if _, err := SealInviteBootstrap(code, c, bad); err != ErrFormat {
			t.Fatal("invalid material")
		}
	}
	if _, err := OpenInviteBootstrap(code, c, envelope, nil); err != ErrFormat {
		t.Fatal("missing fingerprint")
	}
	if _, err := OpenInviteBootstrap(code, c, Envelope{}, fp); err != ErrFormat {
		t.Fatal("missing envelope")
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := OpenInviteBootstrap(code, c, envelope, fp); err != ErrAuthentication {
		t.Fatal("tamper accepted")
	}
	// Correct AEAD with unsupported inner format must still fail closed.
	binding, salt, _ := c.binding()
	key, _ := deriveInviteKey(code, salt, "wormhole/v1/invite-unlock")
	defer Wipe(key)
	bad, _ := Seal(key, binding, make([]byte, inviteBootstrapBytes))
	if _, err := OpenInviteBootstrap(code, c, bad, fp); err != ErrFormat {
		t.Fatal("bad inner version")
	}
}
