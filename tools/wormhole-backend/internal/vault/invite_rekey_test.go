package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestInviteRekeyFreshKeysAndProof(t *testing.T) {
	_, c, b, _ := inviteFixture(t)
	old, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	k, p, err := PrepareInviteRekey(c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	if err := VerifyInviteRekey(c, p, old); err != nil {
		t.Fatal(err)
	}
	pub, _ := k.Public()
	if !bytes.Equal(pub.Encryption, p.Public.Encryption) || !bytes.Equal(pub.Signing, p.Public.Signing) {
		t.Fatal("proof does not match returned keys")
	}
	if bytes.Equal(pub.Encryption, old.Encryption) || bytes.Equal(pub.Signing, old.Signing) || p.EncryptionKeyID == c.KeyID {
		t.Fatal("bootstrap key reused")
	}
	k2, p2, err := PrepareInviteRekey(c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer k2.Wipe()
	if p2.EncryptionKeyID == p.EncryptionKeyID || bytes.Equal(p2.Public.Encryption, p.Public.Encryption) || bytes.Equal(p2.Public.Signing, p.Public.Signing) {
		t.Fatal("rekey generation reused keys")
	}
	raw, _ := json.Marshal(k)
	if string(raw) != "{}" {
		t.Fatal("private JSON exposed")
	}
	enc, sign := k.EncryptionPrivate, k.SigningSeed
	k.Wipe()
	k.Wipe()
	(*UserKeys)(nil).Wipe()
	if !bytes.Equal(enc, make([]byte, 32)) || !bytes.Equal(sign, make([]byte, 32)) {
		t.Fatal("keys not wiped")
	}
	if _, err := k.Public(); err != ErrFormat {
		t.Fatal("retired keys accepted")
	}
	if len(b.SigningSeed) != 32 {
		t.Fatal("bootstrap retired before key copy rewrap")
	}
}

func TestInviteRekeyRejectsTamperAndReplay(t *testing.T) {
	_, c, b, _ := inviteFixture(t)
	old, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	k, p, err := PrepareInviteRekey(c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	for _, mutate := range []func(*InviteRekeyProof){
		func(p *InviteRekeyProof) { p.FormatVersion = 2 }, func(p *InviteRekeyProof) { p.EncryptionKeyID = uuid.Nil }, func(p *InviteRekeyProof) { p.EncryptionKeyID = c.KeyID }, func(p *InviteRekeyProof) { p.KeyVersion = 2 },
		func(p *InviteRekeyProof) { p.SigningKeyID = uuid.Nil }, func(p *InviteRekeyProof) { p.SigningKeyID = p.EncryptionKeyID }, func(p *InviteRekeyProof) { p.SigningKeyID = c.KeyID }, func(p *InviteRekeyProof) { p.SigningKeyID = uuid.New() },
		func(p *InviteRekeyProof) { p.EncryptionKeyID = uuid.New() }, func(p *InviteRekeyProof) { p.Public.Encryption = old.Encryption }, func(p *InviteRekeyProof) { p.Public.Signing = old.Signing }, func(p *InviteRekeyProof) { p.Signature = nil }, func(p *InviteRekeyProof) { p.Public.Signing = nil }, func(p *InviteRekeyProof) { p.Public.Encryption = nil },
	} {
		bad := p
		mutate(&bad)
		if VerifyInviteRekey(c, bad, old) == nil {
			t.Fatal("tampered proof accepted")
		}
	}
	for _, mutate := range []func(*InviteContext){func(c *InviteContext) { c.WorkspaceID = uuid.New() }, func(c *InviteContext) { c.UserID = uuid.New() }, func(c *InviteContext) { c.InviteID = uuid.New() }, func(c *InviteContext) { c.KeyID = uuid.New() }, func(c *InviteContext) { c.KeyVersion++ }, func(c *InviteContext) { c.LoginName = "someone" }, func(c *InviteContext) { c.UserID = uuid.Nil }} {
		bad := c
		mutate(&bad)
		if VerifyInviteRekey(bad, p, old) == nil {
			t.Fatal("replayed context accepted")
		}
	}
	if VerifyInviteRekey(c, p, UserPublicKeys{}) != ErrFormat {
		t.Fatal("missing bootstrap accepted")
	}
	wrong := UserPublicKeys{Encryption: old.Encryption, Signing: p.Public.Signing}
	if VerifyInviteRekey(c, p, wrong) != ErrAuthentication {
		t.Fatal("untrusted signer accepted")
	}
	// An authentic bootstrap signature still cannot certify its own old keys.
	signer := ed25519.NewKeyFromSeed(b.SigningSeed)
	defer Wipe(signer)
	for _, reuse := range []UserPublicKeys{{Encryption: old.Encryption, Signing: p.Public.Signing}, {Encryption: p.Public.Encryption, Signing: old.Signing}} {
		bad := p
		bad.Public = reuse
		raw, err := bad.signingBytes(c)
		if err != nil {
			t.Fatal(err)
		}
		bad.Signature = ed25519.Sign(signer, raw)
		if VerifyInviteRekey(c, bad, old) != ErrAuthentication {
			t.Fatal("signed reused key accepted")
		}
	}
}

func TestInviteRekeyRejectsInvalidKeyMaterial(t *testing.T) {
	_, c, b, _ := inviteFixture(t)
	for _, bad := range []*InviteBootstrap{nil, {}, {EncryptionPrivate: make([]byte, 32)}} {
		if k, _, err := PrepareInviteRekey(c, bad); err != ErrFormat || k != nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	if _, err := (*UserKeys)(nil).Public(); err != ErrFormat {
		t.Fatal("nil keys accepted")
	}
	badContext := c
	badContext.KeyVersion = 0
	if k, _, err := PrepareInviteRekey(badContext, b); err != ErrFormat || k != nil {
		t.Fatal("invalid context accepted")
	}
	k, p, err := PrepareInviteRekey(c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	old, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	alias := append([]byte(nil), old.Encryption...)
	alias[31] |= 128
	prime := bytes.Repeat([]byte{255}, 32)
	prime[0] = 237
	prime[31] = 127
	above := append([]byte(nil), prime...)
	above[0]++
	for _, invalid := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...), alias, prime, above} {
		bad := p
		bad.Public.Encryption = invalid
		if VerifyInviteRekey(c, bad, old) != ErrFormat {
			t.Fatal("invalid/aliased X25519 accepted")
		}
	}
}
