package sharedpg

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestInvitationPrepareRewrapAuthenticatesCompleteGraph(t *testing.T) {
	i, org, now := invitationFixture(t)
	c := vault.InviteContext{WorkspaceID: i.WorkspaceID, UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: i.LoginName}
	bootstrap, err := vault.NewInviteBootstrap(org)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Wipe()
	public, err := (&vault.UserKeys{EncryptionPrivate: bootstrap.EncryptionPrivate, SigningSeed: bootstrap.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, vault.InviteCodeBytes)
	envelope, err := vault.SealInviteBootstrap(code, c, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.KeyCopyBinding{WorkspaceID: c.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: vault.KeyRef{ID: c.KeyID, Version: 1}, Issuer: vault.KeyRef{ID: uuid.New(), Version: 1}}
	copy, err := vault.SealKeyCopy(make([]byte, 32), binding, public.Encryption, bootstrap.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: c, Revision: 1, ExpiresAt: i.ExpiresAt, Bootstrap: public, Copies: []vault.KeyCopyBinding{binding}, Issuers: []vault.InviteIssuer{{Key: binding.Issuer, Public: public.Signing}}}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	copies := []vault.SignedKeyCopy{copy}
	p, err := i.PrepareRewrap(context.Background(), code, envelope, manifest, copies, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	p.Wipe()
	if p, err := i.PrepareRewrap(nil, code, envelope, manifest, copies, 1, now); err != ErrInvitation || p != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := i.PrepareRewrap(ctx, code, envelope, manifest, copies, 1, now); err != context.Canceled || p != nil {
		t.Fatal("canceled join accepted")
	}
	code[0] ^= 1
	if p, err := i.PrepareRewrap(context.Background(), code, envelope, manifest, copies, 1, now); err != ErrInvitation || p != nil {
		t.Fatal("wrong code accepted")
	}
	code[0] ^= 1
	manifest.Signature = make([]byte, 64)
	if p, err := i.PrepareRewrap(context.Background(), code, envelope, manifest, copies, 1, now); err != vault.ErrAuthentication || p != nil {
		t.Fatal("wrong manifest accepted")
	}
}

func invitationFixture(t *testing.T) (Invitation, ed25519.PublicKey, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fp := sha256.Sum256(key)
	now := time.Unix(1800000000, 0)
	return Invitation{FormatVersion: 1, WorkspaceID: uuid.MustParse("11111111-2222-4333-8444-555555555555"), LoginName: "élise", Endpoints: []Endpoint{{Host: "db.example.com", Port: 5432}}, Database: "wormhole", TLS: TLSVerified, CAPEM: testCA(t), OrganisationFingerprint: fp[:], ExpiresAt: now.Add(time.Hour).Unix()}, key, now
}

func TestInvitationOpenBootstrap(t *testing.T) {
	i, org, now := invitationFixture(t)
	c := vault.InviteContext{WorkspaceID: i.WorkspaceID, UserID: uuid.New(), InviteID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1, LoginName: i.LoginName}
	code := make([]byte, vault.InviteCodeBytes)
	b, err := vault.NewInviteBootstrap(org)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()
	envelope, err := vault.SealInviteBootstrap(code, c, b)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := i.OpenBootstrap(code, c, envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	opened.Wipe()
	if got, err := i.OpenBootstrap(code, c, envelope, time.Unix(i.ExpiresAt, 0)); err != ErrInvitation || got != nil {
		t.Fatal("expired bootstrap accepted")
	}
	for _, change := range []func(*vault.InviteContext){func(c *vault.InviteContext) { c.WorkspaceID = uuid.New() }, func(c *vault.InviteContext) { c.LoginName = "other" }} {
		bad := c
		change(&bad)
		if got, err := i.OpenBootstrap(code, bad, envelope, now); err != ErrInvitation || got != nil {
			t.Fatal("mismatched invitation accepted")
		}
	}
	code[0] ^= 1
	if got, err := i.OpenBootstrap(code, c, envelope, now); err != ErrInvitation || got != nil {
		t.Fatal("wrong code accepted")
	}
	code[0] ^= 1
	i.OrganisationFingerprint[0] ^= 1
	if got, err := i.OpenBootstrap(code, c, envelope, now); err != ErrInvitation || got != nil {
		t.Fatal("wrong organisation accepted")
	}
}

func invitationToken(raw []byte) string {
	payload := invitationPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(payload))
	return payload + "." + hex.EncodeToString(sum[:])
}

func TestInvitationRoundTrip(t *testing.T) {
	i, key, now := invitationFixture(t)
	t.Setenv("PGSERVICE", "must-not-be-read")
	token, err := EncodeInvitation(i, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInvitation("\r\n"+token, now)
	if err != nil || !reflect.DeepEqual(decoded, i) {
		t.Fatalf("roundtrip: %v", err)
	}
	if decoded.CheckOrganisationKey(key, now) != nil {
		t.Fatal("key rejected")
	}
	key[0] ^= 1
	if decoded.CheckOrganisationKey(key, now) != ErrInvitation {
		t.Fatal("wrong key accepted")
	}
	if decoded.CheckOrganisationKey(nil, now) != ErrInvitation {
		t.Fatal("missing key accepted")
	}
	key[0] ^= 1 // Expiry must reject an otherwise matching organisation key.
	if decoded.CheckOrganisationKey(key, time.Unix(i.ExpiresAt, 0)) != ErrInvitation {
		t.Fatal("stale invite accepted")
	}
	if _, err := DecodeInvitation(token, time.Unix(i.ExpiresAt, 0)); err != ErrInvitation {
		t.Fatal("expired token accepted")
	}
	for _, mode := range []TLSMode{TLSOff, TLSEncrypted} {
		i.TLS, i.CAPEM = mode, nil
		token, err = EncodeInvitation(i, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeInvitation(token, now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvitationInvalidFields(t *testing.T) {
	fixture, _, now := invitationFixture(t)
	cases := []func(*Invitation){
		func(i *Invitation) { i.FormatVersion = 2 }, func(i *Invitation) { i.WorkspaceID = uuid.Nil },
		func(i *Invitation) { i.LoginName = "" }, func(i *Invitation) { i.LoginName = "Élise" }, func(i *Invitation) { i.LoginName = "e\u0301lise" },
		func(i *Invitation) { i.LoginName = strings.Repeat("a", 257) }, func(i *Invitation) { i.LoginName = "a\x00b" },
		func(i *Invitation) { i.OrganisationFingerprint = nil }, func(i *Invitation) { i.ExpiresAt = 0 }, func(i *Invitation) { i.ExpiresAt = now.Unix() },
		func(i *Invitation) { i.Endpoints = nil }, func(i *Invitation) { i.Endpoints = []Endpoint{{Host: "host/path", Port: 5432}} },
		func(i *Invitation) { i.Endpoints = []Endpoint{{Host: "host", Port: 0}} }, func(i *Invitation) { i.Endpoints = append(i.Endpoints, i.Endpoints[0]) },
		func(i *Invitation) { i.Database = "db;drop" }, func(i *Invitation) { i.TLS = "prefer" }, func(i *Invitation) { i.CAPEM = []byte("bad") },
		func(i *Invitation) { i.TLS = TLSOff }, func(i *Invitation) { i.CAPEM = make([]byte, 256*1024+1) },
	}
	for n, mutate := range cases {
		i := fixture
		mutate(&i)
		if _, err := EncodeInvitation(i, now); err != ErrInvitation {
			t.Fatalf("encode case %d: %v", n, err)
		}
		raw, _ := json.Marshal(i)
		if _, err := DecodeInvitation(invitationToken(raw), now); err != ErrInvitation {
			t.Fatalf("decode case %d: %v", n, err)
		}
	}
}

func TestInvitationRejectsAmbiguousAndCorruptTokens(t *testing.T) {
	i, _, now := invitationFixture(t)
	raw, _ := json.Marshal(i)
	token, _ := EncodeInvitation(i, now)
	malformed := []string{"", "WHINV2-abc", strings.Repeat("x", maxInvitationTokenBytes+3), invitationPrefix + "abc", token + "x", token + ".", invitationToken(nil), invitationToken([]byte("!")), invitationToken([]byte("{}")), invitationToken(append(raw, ' '))}
	for _, fragment := range []string{`"code":"never-allowed",`, `"FormatVersion":1,`, `"formatVersion":1,`} {
		malformed = append(malformed, invitationToken([]byte("{"+fragment+string(raw[1:]))))
	}
	// Even with a recomputed checksum, embedded newlines and invalid base64 fail.
	for _, body := range []string{"!", base64.RawURLEncoding.EncodeToString(raw)[:5] + "\n" + base64.RawURLEncoding.EncodeToString(raw)[5:]} {
		payload := invitationPrefix + body
		sum := sha256.Sum256([]byte(payload))
		malformed = append(malformed, payload+"."+hex.EncodeToString(sum[:]))
	}
	for n, s := range malformed {
		if _, err := DecodeInvitation(s, now); err != ErrInvitation {
			t.Fatalf("case %d: %v", n, err)
		}
	}
}
