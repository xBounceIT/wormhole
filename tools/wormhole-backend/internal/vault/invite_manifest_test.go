package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
)

func manifestFixture(t *testing.T) (*InviteBootstrap, InviteManifest, []SignedKeyCopy, []byte) {
	t.Helper()
	c, b, expected, copies, issuers := inviteCopySet(t, 2)
	seed := bytes.Repeat([]byte{9}, 32)
	root := ed25519.NewKeyFromSeed(seed)
	defer Wipe(root)
	b.OrganisationPublic = root.Public().(ed25519.PublicKey)
	pub, _ := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	m := InviteManifest{FormatVersion: 1, Context: c, Revision: 2, ExpiresAt: 1800003600, Bootstrap: pub, Copies: expected}
	for key, public := range issuers {
		m.Issuers = append(m.Issuers, InviteIssuer{Key: key, Public: public})
	}
	signed, err := SignInviteManifest(m, seed)
	if err != nil {
		t.Fatal(err)
	}
	return b, signed, copies, seed
}

func TestInviteManifestVerifiedRewrapAndCodec(t *testing.T) {
	b, m, copies, _ := manifestFixture(t)
	now := time.Unix(m.ExpiresAt-1, 0)
	raw, err := EncodeInviteManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInviteManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInviteManifest(decoded, m.Context, b.OrganisationPublic, 2, m.ExpiresAt, now); err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, b, decoded, copies, 2, m.ExpiresAt, now)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Wipe()
	if len(plan.Copies) != 2 {
		t.Fatal("incomplete replacement")
	}
	digest := sha256.Sum256(raw)
	if plan.SourceManifestRevision != m.Revision || !bytes.Equal(plan.SourceManifestDigest, digest[:]) {
		t.Fatal("source manifest not pinned in plan")
	}
	for i, row := range plan.Copies {
		key, err := OpenKeyCopy(plan.Keys.EncryptionPrivate, row.Binding, row.Copy, plan.Proof.Public.Signing)
		if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{byte(i + 1)}, 32)) {
			t.Fatal("certified copy not preserved")
		}
		Wipe(key)
	}
	if !bytes.Contains(raw, []byte(`"workspaceId"`)) || bytes.Contains(raw, []byte(`"WorkspaceID"`)) {
		t.Fatal("context wire naming changed")
	}
	plan.Wipe()
	if plan.SourceManifestRevision != 0 || plan.SourceManifestDigest != nil {
		t.Fatal("retired plan retained commit coordinates")
	}
}

func TestInviteManifestAuthenticationAndRollback(t *testing.T) {
	b, m, copies, _ := manifestFixture(t)
	now := time.Unix(m.ExpiresAt-1, 0)
	if VerifyInviteManifest(m, m.Context, b.OrganisationPublic, 3, m.ExpiresAt, now) != ErrRollback {
		t.Fatal("old revision accepted")
	}
	malformed := m
	malformed.FormatVersion = 2
	if VerifyInviteManifest(malformed, m.Context, b.OrganisationPublic, 1, m.ExpiresAt, now) != ErrFormat {
		t.Fatal("malformed manifest accepted")
	}
	tampered := m
	tampered.Signature = make([]byte, 64)
	if VerifyInviteManifest(tampered, m.Context, b.OrganisationPublic, 3, m.ExpiresAt, now) != ErrAuthentication {
		t.Fatal("rollback checked before authentication")
	}
	if VerifyInviteManifest(m, m.Context, b.OrganisationPublic, 0, m.ExpiresAt, now) != ErrFormat {
		t.Fatal("missing floor")
	}
	if VerifyInviteManifest(m, m.Context, b.OrganisationPublic, math.MaxUint64, m.ExpiresAt, now) != ErrFormat {
		t.Fatal("invalid floor")
	}
	other := m.Context
	other.InviteID = uuid.New()
	if VerifyInviteManifest(m, other, b.OrganisationPublic, 1, m.ExpiresAt, now) != ErrAuthentication {
		t.Fatal("wrong invite")
	}
	if VerifyInviteManifest(m, m.Context, nil, 1, m.ExpiresAt, now) != ErrAuthentication {
		t.Fatal("missing root")
	}
	if VerifyInviteManifest(m, m.Context, make([]byte, 32), 1, m.ExpiresAt, now) != ErrAuthentication {
		t.Fatal("wrong root")
	}
	if VerifyInviteManifest(m, m.Context, b.OrganisationPublic, 1, m.ExpiresAt+1, now) != ErrAuthentication {
		t.Fatal("wrong expiry")
	}
	if VerifyInviteManifest(m, m.Context, b.OrganisationPublic, 1, m.ExpiresAt, time.Unix(m.ExpiresAt, 0)) != ErrAuthentication {
		t.Fatal("expired manifest")
	}
	for _, change := range []func(*InviteManifest){func(m *InviteManifest) { m.Copies = m.Copies[:1] }, func(m *InviteManifest) { m.Revision++ }, func(m *InviteManifest) { m.Issuers[0].Public = make([]byte, 32) }, func(m *InviteManifest) { m.Bootstrap.Signing = make([]byte, 32) }} {
		raw, _ := json.Marshal(m)
		var bad InviteManifest
		_ = json.Unmarshal(raw, &bad)
		change(&bad)
		if VerifyInviteManifest(bad, m.Context, b.OrganisationPublic, 1, m.ExpiresAt, now) == nil {
			t.Fatal("modified signed metadata accepted")
		}
	}
	if p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, b, tampered, copies, 1, m.ExpiresAt, now); err != ErrAuthentication || p != nil {
		t.Fatal("untrusted graph reached rewrap")
	}
}

func TestInviteManifestRejectsMalformedShape(t *testing.T) {
	_, m, _, seed := manifestFixture(t)
	for _, change := range []func(*InviteManifest){
		func(m *InviteManifest) { m.FormatVersion = 2 }, func(m *InviteManifest) { m.Revision = 0 }, func(m *InviteManifest) { m.Revision = math.MaxUint64 }, func(m *InviteManifest) { m.ExpiresAt = 0 },
		func(m *InviteManifest) { m.Context.UserID = uuid.Nil }, func(m *InviteManifest) { m.Context.KeyVersion = math.MaxUint32 }, func(m *InviteManifest) { m.Bootstrap.Signing = nil }, func(m *InviteManifest) { m.Bootstrap.Encryption = nil }, func(m *InviteManifest) { m.Bootstrap.Encryption = make([]byte, 32) },
		func(m *InviteManifest) { m.Copies = make([]KeyCopyBinding, MaxInviteKeyCopies+1) }, func(m *InviteManifest) { m.Issuers = make([]InviteIssuer, MaxInviteKeyCopies+1) },
		func(m *InviteManifest) { m.Issuers[0].Key.ID = uuid.Nil }, func(m *InviteManifest) { m.Issuers[0].Key.Version = 0 }, func(m *InviteManifest) { m.Issuers[0].Key.Version = math.MaxUint32 }, func(m *InviteManifest) { m.Issuers[0].Public = nil },
		func(m *InviteManifest) { m.Issuers = append(m.Issuers, m.Issuers[0]) }, func(m *InviteManifest) { m.Issuers = nil }, func(m *InviteManifest) { m.Copies = nil },
		func(m *InviteManifest) { m.Copies[1] = m.Copies[0] }, func(m *InviteManifest) { m.Copies[0].WorkspaceID = uuid.New() }, func(m *InviteManifest) { m.Copies[0].Holder.ID = uuid.New() }, func(m *InviteManifest) { m.Copies[0].Holder.Version++ }, func(m *InviteManifest) { m.Copies[0].Key.Version = 0 },
	} {
		raw, _ := json.Marshal(m)
		var bad InviteManifest
		_ = json.Unmarshal(raw, &bad)
		change(&bad)
		if _, err := SignInviteManifest(bad, seed); err != ErrFormat {
			t.Fatal("signed malformed manifest")
		}
		if _, err := EncodeInviteManifest(bad); err != ErrFormat {
			t.Fatal("encoded malformed manifest")
		}
	}
	if _, err := SignInviteManifest(m, nil); err != ErrFormat {
		t.Fatal("missing signing seed")
	}
	bad := m
	bad.Signature = nil
	if _, err := EncodeInviteManifest(bad); err != ErrFormat {
		t.Fatal("missing signature encoded")
	}
	raw, _ := EncodeInviteManifest(m)
	for _, bad := range [][]byte{nil, make([]byte, MaxInviteManifestBytes+1), []byte("!"), []byte("{}"), append(append([]byte(nil), raw...), ' '), append([]byte(`{"unknown":1,`), raw[1:]...), append([]byte(`{"formatVersion":1,`), raw[1:]...)} {
		if _, err := DecodeInviteManifest(bad); err != ErrFormat {
			t.Fatal("ambiguous manifest accepted")
		}
	}
}

func TestCertifiedInviteRewrapRejectsMismatchAndCancellation(t *testing.T) {
	b, m, copies, seed := manifestFixture(t)
	now := time.Unix(m.ExpiresAt-1, 0)
	if p, err := PrepareCertifiedInviteRewrap(nil, m.Context, b, m, copies, 1, m.ExpiresAt, now); err != ErrFormat || p != nil {
		t.Fatal("nil context")
	}
	if p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, nil, m, copies, 1, m.ExpiresAt, now); err != ErrFormat || p != nil {
		t.Fatal("nil bootstrap")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := PrepareCertifiedInviteRewrap(ctx, m.Context, b, m, copies, 1, m.ExpiresAt, now); err != context.Canceled || p != nil {
		t.Fatal("canceled operation")
	}
	wrong := *b
	wrong.SigningSeed = nil
	if p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, &wrong, m, copies, 1, m.ExpiresAt, now); err != ErrFormat || p != nil {
		t.Fatal("invalid bootstrap")
	}
	wrong = *b
	wrong.SigningSeed = make([]byte, 32)
	if p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, &wrong, m, copies, 1, m.ExpiresAt, now); err != ErrAuthentication || p != nil {
		t.Fatal("different bootstrap")
	}
	if p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, b, m, copies[:1], 1, m.ExpiresAt, now); err != ErrFormat || p != nil {
		t.Fatal("omitted copy")
	}
	m.Copies = nil
	m.Issuers = nil
	m, err := SignInviteManifest(m, seed)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PrepareCertifiedInviteRewrap(context.Background(), m.Context, b, m, nil, 1, m.ExpiresAt, now)
	if err != nil {
		t.Fatal(err)
	}
	p.Wipe()
}
