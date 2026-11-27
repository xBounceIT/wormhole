package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func invitationCopyFixture(t *testing.T, i Invitation, code []byte, count int, now time.Time) (*UnverifiedInvitationBootstrap, []vault.SignedKeyCopy) {
	t.Helper()
	b := invitationBootstrapFixture(t, i, code)
	opened, err := b.Authenticate(i, code, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	issuer := vault.KeyRef{ID: uuid.New(), Version: 1}
	var copies []vault.SignedKeyCopy
	for n := 0; n < count; n++ {
		binding := vault.KeyCopyBinding{WorkspaceID: i.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: vault.KeyRef{ID: i.Enrollment.Context.KeyID, Version: i.Enrollment.Context.KeyVersion}, Issuer: issuer}
		copy, err := vault.SealKeyCopy(bytes.Repeat([]byte{byte(n + 1)}, 32), binding, b.Manifest.Bootstrap.Encryption, opened.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		b.Manifest.Copies = append(b.Manifest.Copies, binding)
		copies = append(copies, copy)
	}
	if count > 0 {
		b.Manifest.Issuers = []vault.InviteIssuer{{Key: issuer, Public: bytes.Clone(b.Manifest.Bootstrap.Signing)}}
	}
	b.Manifest, err = vault.SignInviteManifest(b.Manifest, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return b, copies
}

func invitationCopyRows(m vault.InviteManifest, copies []vault.SignedKeyCopy) [][][]byte {
	var rows [][][]byte
	for n, b := range m.Copies {
		v := func(n uint32) []byte { return []byte(strconv.FormatUint(uint64(n), 10)) }
		rows = append(rows, [][]byte{[]byte(b.Key.ID.String()), v(b.Key.Version), []byte(b.Holder.ID.String()), v(b.Holder.Version), []byte(b.Issuer.ID.String()), v(b.Issuer.Version), []byte("2"), hex.AppendEncode(nil, copies[n].Envelope.Enc), hex.AppendEncode(nil, copies[n].Envelope.Ciphertext), hex.AppendEncode(nil, copies[n].Signature)})
	}
	return rows
}

func TestInvitationCopyParsing(t *testing.T) {
	i, now := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{51}, 16)
	b, copies := invitationCopyFixture(t, i, code, 2, now)
	rows := invitationCopyRows(b.Manifest, copies)
	rows[0], rows[1] = rows[1], rows[0]
	parsed, err := parseInvitationCopies(rows, b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	wipeQueryRows(rows)
	for n := range parsed {
		if !bytes.Equal(parsed[n].Envelope.Ciphertext, copies[n].Envelope.Ciphertext) {
			t.Fatal("manifest ordering/ownership")
		}
	}
	opened, err := b.Authenticate(i, code, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	plan, err := vault.PrepareCertifiedInviteRewrap(context.Background(), i.Enrollment.Context, opened, b.Manifest, parsed, 1, i.ExpiresAt, now)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Wipe()
	for n, copy := range plan.Copies {
		key, err := vault.OpenKeyCopy(plan.Keys.EncryptionPrivate, copy.Binding, copy.Copy, plan.Proof.Public.Signing)
		if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{byte(n + 1)}, 32)) {
			t.Fatal("wrong rewrapped key", err)
		}
		vault.Wipe(key)
	}
	for n := 0; n < 10; n++ {
		rows := invitationCopyRows(b.Manifest, copies)
		rows[0][n] = []byte("bad")
		if got, err := parseInvitationCopies(rows, b.Manifest); got != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid copy column", n, err)
		}
	}
	for _, mode := range []string{"missing", "extra", "duplicate", "shape", "hex", "duplicate-manifest", "oversize"} {
		rows := invitationCopyRows(b.Manifest, copies)
		m := b.Manifest
		m.Copies = append([]vault.KeyCopyBinding(nil), m.Copies...)
		switch mode {
		case "missing":
			rows = rows[:1]
		case "extra":
			rows = append(rows, rows[0])
		case "duplicate":
			rows[1] = rows[0]
		case "shape":
			rows[0] = rows[0][:9]
		case "hex":
			rows[0][7] = bytes.Repeat([]byte{'z'}, 64)
		case "duplicate-manifest":
			m.Copies[1] = m.Copies[0]
		case "oversize":
			rows = make([][][]byte, 1025)
			m.Copies = make([]vault.KeyCopyBinding, 1025)
		}
		if got, err := parseInvitationCopies(rows, m); got != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid graph", mode, err)
		}
	}
	if got, err := parseInvitationCopies(nil, vault.InviteManifest{}); err != nil || len(got) != 0 {
		t.Fatal("empty graph", err)
	}
}

func TestPrepareInvitationJoinGuards(t *testing.T) {
	i, _ := enrollmentInvitationFixture(t)
	s := NewSession()
	defer s.Close(context.Background())
	if p, err := s.PrepareInvitationJoin(nil, i, make([]byte, 16), 1); p != nil || err != ErrConfiguration {
		t.Fatal(err)
	}
	if p, err := s.PrepareInvitationJoin(context.Background(), i, make([]byte, 16), 1); p != nil || err != ErrSessionClosed {
		t.Fatal(err)
	}
}
