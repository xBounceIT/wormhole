package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func invitationBootstrapFixture(t *testing.T, i Invitation, code []byte) *UnverifiedInvitationBootstrap {
	t.Helper()
	_, org, _ := invitationFixture(t)
	b, err := vault.NewInviteBootstrap(org)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Wipe()
	e, err := i.SealBootstrap(code, b, time.Unix(i.ExpiresAt-1, 0))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := (&vault.UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	if err != nil {
		t.Fatal(err)
	}
	m, err := vault.SignInviteManifest(vault.InviteManifest{FormatVersion: 1, Context: i.Enrollment.Context, Revision: 1, ExpiresAt: i.ExpiresAt, Bootstrap: pub, Copies: []vault.KeyCopyBinding{}, Issuers: []vault.InviteIssuer{}}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &UnverifiedInvitationBootstrap{Envelope: e, Manifest: m}
}

func invitationBootstrapRows(t *testing.T, i Invitation, b *UnverifiedInvitationBootstrap, now time.Time) [][][]byte {
	t.Helper()
	e, err := EncodeInvitationBootstrapEnvelope(i, b.Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := vault.EncodeInviteManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	c := i.Enrollment.Context
	return [][][]byte{{[]byte(i.WorkspaceID.String()), []byte(c.UserID.String()), []byte(i.LoginName), []byte(c.InviteID.String()), []byte(c.KeyID.String()), []byte(strconv.FormatUint(uint64(c.KeyVersion), 10)), []byte(strconv.FormatInt(i.ExpiresAt, 10)), hex.AppendEncode(nil, e), hex.AppendEncode(nil, m), []byte("1")}}
}

func TestInvitationBootstrapParsing(t *testing.T) {
	i, now := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{41}, 16)
	b := invitationBootstrapFixture(t, i, code)
	rows := invitationBootstrapRows(t, i, b, now)
	parsed, err := parseInvitationBootstrap(rows, i, now)
	if err != nil {
		t.Fatal(err)
	}
	wipeQueryRows(rows)
	opened, err := parsed.Authenticate(i, code, 1, now)
	if err != nil {
		t.Fatal("result aliases wiped buffers", err)
	}
	opened.Wipe()
	for n := 0; n < 10; n++ {
		rows := invitationBootstrapRows(t, i, b, now)
		rows[0][n] = []byte("bad")
		if got, err := parseInvitationBootstrap(rows, i, now); got != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid column", n, err)
		}
	}
	for _, mutate := range []func([][][]byte) [][][]byte{
		func(r [][][]byte) [][][]byte { return nil }, func(r [][][]byte) [][][]byte { return append(r, r[0]) }, func(r [][][]byte) [][][]byte { return [][][]byte{r[0][:9]} },
		func(r [][][]byte) [][][]byte {
			r[0][7] = bytes.Repeat([]byte{'0'}, 2*maxBootstrapEnvelopeBytes+1)
			return r
		},
		func(r [][][]byte) [][][]byte {
			r[0][8] = bytes.Repeat([]byte{'0'}, 2*vault.MaxInviteManifestBytes+1)
			return r
		},
		func(r [][][]byte) [][][]byte { r[0][7] = hex.AppendEncode(nil, []byte("{}")); return r },
		func(r [][][]byte) [][][]byte { r[0][8] = hex.AppendEncode(nil, []byte("{}")); return r },
		func(r [][][]byte) [][][]byte {
			raw, _ := hex.DecodeString(string(r[0][7]))
			raw = append(raw, ' ')
			r[0][7] = hex.AppendEncode(nil, raw)
			return r
		},
	} {
		if got, err := parseInvitationBootstrap(mutate(invitationBootstrapRows(t, i, b, now)), i, now); got != nil || err != ErrAdmissionResponse {
			t.Fatal("invalid response", err)
		}
	}
	if _, err := parseInvitationBootstrap(invitationBootstrapRows(t, i, b, now), i, time.Unix(i.ExpiresAt, 0)); err != ErrAdmissionResponse {
		t.Fatal("expired parse")
	}
	for _, mutate := range []func(*vault.Envelope){func(e *vault.Envelope) { e.FormatVersion++ }, func(e *vault.Envelope) { e.SuiteID++ }, func(e *vault.Envelope) { e.KeyID = uuid.NewString() }, func(e *vault.Envelope) { e.KeyVersion++ }, func(e *vault.Envelope) { e.Nonce = nil }, func(e *vault.Envelope) { e.Ciphertext = nil }} {
		e := b.Envelope
		mutate(&e)
		if _, err := EncodeInvitationBootstrapEnvelope(i, e, now); err != ErrInvitation {
			t.Fatal("bad envelope shape")
		}
	}
	if _, err := EncodeInvitationBootstrapEnvelope(i, b.Envelope, time.Unix(i.ExpiresAt, 0)); err != ErrInvitation {
		t.Fatal("expired encode")
	}
}

func TestInvitationBootstrapAuthentication(t *testing.T) {
	i, now := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{42}, 16)
	for _, mode := range []string{"nil", "code", "signature", "revision", "key-pair", "context", "expired"} {
		b := invitationBootstrapFixture(t, i, code)
		input := bytes.Clone(code)
		minimum := uint64(1)
		when := now
		switch mode {
		case "nil":
			b = nil
		case "code":
			input[0] ^= 1
		case "signature":
			b.Manifest.Signature[0] ^= 1
		case "revision":
			minimum = 2
		case "key-pair":
			other := invitationBootstrapFixture(t, i, code)
			b.Manifest.Bootstrap = other.Manifest.Bootstrap
			var err error
			b.Manifest, err = vault.SignInviteManifest(b.Manifest, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
		case "context":
			b.Manifest.Context.InviteID = uuid.New()
		case "expired":
			when = time.Unix(i.ExpiresAt, 0)
		}
		if opened, err := b.Authenticate(i, input, minimum, when); opened != nil || err == nil {
			t.Fatal("unauthenticated bootstrap", mode, err)
		}
	}
	b := invitationBootstrapFixture(t, i, code)
	raw, err := json.Marshal(b)
	if err != nil || string(raw) != "{}" {
		t.Fatal("native payload serialized")
	}
}

func TestInvitationBootstrapSessionGuards(t *testing.T) {
	i, _ := enrollmentInvitationFixture(t)
	code := bytes.Repeat([]byte{43}, 16)
	s := NewSession()
	defer s.Close(context.Background())
	if err := s.OpenInvitation(nil, i, code); err != ErrConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.OpenInvitation(ctx, i, code); err != context.Canceled {
		t.Fatal(err)
	}
	if err := s.OpenInvitation(context.Background(), i, nil); err != ErrInvitation {
		t.Fatal(err)
	}
	if _, err := s.InvitationBootstrap(nil, i); err != ErrConfiguration {
		t.Fatal(err)
	}
	expired := i
	expired.ExpiresAt = 1
	if _, err := s.InvitationBootstrap(context.Background(), expired); err != ErrInvitation {
		t.Fatal(err)
	}
	if _, err := s.InvitationBootstrap(context.Background(), i); err != ErrSessionClosed {
		t.Fatal(err)
	}
}
