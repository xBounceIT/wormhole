package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func pendingEnrollmentFixture(t *testing.T, count int) ([]byte, TrustBinding, PendingEnrollment) {
	t.Helper()
	f := invitationCommitFixture(t, count)
	request, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Wipe()
	b := TrustBinding{WorkspaceID: f.i.WorkspaceID, UserID: f.i.Enrollment.Context.UserID, DeviceID: f.device, KeyID: uuid.New(), KeyVersion: 1}
	p, err := request.PendingEnrollment(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Repeat([]byte{53}, 32), b, p
}

func TestPendingEnrollmentRoundTrip(t *testing.T) {
	for _, count := range []int{0, vault.MaxInviteKeyCopies} {
		root, b, p := pendingEnrollmentFixture(t, count)
		raw, err := SealPendingEnrollment(root, b, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenPendingEnrollment(root, b, raw)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("pending roundtrip", err)
		}
		if bytes.Contains(raw, []byte(p.Certificate.Manifest.Context.LoginName)) || bytes.Contains(raw, p.Trust.SignedProfile) {
			t.Fatal("plaintext metadata")
		}
		// Domain separation prevents mistaking staged intent for active trust.
		if _, err := OpenTrustState(root, b, raw, 1); err == nil {
			t.Fatal("pending accepted as trust")
		}
		trustRaw, err := SealTrustState(root, b, p.Trust)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenPendingEnrollment(root, b, trustRaw); err == nil {
			t.Fatal("trust accepted as pending")
		}
		if _, err := OpenPendingEnrollment(bytes.Repeat([]byte{54}, 32), b, raw); err == nil {
			t.Fatal("wrong root")
		}
		for n := 0; n < 5; n++ {
			wrong := b
			switch n {
			case 0:
				wrong.WorkspaceID = uuid.New()
			case 1:
				wrong.UserID = uuid.New()
			case 2:
				wrong.DeviceID = uuid.New()
			case 3:
				wrong.KeyID = uuid.New()
			case 4:
				wrong.KeyVersion++
			}
			if _, err := OpenPendingEnrollment(root, wrong, raw); err == nil {
				t.Fatal("binding substitution", n)
			}
		}
	}
}

func TestPendingEnrollmentValidation(t *testing.T) {
	for _, mode := range []string{"format", "binding", "revision", "trust-format", "missing-state", "revoked", "wrapping", "digest", "profile", "signature", "role-short", "role-invalid", "preset", "ask"} {
		t.Run(mode, func(t *testing.T) {
			root, b, p := pendingEnrollmentFixture(t, 0)
			switch mode {
			case "format":
				p.FormatVersion++
			case "binding":
				p.Trust.UserID = uuid.New()
			case "revision":
				p.Trust.Revision++
			case "trust-format":
				p.Trust.FormatVersion = 2
			case "missing-state":
				p.Trust.Account = nil
			case "revoked":
				p.Trust.Account.Active = false
			case "wrapping":
				p.Trust.WrappingRevision++
			case "digest":
				p.CapsuleDigest = nil
			case "profile":
				p.Trust.SignedProfile[0] ^= 1
			case "signature":
				p.Certificate.Rekey.Signature[0] ^= 1
			case "role-short":
				p.RoleTag = "a"
			case "role-invalid":
				p.RoleTag = "invalid!"
			case "preset":
				p.KDF = vault.KDFLow
			case "ask":
				p.ASKRequired = false
			}
			if _, err := SealPendingEnrollment(root, b, p); err != ErrTrustState {
				t.Fatal("invalid record sealed", err)
			}
		})
	}
	root, b, p := pendingEnrollmentFixture(t, 0)
	for _, key := range [][]byte{nil, {1}} {
		if _, err := SealPendingEnrollment(key, b, p); err != ErrTrustState {
			t.Fatal(err)
		}
	}
	wrong := b
	wrong.KeyID = uuid.Nil
	if _, err := SealPendingEnrollment(root, wrong, p); err != ErrTrustState {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte("bad"), []byte("{}"), bytes.Repeat([]byte{'x'}, MaxPendingEnrollmentBytes+1)} {
		if _, err := OpenPendingEnrollment(root, b, raw); err != ErrTrustState {
			t.Fatal(err)
		}
	}
	raw, err := SealPendingEnrollment(root, b, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPendingEnrollment(nil, b, raw); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := OpenPendingEnrollment(root, wrong, raw); err != ErrTrustState {
		t.Fatal(err)
	}
	if _, err := OpenPendingEnrollment(root, b, append(raw, ' ')); err != ErrTrustState {
		t.Fatal(err)
	}
	// Authenticate malformed/noncanonical plaintext to exercise post-AEAD checks.
	binding, _ := pendingEnrollmentBinding(b)
	key, _ := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	defer vault.Wipe(key)
	plain, _ := json.Marshal(p)
	for _, body := range [][]byte{[]byte("bad"), []byte("{}"), append(plain, ' ')} {
		env, e := vault.Seal(key, binding, body)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(env)
		if _, e := OpenPendingEnrollment(root, b, raw); e != ErrTrustState {
			t.Fatal(e)
		}
	}
	f := invitationCommitFixture(t, 0)
	request, e := f.prepare()
	if e != nil {
		t.Fatal(e)
	}
	defer request.Wipe()
	var absent *PreparedInvitationCommit
	if _, e := absent.PendingEnrollment(b); e != ErrTrustState {
		t.Fatal(e)
	}
	if _, e := request.PendingEnrollment(b); e != ErrTrustState {
		t.Fatal("foreign binding", e)
	}
	request.pending = []byte("bad")
	if _, e := request.PendingEnrollment(b); e != ErrTrustState {
		t.Fatal(e)
	}
}

func TestPendingEnrollmentSurvivesExpiryAndWipe(t *testing.T) {
	f := invitationCommitFixture(t, 0)
	// The prepared intent remains recoverable after invitation expiry.
	f.manifest.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	var err error
	f.manifest, err = vault.SignInviteManifest(f.manifest, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.i.ExpiresAt = f.manifest.ExpiresAt
	f.now = time.Unix(f.i.ExpiresAt-1, 0)
	manifest, _ := vault.EncodeInviteManifest(f.manifest)
	digest := sha256.Sum256(manifest)
	f.plan.SourceManifestDigest = digest[:]
	p, err := f.prepare()
	if err != nil {
		t.Fatal(err)
	}
	b := TrustBinding{WorkspaceID: f.i.WorkspaceID, UserID: f.i.Enrollment.Context.UserID, DeviceID: f.device, KeyID: uuid.New(), KeyVersion: 1}
	record, err := p.PendingEnrollment(b)
	if err != nil {
		t.Fatal(err)
	}
	retained := p.pending
	p.Wipe()
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("pending buffer retained")
	}
	if _, err := p.PendingEnrollment(b); err != ErrTrustState {
		t.Fatal(err)
	}
	root := make([]byte, 32)
	raw, err := SealPendingEnrollment(root, b, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPendingEnrollment(root, b, raw); err != nil {
		t.Fatal("expired intent lost", err)
	}
}
