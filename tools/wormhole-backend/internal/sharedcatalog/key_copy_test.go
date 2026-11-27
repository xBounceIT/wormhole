package sharedcatalog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestCurrentKeyCopyIssuer(t *testing.T) {
	_, _, cert, state, pin, key := credentialFixture(t)
	user, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	b := vault.KeyCopyBinding{WorkspaceID: pin.Workspace, Key: vault.KeyRef{ID: uuid.New(), Version: 2}, Holder: vault.KeyRef{ID: uuid.New(), Version: 1}, Issuer: state.Signing}
	copy, e := vault.SealKeyCopy(bytes.Repeat([]byte{23}, 32), b, user.PublicKey().Bytes(), key.Seed())
	if e != nil {
		t.Fatal(e)
	}
	trust := vault.UserKeyTrust{WorkspaceID: pin.Workspace, UserID: pin.Author, Signer: pin.OrganisationKey, Organisation: pin.Organisation, MinimumSequence: 9}
	if got, e := VerifyCurrentKeyCopy(b, copy, cert, state, trust, 3); e != nil || got != (KeyCopyObservation{9, 3}) {
		t.Fatal(got, e)
	}
	for _, mode := range []string{"workspace", "issuer", "key", "signature", "suite", "future", "certificate", "state-floor", "certificate-floor", "revoked", "org-pin"} {
		t.Run(mode, func(t *testing.T) {
			binding, record, c, s, p := b, copy, cert, state, trust
			floor := uint64(3)
			expected := KeyCopyObservation{9, 3}
			want := error(vault.ErrAuthentication)
			switch mode {
			case "workspace":
				binding.WorkspaceID = uuid.New()
			case "issuer":
				binding.Issuer.ID = uuid.New()
			case "key":
				binding.Key.ID = uuid.New()
			case "signature":
				record.Signature = make([]byte, 64)
			case "suite":
				record.Envelope.SuiteID = 1
				want = vault.ErrFormat
			case "future":
				record.Envelope.FormatVersion++
				want = vault.ErrNewerFormat
			case "certificate":
				c.Signature = make([]byte, 64)
				expected.CertificateRevision = 0
			case "state-floor":
				p.MinimumSequence++
				expected = KeyCopyObservation{}
				want = vault.ErrRollback
			case "certificate-floor":
				floor++
				expected.CertificateRevision = 0
				want = vault.ErrRollback
			case "revoked":
				s.Active = false
				s.Sequence++
				org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
				var e error
				s, e = vault.SignUserKeyState(s, org)
				vault.Wipe(org)
				if e != nil {
					t.Fatal(e)
				}
				expected = KeyCopyObservation{10, 0}
				want = vault.ErrPolicy
			case "org-pin":
				p.Organisation = make([]byte, 32)
				expected = KeyCopyObservation{}
			}
			got, e := VerifyCurrentKeyCopy(binding, record, c, s, p, floor)
			if e != want || got != expected {
				t.Fatal("issuer observation", mode, got, e)
			}
		})
	}
}
