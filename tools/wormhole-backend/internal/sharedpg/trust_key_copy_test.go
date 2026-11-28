package sharedpg

import (
	"bytes"
	"crypto/ecdh"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestKeyCopyIssuerTrustPersistence(t *testing.T) {
	root, bind, s, _, a, org, key := credentialTrustFixture(t)
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	b := vault.KeyCopyBinding{WorkspaceID: s.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: a.State.Encryption, Issuer: a.State.Signing}
	copy, e := vault.SealKeyCopy(bytes.Repeat([]byte{23}, 32), b, private.PublicKey().Bytes(), key.Seed())
	if e != nil {
		t.Fatal(e)
	}
	next, e := s.AdvanceKeyCopy(b, copy, &a)
	if e != nil || len(next.Catalog) != 2 || s.ValidateAdvance(next) != nil {
		t.Fatal("copy issuer", e)
	}
	raw, e := SealTrustState(root, bind, next)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := OpenTrustState(root, bind, raw, next.Revision)
	if e != nil || !reflect.DeepEqual(restored, next) {
		t.Fatal("persistent copy issuer", e)
	}
	same, e := restored.AdvanceKeyCopy(b, copy, &a)
	if e != nil || !reflect.DeepEqual(same, restored) {
		t.Fatal("repeat", e)
	}
	for _, mode := range []string{"signature", "scope", "certificate", "revoked", "missing-author", "missing-state"} {
		t.Run(mode, func(t *testing.T) {
			binding, record, author := b, copy, a
			var arg *UnverifiedNodeAuthor = &author
			want := error(vault.ErrAuthentication)
			switch mode {
			case "signature":
				record.Signature = make([]byte, 64)
			case "scope":
				binding.WorkspaceID = uuid.New()
			case "certificate":
				author.Certificate = nil
				want = vault.ErrFormat
			case "revoked":
				state := *a.State
				state.Active = false
				state.Sequence++
				state, e = vault.SignUserKeyState(state, org)
				if e != nil {
					t.Fatal(e)
				}
				author.State = &state
				want = vault.ErrPolicy
			case "missing-author":
				arg = nil
				want = ErrTrustState
			case "missing-state":
				author.State = nil
				want = ErrTrustState
			}
			observed, e := s.AdvanceKeyCopy(binding, record, arg)
			if e != want {
				t.Fatal("copy rejection", mode, e)
			}
			if mode != "missing-author" && mode != "missing-state" {
				if observed.Revision != s.Revision+1 || s.ValidateAdvance(observed) != nil {
					t.Fatal("observations lost", mode)
				}
				if mode == "revoked" {
					if observed.Catalog["author/"+s.UserID.String()].Revision != a.State.Sequence+1 {
						t.Fatal("revocation lost")
					}
					if _, e = observed.AdvanceAccount(*a.State, 1); e != vault.ErrRollback {
						t.Fatal("first unlock ignored copy revocation", e)
					}
				}
			}
		})
	}
	b.Issuer = a.State.Signer
	copy, e = vault.SealKeyCopy(bytes.Repeat([]byte{23}, 32), b, private.PublicKey().Bytes(), org.Seed())
	if e != nil {
		t.Fatal(e)
	}
	observed, e := s.AdvanceKeyCopy(b, copy, nil)
	if e != nil || !reflect.DeepEqual(observed, s) {
		t.Fatal("org pin", e)
	}
	if _, e = s.AdvanceKeyCopy(b, copy, &a); e != vault.ErrAuthentication {
		t.Fatal("extraneous user issuer", e)
	}
	b.WorkspaceID = uuid.New()
	if _, e = s.AdvanceKeyCopy(b, copy, nil); e != vault.ErrAuthentication {
		t.Fatal("org copy workspace", e)
	}
	invalid := s
	invalid.Revision = 0
	if _, e = invalid.AdvanceKeyCopy(b, copy, nil); e != ErrTrustState {
		t.Fatal(e)
	}
}
