package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRecoveryDisplayRecipientAndDomain(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workspace, enrollment := uuid.NewString(), uuid.NewString()
	code, err := FormatRecoveryKey(NewRecoveryKey())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := SealRecoveryDisplay(private.PublicKey().Bytes(), workspace, enrollment, code)
	if err != nil || bundle.FormatVersion != FormatVersion || bundle.SuiteID != SuiteX25519HKDFSHA256AES256GCM || len(bundle.Enc) != 32 || len(bundle.Ciphertext) != len(code)+16 {
		t.Fatal("invalid sealed display", err)
	}
	if bytes.Contains(bundle.Ciphertext, code) {
		t.Fatal("plaintext display")
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		domain, workspace, enrollment string
		valid                         bool
	}{
		{"wormhole/v1/recovery-display", workspace, enrollment, true},
		{"wormhole/v1/protocol-bundle", workspace, enrollment, false},
		{"wormhole/v1/recovery-display", uuid.NewString(), enrollment, false},
		{"wormhole/v1/recovery-display", workspace, uuid.NewString(), false},
	} {
		r, err := hpke.NewRecipient(bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), canonical(test.domain, []byte(test.workspace), []byte(test.enrollment)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Open(nil, bundle.Ciphertext)
		if test.valid {
			if err != nil || !bytes.Equal(got, code) {
				t.Fatal("display interop", err)
			}
		} else if err == nil {
			t.Fatal("changed display context accepted")
		}
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	otherKey, _ := hpke.NewDHKEMPrivateKey(other)
	info, _ := recoveryDisplayInfo(workspace, enrollment)
	r, err := hpke.NewRecipient(bundle.Enc, otherKey, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(nil, bundle.Ciphertext); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	for _, bad := range []string{"", uuid.Nil.String(), "bad", strings.ToUpper("abcdefab-cdef-4abc-8def-abcdefabcdef")} {
		if _, err := SealRecoveryDisplay(private.PublicKey().Bytes(), bad, enrollment, code); err != ErrFormat {
			t.Fatal("bad workspace accepted", err)
		}
		if _, err := SealRecoveryDisplay(private.PublicKey().Bytes(), workspace, bad, code); err != ErrFormat {
			t.Fatal("bad enrollment accepted", err)
		}
	}
	if _, err := SealRecoveryDisplay(nil, workspace, enrollment, code); err != ErrFormat {
		t.Fatal(err)
	}
	if _, err := SealRecoveryDisplay(make([]byte, 32), workspace, enrollment, code); err != ErrAuthentication {
		t.Fatal(err)
	}
	if _, err := SealRecoveryDisplay(private.PublicKey().Bytes(), workspace, enrollment, []byte("invalid")); err != ErrFormat {
		t.Fatal(err)
	}
}
