package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestParseServerCertificateRenewalMaterial(t *testing.T) {
	key := vault.KeyRef{ID: uuid.New(), Version: 1}
	enc, ciphertext, signature := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 64)
	ca := workspaceCAKeyCopy{Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Copy: vault.SignedKeyCopy{
		Envelope:  vault.SealedBundle{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteX25519HKDFSHA256AES256GCM, Enc: enc, Ciphertext: ciphertext},
		Signature: signature,
	}}
	copyJSON, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	row := [][]byte{[]byte(key.ID.String()), []byte("1"), hex.AppendEncode(nil, enc), hex.AppendEncode(nil, ciphertext), hex.AppendEncode(nil, signature), copyJSON}
	material, err := parseServerCertificateRenewal([][][]byte{row})
	if err != nil || material.organisation != key || material.ca.Key != ca.Key ||
		!bytes.Equal(material.copy.Envelope.Ciphertext, ciphertext) || !bytes.Equal(material.copy.Signature, signature) {
		t.Fatal("encrypted renewal material changed", err)
	}
	for _, shape := range [][][][]byte{nil, {row, row}, {row[:5]}} {
		if _, err := parseServerCertificateRenewal(shape); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("unexpected renewal row shape accepted", err)
		}
	}
	for _, test := range []struct {
		index int
		bad   []byte
	}{
		{0, []byte(uuid.Nil.String())}, {1, []byte("01")}, {2, nil}, {3, nil}, {4, nil},
		{2, bytes.Repeat([]byte{'x'}, 64)}, {3, bytes.Repeat([]byte{'x'}, 96)}, {4, bytes.Repeat([]byte{'x'}, 128)},
		{5, nil}, {5, []byte(`{"key":{"version":2}}`)}, {5, bytes.Repeat([]byte{' '}, maxBootstrapRecoveryBytes+1)},
	} {
		invalid := slices.Clone(row)
		invalid[test.index] = test.bad
		if _, err := parseServerCertificateRenewal([][][]byte{invalid}); !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("bad renewal field accepted", test.index, err)
		}
	}
}

func TestServerCertificateRenewalRequiresTrustedAccountAndKey(t *testing.T) {
	var session Session
	key := make([]byte, 32)
	if _, err := session.RenewServerCertificate(context.Background(), TrustState{}, nil, key, nil, nil, time.Now()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing resident signing key accepted", err)
	}
	if _, err := session.RenewServerCertificate(context.Background(), TrustState{}, nil, key, key, nil, time.Now()); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("untrusted account accepted", err)
	}
}
