package ikesa

import (
	"bytes"
	"testing"
)

// TestDeriveRejectsShortNonces: key derivation fails closed on a peer nonce
// below the RFC 7296 §2.10 minimum (128 bits / half the PRF key size = 16
// bytes for PRF_HMAC_SHA2_256) instead of silently folding a low-entropy
// nonce into SKEYSEED and the AUTH signed octets.
func TestDeriveRejectsShortNonces(t *testing.T) {
	ok := bytes.Repeat([]byte{0x11}, 32)
	short := bytes.Repeat([]byte{0x22}, minNonceLen-1)
	atFloor := bytes.Repeat([]byte{0x33}, minNonceLen)
	dh := bytes.Repeat([]byte{0x99}, modp2048Len)

	cases := []struct {
		name    string
		ni, nr  []byte
		wantErr bool
	}{
		{"both ok", ok, ok, false},
		{"at floor", atFloor, atFloor, false},
		{"short initiator", short, ok, true},
		{"short responder", ok, short, true},
		{"empty responder", ok, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &IKESA{}
			err := s.Derive(SuiteAESCBC256SHA256, Initiator, 1, 2, tc.ni, tc.nr, dh)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Derive err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			// The rekey path enforces the same floor.
			if _, err := DeriveRekeyIKE(SuiteAESCBC256SHA256, s.SKd, Initiator, 3, 4, tc.ni, tc.nr, dh); err != nil {
				t.Fatalf("DeriveRekeyIKE: %v", err)
			}
			if _, err := DeriveRekeyIKE(SuiteAESCBC256SHA256, s.SKd, Initiator, 3, 4, short, tc.nr, dh); err == nil {
				t.Fatal("DeriveRekeyIKE accepted a short nonce")
			}
		})
	}
}
