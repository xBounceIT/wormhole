package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCanonicalSignaturesRejectInvalidUTF8AndNUL(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, invalid := range []string{"invalid\xff", "nul\x00"} {
		binding := testBinding()
		binding.OwnerID = invalid
		if _, err := Seal(testKey(), binding, nil); err != ErrFormat {
			t.Fatal("invalid envelope text accepted")
		}
		record := testRecord()
		record.Host = &invalid
		if _, err := SignRecord(record, "signer", 1, nil, privateKey); err != ErrFormat {
			t.Fatal("lossy record canonicalization")
		}
		record = testRecord()
		record.ParentID = invalid
		if _, err := SealLocalRecord(record, testKey()); err != ErrFormat {
			t.Fatal("invalid parent accepted")
		}
		p := testPolicy()
		p.WorkspaceID = invalid
		if _, err := SignPolicy(p, "signer", 1, privateKey); err != ErrFormat {
			t.Fatal("lossy policy canonicalization")
		}
		if _, err := SignPolicy(testPolicy(), invalid, 1, privateKey); err != ErrFormat {
			t.Fatal("invalid signer accepted")
		}
		b := testBundleBinding()
		b.TunnelConfigID = invalid
		if _, err := b.info(); err != ErrFormat {
			t.Fatal("invalid route accepted")
		}
		if _, err := KeyCheck(testKey(), "vault", invalid); err != ErrFormat {
			t.Fatal("invalid file ID accepted")
		}
		if _, err := SharedSalt("11111111-1111-4111-8111-111111111111", invalid); err != ErrFormat {
			t.Fatal("invalid login accepted")
		}
	}
}
