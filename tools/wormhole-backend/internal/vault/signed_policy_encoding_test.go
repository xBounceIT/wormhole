package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignedPolicyCanonicalEncoding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignPolicy(testPolicy(), "org", 1, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPolicy(decoded, "workspace", "org", 1, pub, 1); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", strings.Repeat(" ", MaxSignedPolicyBytes+1), "{", "null", string(raw) + "\n", string(raw) + "{}",
		strings.Replace(string(raw), `"sequence":1`, `"sequence":1,"sequence":1`, 1),
		strings.Replace(string(raw), `"sequence":1`, `"Sequence":1`, 1),
		strings.Replace(string(raw), `"sequence":1`, `"sequence":1.0`, 1),
		strings.Replace(string(raw), `"askRequired":false,`, "", 1),
		strings.Replace(string(raw), `"profile":"standard"`, `"profile":"standard","unknown":true`, 1),
		strings.Replace(string(raw), `"signerKeyVersion":1`, `"signerKeyVersion":0`, 1),
		strings.Replace(string(raw), `"formatVersion":1`, `"formatVersion":99`, 1),
	} {
		if _, err := DecodeSignedPolicy([]byte(bad)); err == nil {
			t.Fatal("accepted noncanonical/invalid policy")
		}
	}
	signed.Signature = nil
	if _, err := EncodeSignedPolicy(signed); err != ErrFormat {
		t.Fatal("accepted missing signature")
	}
	signed.Signature = make([]byte, ed25519.SignatureSize)
	signed.Policy.Sequence = 0
	if _, err := EncodeSignedPolicy(signed); err == nil {
		t.Fatal("accepted invalid policy")
	}
}
