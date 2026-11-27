package sharedpg

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSCRAMVerifierIndependentVector(t *testing.T) {
	// Independently computed with Python hashlib.pbkdf2_hmac and hmac.
	material, salt := make([]byte, 32), make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
		salt[i] = byte(i + 32)
	}
	login, err := EncodeLoginSecret(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	if string(login) != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" {
		t.Fatal("login encoding changed")
	}
	verifier := buildSCRAMVerifier(login, salt)
	defer vault.Wipe(verifier)
	const expected = "SCRAM-SHA-256$4096:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=$5iXsgCWcXBs1eDy9RKNWg6be/vOSn+aoEvu7vf/IbBU=:nqjc37IGvhCLixL0AaLScyoY0P/cpL8+plBAoIFqj9k="
	if string(verifier) != expected || ValidateSCRAMVerifier(verifier) != nil {
		t.Fatal("verifier vector mismatch")
	}
}

func TestSCRAMVerifierGenerationAndBounds(t *testing.T) {
	material := bytes.Repeat([]byte{7}, 32)
	a, err := NewSCRAMVerifier(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(a)
	b, err := NewSCRAMVerifier(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(b)
	if bytes.Equal(a, b) || ValidateSCRAMVerifier(a) != nil || ValidateSCRAMVerifier(b) != nil {
		t.Fatal("salt reused or invalid verifier")
	}
	if !bytes.Equal(material, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("borrowed material modified")
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 1024)} {
		if got, err := NewSCRAMVerifier(bad); err != ErrSCRAMVerifier || got != nil {
			t.Fatal("invalid derived material accepted")
		}
		if got, err := EncodeLoginSecret(bad); err != ErrSCRAMVerifier || got != nil {
			t.Fatal("invalid login material accepted")
		}
	}
}

func TestSCRAMVerifierCanonicalValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	salt := base64.StdEncoding.EncodeToString(make([]byte, 32))
	value := func(cost, salt, stored, server string) []byte {
		return []byte("SCRAM-SHA-256$" + cost + ":" + salt + "$" + stored + ":" + server)
	}
	for _, cost := range []string{"4096", "8192", "1000000"} {
		for _, size := range []int{16, 32, 64} {
			if ValidateSCRAMVerifier(value(cost, base64.StdEncoding.EncodeToString(make([]byte, size)), key, key)) != nil {
				t.Fatal("valid verifier rejected")
			}
		}
	}
	for _, cost := range []string{"", "0", "4095", "1000001", "10000000", "04096", "+4096", "-4096", "4096 ", "4e3"} {
		if ValidateSCRAMVerifier(value(cost, salt, key, key)) != ErrSCRAMVerifier {
			t.Fatal("invalid cost accepted")
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 100), base64.StdEncoding.EncodeToString(make([]byte, 15)), base64.StdEncoding.EncodeToString(make([]byte, 65)), salt[:3] + "\n" + salt[3:], salt + " ", "!", salt[:len(salt)-2] + "B="} {
		if ValidateSCRAMVerifier(value("4096", bad, key, key)) != ErrSCRAMVerifier {
			t.Fatal("invalid salt accepted")
		}
	}
	for _, bad := range []string{"", key[:len(key)-1], base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33)), key + ":extra", "'"} {
		if ValidateSCRAMVerifier(value("4096", salt, bad, key)) != ErrSCRAMVerifier || ValidateSCRAMVerifier(value("4096", salt, key, bad)) != ErrSCRAMVerifier {
			t.Fatal("invalid keys accepted")
		}
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxSCRAMVerifierBytes+1), []byte("md5invalid"), []byte("SCRAM-SHA-256$4096"), []byte("SCRAM-SHA-256$4096$bad"), []byte("SCRAM-SHA-256$4096:" + salt + "$bad")} {
		if ValidateSCRAMVerifier(bad) != ErrSCRAMVerifier {
			t.Fatal("malformed verifier accepted")
		}
	}
}
