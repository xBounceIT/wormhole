package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestCredentialDisplayEncodingAndDomain(t *testing.T) {
	for _, passphrase := range []bool{false, true} {
		p := CredentialDisplayPayload{Username: "alïce", Domain: "CORP", Passphrase: passphrase, Secret: []byte("<secret>\x00🪱")}
		raw, err := EncodeCredentialDisplay(p)
		if err != nil {
			t.Fatal(err)
		}
		defer Wipe(raw)
		if raw[0] != 1 || (raw[1] == 1) != passphrase {
			t.Fatal("format")
		}
		rest := raw[2:]
		for _, want := range [][]byte{[]byte(p.Username), []byte(p.Domain), p.Secret} {
			size := int(binary.BigEndian.Uint32(rest))
			rest = rest[4:]
			if !bytes.Equal(rest[:size], want) {
				t.Fatal("field")
			}
			rest = rest[size:]
		}
		if len(rest) != 0 {
			t.Fatal("trailing")
		}
		key, _ := ecdh.X25519().GenerateKey(rand.Reader)
		ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), "1"}
		bundle, err := SealCredentialDisplay(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 1, raw)
		if err != nil {
			t.Fatal(err)
		}
		private, _ := hpke.NewDHKEMPrivateKey(key)
		for _, domain := range []string{"wormhole/v1/credential-display", "wormhole/v1/notes-display", "wormhole/v1/protocol-bundle"} {
			info := canonical(domain, []byte(ids[0]), []byte(ids[1]), []byte(ids[2]), []byte(ids[3]))
			recipient, e := hpke.NewRecipient(bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
			if e != nil {
				t.Fatal(e)
			}
			value, e := recipient.Open(nil, bundle.Ciphertext)
			if domain == "wormhole/v1/credential-display" {
				if e != nil || !bytes.Equal(value, raw) {
					t.Fatal("plaintext", e)
				}
			} else if e == nil {
				t.Fatal("wrong domain")
			}
			Wipe(value)
		}
	}
	for _, bad := range []CredentialDisplayPayload{{Username: strings.Repeat("a", 2049)}, {Domain: strings.Repeat("a", 2049)}, {Secret: make([]byte, 16385)}, {Username: string([]byte{255})}, {Domain: string([]byte{255})}, {Secret: []byte{255}}} {
		if _, err := EncodeCredentialDisplay(bad); err != ErrFormat {
			t.Fatal("invalid payload", err)
		}
	}
	if _, err := EncodeCredentialDisplay(CredentialDisplayPayload{}); err != nil {
		t.Fatal("empty", err)
	}
}
