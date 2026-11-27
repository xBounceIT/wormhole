package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"github.com/google/uuid"
	"testing"
)

func TestClipboardReleaseBindingAndBounds(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), "7"}
	private, _ := hpke.NewDHKEMPrivateKey(key)
	value := []byte("\ufeffalïce🪱")
	for _, field := range []string{"username", "domain", "secret"} {
		for _, ttl := range []int{20, 30} {
			bundle, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 7, field, ttl, value)
			if err != nil {
				t.Fatal(err)
			}
			for _, domain := range []string{"wormhole/v1/clipboard/" + field, "wormhole/v1/credential-display", "wormhole/v1/notes-display", "wormhole/v1/clipboard/privateKey"} {
				for changed := -1; changed < 4; changed++ {
					fields := append([]string{}, ids...)
					if changed >= 0 {
						fields[changed] += "1"
					}
					info := canonical(domain, []byte(fields[0]), []byte(fields[1]), []byte(fields[2]), []byte(fields[3]))
					recipient, err := hpke.NewRecipient(bundle.Enc, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
					if err != nil {
						t.Fatal(err)
					}
					plain, err := recipient.Open(nil, bundle.Ciphertext)
					if changed == -1 && domain == "wormhole/v1/clipboard/"+field {
						if err != nil || !bytes.Equal(plain, append([]byte{1, byte(ttl)}, value...)) {
							t.Fatal("wrong release", err)
						}
					} else if err == nil {
						t.Fatal("context/purpose not authenticated")
					}
					Wipe(plain)
				}
			}
		}
	}
	for _, bad := range [][]byte{nil, {}, {0}, {255}, bytes.Repeat([]byte{'a'}, 16385)} {
		if _, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 7, "secret", 20, bad); err != ErrFormat {
			t.Fatal("value bounds", err)
		}
	}
	for _, field := range []string{"", "privateKey"} {
		if _, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 7, field, 20, value); err != ErrFormat {
			t.Fatal("field", err)
		}
	}
	for _, ttl := range []int{-1, 0, 21, 256} {
		if _, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 7, "secret", ttl, value); err != ErrFormat {
			t.Fatal("ttl", err)
		}
	}
	if _, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 7, "secret", 20, bytes.Repeat([]byte{'a'}, 16384)); err != nil {
		t.Fatal("max", err)
	}
	for _, public := range [][]byte{nil, make([]byte, 32)} {
		if _, err := SealClipboardRelease(public, ids[0], ids[1], ids[2], 7, "secret", 20, value); err == nil {
			t.Fatal("key")
		}
	}
	if _, err := SealClipboardRelease(key.PublicKey().Bytes(), "bad", ids[1], ids[2], 7, "secret", 20, value); err == nil {
		t.Fatal("id")
	}
	if _, err := SealClipboardRelease(key.PublicKey().Bytes(), ids[0], ids[1], ids[2], 0, "secret", 20, value); err == nil {
		t.Fatal("revision")
	}
}
