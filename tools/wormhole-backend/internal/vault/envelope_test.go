package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testBinding() Binding {
	return Binding{"workspace", "SecretValues", "credential", "password", "dek", 1}
}
func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }
func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnvelopeRoundTripAndAAD(t *testing.T) {
	key, binding := testKey(), testBinding()
	for _, plaintext := range [][]byte{nil, []byte("saved-password"), make([]byte, MaxSecretBytes)} {
		env, err := Seal(key, binding, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		var restored Envelope
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		actual, err := Open(key, binding, restored)
		if err != nil || !bytes.Equal(actual, plaintext) {
			t.Fatalf("round trip: %v", err)
		}
	}
	env, _ := Seal(key, binding, []byte("secret"))
	second, _ := Seal(key, binding, []byte("secret"))
	if bytes.Equal(env.Nonce, second.Nonce) {
		t.Fatal("nonce reuse")
	}
	for name, mutate := range map[string]func(*Binding){
		"workspace": func(b *Binding) { b.WorkspaceID = "other" },
		"table":     func(b *Binding) { b.Table = "Nodes" },
		"owner":     func(b *Binding) { b.OwnerID = "other" },
		"field":     func(b *Binding) { b.Field = "token" },
		"key":       func(b *Binding) { b.KeyID = "other" },
		"version":   func(b *Binding) { b.KeyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			b := binding
			mutate(&b)
			if _, err := Open(key, b, env); err == nil {
				t.Fatal("cross-record ciphertext accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Envelope){
		"version":  func(e *Envelope) { e.FormatVersion = 0 },
		"future":   func(e *Envelope) { e.FormatVersion++ },
		"suite":    func(e *Envelope) { e.SuiteID++ },
		"nonce":    func(e *Envelope) { e.Nonce = []byte{1} },
		"tag":      func(e *Envelope) { e.Ciphertext = make([]byte, 16) },
		"short":    func(e *Envelope) { e.Ciphertext = nil },
		"oversize": func(e *Envelope) { e.Ciphertext = make([]byte, MaxSecretBytes+17) },
	} {
		t.Run(name, func(t *testing.T) {
			e := env
			mutate(&e)
			if _, err := Open(key, binding, e); err == nil {
				t.Fatal("modified envelope accepted")
			}
		})
	}
	if _, err := Open(bytes.Repeat([]byte{1}, 32), binding, env); err != ErrAuthentication {
		t.Fatal("wrong key accepted")
	}
}

func TestEnvelopeBoundsAndCanonicalAmbiguity(t *testing.T) {
	for _, binding := range []Binding{{}, {"a", "b", "c", "d", "e", 0}, {strings.Repeat("a", MaxContextBytes+1), "b", "c", "d", "e", 1}} {
		if _, err := Seal(testKey(), binding, nil); err != ErrFormat {
			t.Fatal("invalid binding accepted")
		}
	}
	if _, err := Seal(nil, testBinding(), nil); err != ErrFormat {
		t.Fatal("invalid key accepted")
	}
	if _, err := Seal(testKey(), testBinding(), make([]byte, MaxSecretBytes+1)); err != ErrFormat {
		t.Fatal("oversized secret accepted")
	}
	if bytes.Equal(canonical("d", []byte("ab"), []byte("c")), canonical("d", []byte("a"), []byte("bc"))) {
		t.Fatal("ambiguous encoding")
	}
	env, _ := Seal(testKey(), testBinding(), nil)
	if _, err := Open(nil, testBinding(), env); err != ErrFormat {
		t.Fatal("invalid open key accepted")
	}
}

func TestAES256GCMKnownAnswerAndExternalEnvelope(t *testing.T) {
	// NIST empty plaintext, zero AES-256 key and 96-bit zero IV.
	aead, err := gcm(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if got := aead.Seal(nil, make([]byte, 12), nil, nil); !bytes.Equal(got, mustHex(t, "530f8afbc74536b9a963b4f1c4cb738b")) {
		t.Fatal("NIST vector mismatch")
	}
	// Independently build an envelope using the published v1 encoding.
	block, _ := aes.NewCipher(testKey())
	external, _ := cipher.NewGCM(block)
	aad := []byte("wormhole/v1/envelope")
	for _, v := range [][]byte{{0, 1}, {0, 1}, []byte("workspace"), []byte("SecretValues"), []byte("credential"), []byte("password"), []byte("dek"), {0, 0, 0, 1}} {
		aad = append(aad, 0, 0, 0, byte(len(v)))
		aad = append(aad, v...)
	}
	nonce := make([]byte, 12)
	env := Envelope{1, 1, "dek", 1, nonce, external.Seal(nil, nonce, []byte("interop"), aad)}
	if got, err := Open(testKey(), testBinding(), env); err != nil || string(got) != "interop" {
		t.Fatalf("interop: %v", err)
	}
}

func FuzzEnvelopeOpen(f *testing.F) {
	env, _ := Seal(testKey(), testBinding(), []byte("seed"))
	encoded, _ := json.Marshal(env)
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxSecretBytes+1024 {
			return
		}
		var e Envelope
		if json.Unmarshal(data, &e) == nil {
			_, _ = Open(testKey(), testBinding(), e)
		}
	})
}
