package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Public metadata and ciphertext only cross this test process boundary. Its
// private recipient remains in Go, independently checking the browser sender.
func TestVaultVNCManualSenderInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_VNC_MANUAL_INTEROP")
	if mode == "" {
		t.Skip("isolated password sender interop fixture")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := sealedVNCBinding()
	b.Host = "café.example"
	b.Port = 5900
	var route *vault.TunnelBundleBinding
	endpoint := ""
	binding := any(b)
	context := map[string]any{"publicKey": key.PublicKey().Bytes()}
	if mode == "route" {
		b.TunnelConfigID = uuid.NewString()
		route = &vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 9223372036854775807, ConfigurationVersion: 9223372036854775806}
		endpoint = "127.0.0.1:2345"
		binding = *route
		context["endpoint"] = endpoint
	}
	context["binding"] = binding
	if json.NewEncoder(os.Stdout).Encode(context) != nil {
		t.Fatal("context unavailable")
	}
	var sealed vault.SealedBundle
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 64*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&sealed) != nil {
		t.Fatal("invalid sender envelope")
	}
	raw, err := vault.OpenManualVNCPassword(key.Bytes(), b, route, endpoint, sealed)
	defer vault.Wipe(raw)
	if mode == "tamper" {
		if err == nil {
			t.Fatal("substituted browser context accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		payload, err := vault.DecodeVNCBundle(raw)
		expected := []byte("one-use-browser")
		if mode == "empty" {
			expected = nil
		}
		if err != nil || !payload.PasswordProvided || !bytes.Equal(payload.Password, expected) {
			t.Fatal("browser password mismatch")
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack unavailable")
	}
}
