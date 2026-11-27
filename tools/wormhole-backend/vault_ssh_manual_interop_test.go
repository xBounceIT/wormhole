package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Only authenticated public context and ciphertext cross the process boundary.
// The native test recipient independently checks Go/browser canonical encoding.
func TestVaultSSHManualSenderInteropFixture(t *testing.T) {
	scenario := os.Getenv("WORMHOLE_TEST_SSH_MANUAL_INTEROP")
	if scenario == "" {
		t.Skip("SSH manual sender fixture")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := sealedSSHFixtureBinding()
	b.Host = "café.example"
	c := vault.SSHManualContext{Binding: b, Mode: "account", FileID: uuid.NewString(), Revision: strings.Repeat("a", 64), Fingerprint: sealedSSHFixturePayload().Fingerprint, AutoSudo: true}
	if strings.Contains(scenario, "passphrase") {
		c.Mode = "passphrase"
	}
	if scenario == "route" {
		c.Binding.TunnelConfigID = uuid.NewString()
		c.Route = &vault.TunnelBundleBinding{BundleBinding: c.Binding, FileID: c.FileID, Kind: 6, RowVersion: 9223372036854775807, ConfigurationVersion: 9223372036854775806}
		c.Endpoint = "127.0.0.1:2345"
	}
	plan := localvault.SSHManualPlan{Host: localvault.SSHHostPlan{Binding: c.Binding, FileID: c.FileID, Revision: c.Revision, Fingerprint: c.Fingerprint}, Mode: c.Mode, AutoSudo: c.AutoSudo, SFTPOnly: c.SFTPOnly}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"plan": plan, "route": c.Route, "endpoint": c.Endpoint, "publicKey": key.PublicKey().Bytes()}) != nil {
		t.Fatal("context unavailable")
	}
	var inner vault.SealedBundle
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 3*1024*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inner) != nil {
		t.Fatal("invalid sender envelope")
	}
	raw, err := vault.OpenManualSSHCredentials(key.Bytes(), c, inner)
	defer vault.Wipe(raw)
	if scenario == "tamper" {
		if err == nil {
			t.Fatal("substituted context accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		p, e := vault.DecodeSSHManualCredentials(c, raw)
		if e != nil {
			t.Fatal(e)
		}
		if c.Mode == "passphrase" {
			expected := "explicit-override"
			if scenario == "empty-passphrase" {
				expected = ""
			}
			if !bytes.Equal(p.Passphrase, []byte(expected)) || p.Username != "" {
				t.Fatal("manual passphrase changed")
			}
		} else {
			if p.Username != "例-user" || p.Fingerprint != c.Fingerprint || p.AutoSudo || p.SFTPOnly {
				t.Fatal("manual account changed")
			}
			if scenario == "key" || scenario == "certificate" {
				if !bytes.Equal(p.PrivateKey, []byte("document-key")) || !bytes.Equal(p.Passphrase, []byte("key-passphrase")) {
					t.Fatal("manual key changed")
				}
				if scenario == "certificate" && !bytes.Equal(p.Certificate, []byte("document-certificate")) {
					t.Fatal("certificate changed")
				}
			} else if !bytes.Equal(p.Password, []byte("one-use-browser")) {
				t.Fatal("manual password changed")
			}
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack unavailable")
	}
}
