package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Public metadata and ciphertext only cross this test process boundary. Its
// private recipient remains in Go, independently checking the browser sender.
func TestVaultRDPManualSenderInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_RDP_MANUAL_INTEROP")
	if mode == "" {
		t.Skip("isolated password sender interop fixture")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := sealedRDPFixtureBinding()
	b.Host = "café.example"
	b.Port = 3389
	var route *vault.TunnelBundleBinding
	endpoint := ""
	binding := any(b)
	packet := map[string]any{"publicKey": key.PublicKey().Bytes()}
	if mode == "route" {
		b.TunnelConfigID = uuid.NewString()
		route = &vault.TunnelBundleBinding{BundleBinding: b, FileID: uuid.NewString(), Kind: 6, RowVersion: 9223372036854775807, ConfigurationVersion: 9223372036854775806}
		endpoint = "127.0.0.1:2345"
		binding = *route
		packet["endpoint"] = endpoint
	}
	if strings.HasPrefix(mode, "service") {
		b, route, endpoint = prepareRDPManualServiceFixture(t, mode)
		binding = b
		if route != nil {
			binding = *route
			packet["endpoint"] = endpoint
		}
	}
	packet["binding"] = binding
	if json.NewEncoder(os.Stdout).Encode(packet) != nil {
		t.Fatal("context unavailable")
	}
	var sealed vault.SealedBundle
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 64*1024))
	decoder.DisallowUnknownFields()
	if strings.HasPrefix(mode, "service") {
		var result localvault.RoutedRDPConnectionBundle
		if decoder.Decode(&result) != nil {
			t.Fatal("invalid service bundle")
		}
		var raw []byte
		if route == nil {
			raw, err = vault.OpenBundle(key.Bytes(), b, result.Bundle)
		} else {
			if result.Binding != *route || result.Endpoint != endpoint {
				t.Fatal("service route changed")
			}
			raw, err = vault.OpenRoutedBundle(key.Bytes(), *route, endpoint, result.Bundle)
		}
		defer vault.Wipe(raw)
		if err != nil {
			t.Fatal(err)
		}
		base, inner, e := vault.DecodeRDPManualAuthorization(raw)
		if e != nil || base.PasswordProvided || base.Username != "" || base.Settings.Domain != "" {
			t.Fatal("service saved fallback", e)
		}
		sealed = inner
	} else if decoder.Decode(&sealed) != nil {
		t.Fatal("invalid sender envelope")
	}
	raw, err := vault.OpenManualRDPCredentials(key.Bytes(), b, route, endpoint, sealed)
	defer vault.Wipe(raw)
	if mode == "tamper" {
		if err == nil {
			t.Fatal("substituted browser context accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		payload, err := vault.DecodeRDPManualCredentials(raw)
		expected := []byte("one-use-browser")
		if mode == "empty" {
			expected = nil
		}
		if err != nil || payload.Username != "manual-browser-user" || payload.Domain != "MANUAL-DOMAIN" || !bytes.Equal(payload.Password, expected) {
			t.Fatal("browser password mismatch")
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack unavailable")
	}
}

// The service owner opens the real SQLite database after this writer closes.
// Only identifiers/public recipient data leave this native test process.
func prepareRDPManualServiceFixture(t *testing.T, mode string) (vault.BundleBinding, *vault.TunnelBundleBinding, string) {
	t.Helper()
	doc, root := localSlotFixture(t)
	defer vault.Wipe(root)
	doc.Initializing = true
	ctx := context.Background()
	owner, err := initializeVaultFiles(ctx, os.Getenv("WORMHOLE_TEST_RDP_MANUAL_DATABASE"), doc, root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	credential, err := owner.PutCredential(ctx, vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Unselected account", Protocol: "rdp", Kind: "password", Provider: "local", Username: `AzureAD\saved-user`, Domain: "AzureAD"}, []localvault.SecretChange{{Field: "password", Value: []byte("saved-primary-not-selected")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	host, port, protocol, selected := "café.example", 3389, 1, 2
	metadata := vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Manual RDP", Kind: 1, Protocol: &protocol, Host: &host, Port: &port, CredentialID: &credential.ID, CredentialMode: &selected}
	if mode == "service-route" {
		tunnel, e := owner.PutTunnel(ctx, vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "RDP fixture VPN", Kind: 6}, []byte(`{"Host":"gateway.invalid","Username":"vpn-user","Password":"route-not-selected"}`), 0)
		if e != nil {
			t.Fatal(e)
		}
		enabled := true
		metadata.TunnelEnabled, metadata.TunnelConfigID = &enabled, &tunnel.ID
	}
	if _, err = owner.PutNode(ctx, metadata, nil, 0); err != nil {
		t.Fatal(err)
	}
	q := localvault.TunnelPlanRequest{NodeID: metadata.ID, SessionID: uuid.NewString(), RequestID: uuid.NewString(), Epoch: 1}
	if mode == "service-route" {
		route, e := owner.ResolveConnectionRoute(ctx, q)
		if e != nil || route == nil {
			t.Fatal("fixture route", e)
		}
		return route.BundleBinding, route, "127.0.0.1:2345"
	}
	binding, e := owner.PlanRDPConnection(ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	return binding, nil, ""
}
