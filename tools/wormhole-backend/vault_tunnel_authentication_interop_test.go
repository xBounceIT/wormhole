package main

import (
	"context"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"io"
	"os"
	"testing"
)

// The fixture exposes public metadata and accepts only an opaque envelope. The
// same independently compiled native decoder verifies Node and Chromium inputs.
func TestVaultTunnelAuthenticationSenderInteropFixture(t *testing.T) {
	mode := os.Getenv("WORMHOLE_TEST_TUNNEL_AUTH_INTEROP")
	if mode == "" {
		t.Skip("isolated VPN factor sender interop fixture")
	}
	route := sealedTunnelBinding()
	route.Kind = 9
	route.Host = "café.example"
	route.RowVersion = 9223372036854775807
	route.ConfigurationVersion = 9223372036854775806
	configuration := []byte(`{"Host":"vpn.test","PreSharedKey":"synthetic-key","UserAuth":1,"Password":"stale-never-used"}`)
	if mode == "fixed" || mode == "browser-fixed" {
		configuration = []byte(`{"Host":"vpn.test","PreSharedKey":"synthetic-key","UserAuth":1,"Username":"fixed-user","Password":"stale-never-used"}`)
	}
	defer vault.Wipe(configuration)
	a, err := newSealedTunnelAuthentication(route, configuration)
	if err != nil || a == nil {
		t.Fatal("native authentication unavailable", err)
	}
	defer a.key.Close()
	b := a.binding
	c := map[string]any{"binding": route, "challengeId": b.ChallengeID, "publicKey": a.public, "usernameRequired": b.UsernameRequired}
	if json.NewEncoder(os.Stdout).Encode(c) != nil {
		t.Fatal("context unavailable")
	}
	var sealed vault.SealedBundle
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16384))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&sealed) != nil {
		t.Fatal("invalid sender envelope")
	}
	a.response <- sealed
	raw, err := a.complete(context.Background(), json.NewEncoder(io.Discard), configuration)
	defer vault.Wipe(raw)
	if mode == "tamper" {
		if err == nil {
			t.Fatal("substituted browser context accepted")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		settings, err := decodeVaultTunnelSettings(raw)
		defer clearTunnelSettingsMap(settings)
		name := "fixed-user"
		if b.UsernameRequired {
			name = "utente-é"
		}
		if err != nil || tunnelSettingString(settings, "Username") != name || tunnelSettingString(settings, "Password") != "one-use-browser" || fortinetUserAuth(settings) != 2 {
			t.Fatal("browser factor mismatch")
		}
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) != nil {
		t.Fatal("ack unavailable")
	}
}
