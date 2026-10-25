package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func forcepointSettingsForTest() map[string]any {
	return map[string]any{"Host": "vpn.example.test", "Port": 443, "Username": "fixture-user", "Password": "fixture-password", "Mtu": 1390}
}

func TestForcepointSettingsPersistAndSelectNativeSSLTransport(t *testing.T) {
	settings := forcepointSettingsForTest()
	settings["ServerCertSha256Pin"] = strings.Repeat("a1:", 31) + "a1\n"
	raw, _ := json.Marshal(settings)
	path := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createTunnel(path, tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != 7 || created.Endpoint != "vpn.example.test:443" {
		t.Fatal("Forcepoint metadata did not persist")
	}
	details, err := readTunnel(path, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(details.Settings, &values); err != nil {
		t.Fatal(err)
	}
	if tunnelSettingString(values, "ServerCertSha256Pin") != strings.Repeat("a1", 32) {
		t.Fatal("public certificate pin was not normalized")
	}
	prepared, err := prepareTunnelAuthentication(context.Background(), 7, details.Settings)
	if err != nil {
		t.Fatal(err)
	}
	executable, payload, err := tunnelSidecarCommand(7, prepared)
	if err != nil || executable != "wormhole-ciscoproxy" {
		t.Fatal("native SSL process selection failed", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(payload, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["vpn_protocol"] != "forcepoint-ssl" || cfg["mtu"] != float64(1390) || cfg["port"] != float64(443) || cfg["password"] != "fixture-password" {
		t.Fatal("Forcepoint native process configuration is incomplete")
	}
	for _, unsupported := range []string{"profile_ovpn", "trust_server_certificate", "totp_secret", "secondary_password", "group"} {
		if _, exists := cfg[unsupported]; exists {
			t.Fatal("Forcepoint SSL received an unrelated provider option")
		}
	}
	summaries, err := loadTunnelSummaries(path)
	if err != nil || len(summaries) != 1 || summaries[0].Kind != "Forcepoint" {
		t.Fatal("Forcepoint is missing from the tunnel list", err)
	}
	public, _ := json.Marshal(summaries)
	if bytes.Contains(public, []byte("fixture-password")) || bytes.Contains(public, []byte("fixture-user")) {
		t.Fatal("public tunnel metadata exposed credentials")
	}
}

func TestForcepointSettingsRejectInvalidTransportAndAuthentication(t *testing.T) {
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"Host", ""}, {"Host", "https://vpn.example.test"}, {"Host", "bad host"}, {"Host", strings.Repeat("x", 254)},
		{"Username", ""}, {"Password", ""}, {"Username", strings.Repeat("é", 128)}, {"Password", "a\x00b"},
		{"Port", 0}, {"Port", 65536}, {"Port", "443"},
		{"Mtu", 575}, {"Mtu", 16385}, {"Mtu", 1390.5},
		{"TrustServerCertificate", true}, {"TrustServerCertificate", "true"},
		{"ServerCertSha256Pin", 123}, {"ServerCertSha256Pin", "aa"}, {"ServerCertSha256Pin", strings.Repeat("zz", 32)},
	} {
		settings := forcepointSettingsForTest()
		settings[mutation.key] = mutation.value
		raw, _ := json.Marshal(settings)
		request := tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: raw}
		if err := validateTunnelWriteRequest(&request, false); err == nil {
			t.Fatalf("invalid Forcepoint setting accepted: %s", mutation.key)
		}
	}
	for _, pin := range []any{nil, "", strings.Repeat("ff", 32)} {
		settings := forcepointSettingsForTest()
		settings["ServerCertSha256Pin"] = pin
		delete(settings, "Mtu")
		raw, _ := json.Marshal(settings)
		request := tunnelWriteRequest{Name: "Forcepoint", Kind: 7, Settings: raw}
		if err := validateTunnelWriteRequest(&request, false); err != nil {
			t.Fatal(err)
		}
	}
	if got := tunnelEndpointSummary(7, json.RawMessage(`{"Host":"2001:db8::1"}`)); got != "[2001:db8::1]:443" {
		t.Fatal("Forcepoint endpoint formatting failed")
	}
}

func TestForcepointNativeProcessUsesExistingLeaseLifecycle(t *testing.T) {
	// Use the repository's process fixture: parent configuration still goes over
	// stdin, and the loopback SOCKS endpoint is published only after READY.
	t.Setenv("WORMHOLE_CISCOPROXY_PATH", os.Args[0])
	t.Setenv("WORMHOLE_TUNNEL_TEST_HELPER", "ready")
	settings := forcepointSettingsForTest()
	settings["ServerCertSha256Pin"] = strings.Repeat("a1", 32)
	raw, _ := json.Marshal(settings)
	process, err := startTunnelProcess(context.Background(), tunnelConfigSnapshot{kind: 7, settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	if process.socks != "127.0.0.1:32123" || !process.alive() {
		t.Fatal("Forcepoint process did not publish a supervised SOCKS listener")
	}
	process.close()
	if process.alive() {
		t.Fatal("released Forcepoint process is still alive")
	}
}

func TestForcepointStartupErrorsAreActionableAndSecretFree(t *testing.T) {
	t.Setenv("WORMHOLE_TUNNEL_DEBUG", "")
	for _, test := range []struct{ diagnostic, want string }{
		{"Forcepoint TLS connection failed", "certificate"},
		{"Forcepoint SSVTP version 9 negotiation failed", "SSVTP"},
		{"Forcepoint requires local security checks", "endpoint security"},
		{"Forcepoint endpoint control is unsupported", "endpoint security"},
		{"Forcepoint requires an unsupported authentication challenge", "username and password"},
	} {
		err := tunnelSidecarFailureMessage("wormhole-ciscoproxy", test.diagnostic+" password=fixture-sensitive", 1)
		if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "fixture-sensitive") {
			t.Fatal("Forcepoint startup failure was not safely classified")
		}
	}
}
