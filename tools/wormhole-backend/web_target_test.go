package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestResolveWebTargetResolvesInheritedHTTPSettings(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, HttpIgnoreCertErrors) VALUES
    ('folder', NULL, 'Appliances', 0, 4, 'firewall.example.test', 8443, 0, 1),
    ('web', 'folder', 'Firewall', 1, NULL, NULL, NULL, NULL, 0);`)

	target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve web target: %v", err)
	}
	if target.URL != "https://firewall.example.test:8443/" {
		t.Fatalf("unexpected URL: %q", target.URL)
	}
	if target.Protocol != "https" || target.Host != "firewall.example.test" || target.Port != 8443 {
		t.Fatalf("unexpected target metadata: %#v", target)
	}
	// The certificate opt-in is deliberately leaf-only, even when all other target settings inherit.
	if target.IgnoreCertErrors {
		t.Fatalf("certificate bypass inherited from a folder: %#v", target)
	}
}

func TestResolveWebTargetUsesLeafCertificateOptInAndDefaultPort(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, HttpIgnoreCertErrors) VALUES
    ('web', NULL, 'Firewall', 1, 4, 'fd00::1', NULL, 0, 1);`)

	target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve web target: %v", err)
	}
	if target.URL != "https://[fd00::1]:443/" || target.Port != 443 || !target.IgnoreCertErrors {
		t.Fatalf("unexpected HTTPS target: %#v", target)
	}
}

func TestResolveWebTargetDropsCrossProtocolInheritedPort(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, HttpIgnoreCertErrors) VALUES
    ('folder', NULL, 'RDP hosts', 0, 1, 'gateway.example.test', 3389, 0, 0),
    ('web', 'folder', 'Gateway UI', 1, 3, NULL, NULL, NULL, 0);`)

	target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve web target: %v", err)
	}
	if target.URL != "http://gateway.example.test:80/" || target.Port != 80 {
		t.Fatalf("cross-protocol folder port leaked into web target: %#v", target)
	}
}

func TestResolveWebTargetReturnsInheritedTunnelForNativeController(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, TunnelConfigId, HttpIgnoreCertErrors) VALUES
    ('web', NULL, 'Private UI', 1, 4, 'private.example.test', 443, 1, '11111111-2222-3333-4444-555555555555', 0);`)

	target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve tunneled web target: %v", err)
	}
	if target.TunnelConfigID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("tunnel inheritance was not preserved: %#v", target)
	}
}

func TestResolveWebTargetRejectsEnabledTunnelWithoutConfig(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, TunnelConfigId, HttpIgnoreCertErrors) VALUES
    ('web', NULL, 'Private UI', 1, 4, 'private.example.test', 443, 1, NULL, 0);`)

	_, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err == nil || !strings.Contains(err.Error(), "no tunnel") {
		t.Fatalf("expected a missing tunnel error, got %v", err)
	}
}

func TestBuildWebURLRejectsEmbeddedPortAndPath(t *testing.T) {
	for _, host := range []string{"firewall.example.test:8443", "firewall.example.test/path", "firewall example.test", "firewall\x01example.test"} {
		if _, err := buildWebURL("https", host, 443); err == nil {
			t.Fatalf("accepted invalid host %q", host)
		}
	}
}

func TestBuildWebURLValidatesProtocolPortAndIPv6Brackets(t *testing.T) {
	if value, err := buildWebURL("https", "[fd00::1]", 8443); err != nil || value != "https://[fd00::1]:8443/" {
		t.Fatalf("bracketed IPv6 URL = %q, %v", value, err)
	}
	for _, test := range []struct {
		name   string
		scheme string
		host   string
		port   int
	}{
		{name: "protocol", scheme: "ftp", host: "example.test", port: 443},
		{name: "empty host", scheme: "https", host: "", port: 443},
		{name: "non IPv6 brackets", scheme: "https", host: "[example.test]", port: 443},
		{name: "invalid colon host", scheme: "https", host: "not:an:ip", port: 443},
		{name: "zero port", scheme: "https", host: "example.test", port: 0},
		{name: "oversized port", scheme: "https", host: "example.test", port: 65536},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildWebURL(test.scheme, test.host, test.port); err == nil {
				t.Fatal("invalid web URL was accepted")
			}
		})
	}
}

func TestParseWebAddressCoversLegacyAddressForms(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		host string
		port int
	}{
		{name: "HTTP URL", raw: "http://example.test/admin?q=1", host: "example.test"},
		{name: "host", raw: "example.test", host: "example.test"},
		{name: "host and port", raw: "example.test:8443", host: "example.test", port: 8443},
		{name: "bare IPv6", raw: "fd00::1", host: "fd00::1"},
		{name: "bracketed IPv6", raw: "[fd00::1]", host: "fd00::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := parseWebAddress(test.raw)
			if err != nil || host != test.host || port != test.port {
				t.Fatalf("parseWebAddress(%q) = %q, %d, %v", test.raw, host, port, err)
			}
		})
	}

	for _, raw := range []string{
		"https://",
		"[",
		"[example.test]",
		"[fd00::1]suffix",
		"[fd00::1]:invalid",
		":443",
		"not:an:ipv6",
	} {
		if _, _, err := parseWebAddress(raw); err == nil {
			t.Fatalf("parseWebAddress accepted %q", raw)
		}
	}
}

func TestResolvedProtocolForWebNodeHandlesInheritanceAndCycles(t *testing.T) {
	const expectedProtocol = int64(4)
	folder := &webNode{ID: "folder", Protocol: sql.NullInt64{Int64: expectedProtocol, Valid: true}}
	leaf := &webNode{ID: "leaf", ParentID: sql.NullString{String: "folder", Valid: true}}
	nodes := map[string]*webNode{"folder": folder, "leaf": leaf}
	protocol, err := resolvedProtocolForWebNode(leaf, nodes)
	if err != nil || !protocol.Valid || protocol.Int64 != expectedProtocol {
		t.Fatalf("inherited protocol = %#v, %v", protocol, err)
	}

	orphan := &webNode{ID: "orphan", ParentID: sql.NullString{String: "missing", Valid: true}}
	if protocol, err := resolvedProtocolForWebNode(orphan, nodes); err != nil || protocol.Valid {
		t.Fatalf("orphan protocol = %#v, %v", protocol, err)
	}

	first := &webNode{ID: "first", ParentID: sql.NullString{String: "second", Valid: true}}
	second := &webNode{ID: "second", ParentID: sql.NullString{String: "first", Valid: true}}
	if _, err := resolvedProtocolForWebNode(first, map[string]*webNode{"first": first, "second": second}); err == nil {
		t.Fatal("web node cycle was accepted")
	}
}

func TestResolveWebTargetParsesQuickConnectAddressInGo(t *testing.T) {
	target, err := resolveWebTarget("", webTargetRequest{
		Address:          "https://[fd00::1]:8443/admin?from=bookmark",
		Protocol:         "http",
		IgnoreCertErrors: true,
	})
	if err != nil {
		t.Fatalf("resolve direct web target: %v", err)
	}
	if target.URL != "http://[fd00::1]:8443/" || target.Protocol != "http" || target.Port != 8443 {
		t.Fatalf("unexpected direct target: %#v", target)
	}
	if target.IgnoreCertErrors {
		t.Fatalf("HTTP target retained an HTTPS-only certificate bypass: %#v", target)
	}
}

func TestResolveWebTargetUsesQuickConnectPortField(t *testing.T) {
	target, err := resolveWebTarget("", webTargetRequest{
		Address: "[fd00::1]:9443", Port: 8443, Protocol: "https",
	})
	if err != nil {
		t.Fatalf("resolve direct web target with explicit port: %v", err)
	}
	if target.URL != "https://[fd00::1]:8443/" || target.Port != 8443 {
		t.Fatalf("explicit quick-connect port was ignored: %#v", target)
	}
}

func TestResolveWebTargetRejectsPortOverrideForSavedNode(t *testing.T) {
	if _, err := resolveWebTarget("ignored.db", webTargetRequest{NodeID: "web", Port: 8443}); err == nil {
		t.Fatal("saved web target accepted a direct port override")
	}
}

func TestResolveWebTargetPreservesQuickConnectTunnel(t *testing.T) {
	const tunnelID = "11111111-2222-3333-4444-555555555555"
	target, err := resolveWebTarget("", webTargetRequest{
		Address:        "private.example.test:8443",
		Protocol:       "https",
		TunnelConfigID: tunnelID,
	})
	if err != nil {
		t.Fatalf("resolve direct web target with tunnel: %v", err)
	}
	if target.TunnelConfigID != tunnelID {
		t.Fatalf("quick-connect tunnel was not preserved: %#v", target)
	}
}

func TestResolveWebTargetRejectsInvalidQuickConnectTunnel(t *testing.T) {
	if _, err := resolveWebTarget("", webTargetRequest{
		Address:        "private.example.test",
		Protocol:       "https",
		TunnelConfigID: "not-a-uuid",
	}); err == nil {
		t.Fatal("invalid quick-connect tunnel was accepted")
	}
}

func TestResolveWebTargetRejectsMalformedQuickConnectAddress(t *testing.T) {
	for _, address := range []string{":8443", "firewall.example.test:99999", "admin@firewall.example.test", "firewall example.test"} {
		if _, err := resolveWebTarget("", webTargetRequest{Address: address, Protocol: "https"}); err == nil {
			t.Fatalf("accepted invalid direct address %q", address)
		}
	}
}

func TestUpdateWorkspaceNodeWebSettingsStoresLeafCertificateOptIn(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, HttpIgnoreCertErrors) VALUES
    ('web', NULL, 'Firewall', 1, 4, 'firewall.example.test', 443, 0, NULL);`)
	value := true
	if err := updateWorkspaceNodeWebSettings(databasePath, workspaceNodeWebSettingsRequest{
		NodeID:               "web",
		HTTPIgnoreCertErrors: &value,
	}); err != nil {
		t.Fatalf("enable certificate opt-in: %v", err)
	}

	target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve web target: %v", err)
	}
	if !target.IgnoreCertErrors {
		t.Fatalf("certificate opt-in was not persisted: %#v", target)
	}

	if err := updateWorkspaceNodeWebSettings(databasePath, workspaceNodeWebSettingsRequest{NodeID: "web"}); err != nil {
		t.Fatalf("clear certificate opt-in: %v", err)
	}
	target, err = resolveWebTarget(databasePath, webTargetRequest{NodeID: "web"})
	if err != nil {
		t.Fatalf("resolve web target after clear: %v", err)
	}
	if target.IgnoreCertErrors {
		t.Fatalf("certificate opt-in was not cleared: %#v", target)
	}
}

func TestUpdateWorkspaceNodeWebSettingsRejectsCertificateBypassForHTTP(t *testing.T) {
	databasePath := createWebTargetDatabase(t, `
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, Port, TunnelEnabled, HttpIgnoreCertErrors) VALUES
    ('web', NULL, 'Plain web', 1, 3, 'web.example.test', 80, 0, NULL);`)
	value := true
	err := updateWorkspaceNodeWebSettings(databasePath, workspaceNodeWebSettingsRequest{
		NodeID:               "web",
		HTTPIgnoreCertErrors: &value,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected an HTTPS-only error, got %v", err)
	}
}

func createWebTargetDatabase(t *testing.T, seed string) string {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
    TunnelEnabled INTEGER NULL,
    TunnelConfigId TEXT NULL,
    HttpIgnoreCertErrors INTEGER NULL,
    UpdatedAt TEXT NOT NULL DEFAULT ''
);`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := database.Exec(seed); err != nil {
		t.Fatalf("seed database: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	return databasePath
}
