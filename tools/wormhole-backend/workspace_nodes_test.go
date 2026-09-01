package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func createWorkspaceNodeTestSchema(t *testing.T, databasePath string) {
	t.Helper()
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    Port INTEGER NULL,
	Username TEXT NULL,
	CredentialId TEXT NULL,
	CredentialMode INTEGER NULL,
	UseInlinePassword INTEGER NULL,
    SshAutoSudo INTEGER NULL,
    HttpIgnoreCertErrors INTEGER NULL,
    HttpPath TEXT NULL,
    TunnelEnabled INTEGER NULL,
    TunnelConfigId TEXT NULL,
    SerialBaudRate INTEGER NULL,
    SerialDataBits INTEGER NULL,
    SerialStopBits INTEGER NULL,
    SerialParity INTEGER NULL,
    SerialFlowControl INTEGER NULL,
	RdpDomain TEXT NULL,
	RdpScreenSize TEXT NULL,
	RdpFullScreen INTEGER NULL,
	RdpColorDepth INTEGER NULL,
	RdpUseAllMonitors INTEGER NULL,
	RdpAudioMode INTEGER NULL,
	RdpAudioCaptureMode INTEGER NULL,
	RdpKeyboardHookMode INTEGER NULL,
	RdpRedirectClipboard INTEGER NULL,
	RdpRedirectPrinters INTEGER NULL,
	RdpRedirectSmartCards INTEGER NULL,
	RdpRedirectPorts INTEGER NULL,
	RdpRedirectDevices INTEGER NULL,
	RdpRedirectDrives TEXT NULL,
	RdpConnectionSpeed INTEGER NULL,
	RdpDesktopBackground INTEGER NULL,
	RdpFontSmoothing INTEGER NULL,
	RdpDesktopComposition INTEGER NULL,
	RdpWindowDrag INTEGER NULL,
	RdpMenuAnimation INTEGER NULL,
	RdpVisualStyles INTEGER NULL,
	RdpBitmapCaching INTEGER NULL,
	RdpAutoReconnect INTEGER NULL,
	RdpServerAuthentication INTEGER NULL,
	RdpGatewayUsageMethod INTEGER NULL,
	RdpGatewayHostname TEXT NULL,
	RdpGatewayCredentialId TEXT NULL,
	RdpGatewayBypassLocal INTEGER NULL,
	RdpGatewayUseSameCreds INTEGER NULL,
	RdpUseExternalClient INTEGER NULL,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
	Username TEXT NULL,
	Domain TEXT NULL,
	Protocol INTEGER NOT NULL,
	Kind INTEGER NOT NULL DEFAULT 0,
	SecretProvider INTEGER NOT NULL DEFAULT 0
);
	CREATE TABLE CredentialSecrets (Id TEXT PRIMARY KEY, Secret TEXT NOT NULL, Encoding TEXT NOT NULL, UpdatedAt TEXT);
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL DEFAULT '',
    Kind INTEGER NOT NULL DEFAULT 0
);`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceNodeUpdateReloadsLegacyTunnelRoute(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	const storedTunnelID = "B2A0A6B0-69C8-4F3E-A4CB-F3395AA0A9F7"
	const canonicalTunnelID = "b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7"

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(
		"INSERT INTO TunnelConfigs (Id, Name, Kind) VALUES (?, 'Legacy VPN', 0);",
		storedTunnelID,
	); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "SSH", Kind: "connection", Protocol: "ssh", Host: "target.example",
		CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelEnabled := true
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "SSH", Kind: "connection", Protocol: "ssh", Host: "target.example",
		CredentialMode: 0, TunnelEnabled: &tunnelEnabled, TunnelConfigID: storedTunnelID,
	}); err != nil {
		t.Fatal(err)
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tree, err := loadTree(database)
	if err != nil {
		t.Fatal(err)
	}
	tunnels, err := loadTunnels(database)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 1 || tree[0].TunnelConfigID != canonicalTunnelID {
		t.Fatalf("reloaded route = %#v, want %q", tree, canonicalTunnelID)
	}
	if len(tunnels) != 1 || tunnels[0].ID != tree[0].TunnelConfigID {
		t.Fatalf("reloaded tunnels = %#v, want route id %q", tunnels, tree[0].TunnelConfigID)
	}
}

func TestWorkspaceNodeCreatePersistsVirtualBitwardenCredential(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	if _, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{{
		ID: "vault-item", Name: "Production", Username: "root",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Servers", Kind: "folder", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialID := bitwardenVirtualCredentialID("vault-item", 0)
	autoSudo := true
	connectionID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ParentID:       folderID,
		Name:           "Gateway",
		Kind:           "connection",
		Protocol:       "ssh",
		Host:           "gateway.example.com:2222",
		SshAutoSudo:    &autoSudo,
		CredentialMode: 2,
		CredentialID:   credentialID,
	})
	if err != nil {
		t.Fatal(err)
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var parentID, host, storedCredentialID string
	var port sql.NullInt64
	var credentialMode, sshAutoSudo int64
	if err := database.QueryRow(`
SELECT ParentId, Host, Port, CredentialMode, CredentialId, SshAutoSudo
FROM Nodes WHERE Id = ?;`, connectionID).Scan(
		&parentID, &host, &port, &credentialMode, &storedCredentialID, &sshAutoSudo,
	); err != nil {
		t.Fatal(err)
	}
	if parentID != folderID || host != "gateway.example.com:2222" || port.Valid {
		t.Fatalf("unexpected target persisted: parent=%q host=%q port=%+v", parentID, host, port)
	}
	if credentialMode != 2 || storedCredentialID != credentialID || sshAutoSudo != 1 {
		t.Fatalf("credential settings were not persisted: mode=%d id=%q sudo=%d", credentialMode, storedCredentialID, sshAutoSudo)
	}
}

func TestWorkspaceNodeCreatePersistsCustomPortsForNetworkProtocols(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)

	tests := []struct {
		protocol string
		port     int
	}{
		{protocol: "ssh", port: 2222},
		{protocol: "rdp", port: 3390},
		{protocol: "http", port: 8080},
		{protocol: "https", port: 8443},
		{protocol: "vnc", port: 5901},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
				Name: test.protocol, Kind: "connection", Protocol: test.protocol,
				Host: "target.example", Port: test.port, CredentialMode: 0,
			})
			if err != nil {
				t.Fatal(err)
			}

			database, err := openDatabase(databasePath, false)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			var port int
			if err := database.QueryRow("SELECT Port FROM Nodes WHERE Id = ?;", nodeID).Scan(&port); err != nil {
				t.Fatal(err)
			}
			if port != test.port {
				t.Fatalf("stored custom port %d, want %d", port, test.port)
			}
		})
	}
}

func TestWorkspaceNodeCreateAndUpdatePersistsWebContextPath(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)

	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Admin", Kind: "connection", Protocol: "https",
		Host: "https://target.example:8443/admin/dashboard?tab=network#routes", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStoredWebTarget := func(wantHost string, wantPort int, wantPath, wantURL string) {
		t.Helper()
		database, err := openDatabase(databasePath, true)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		var host, httpPath string
		var port int
		if err := database.QueryRow("SELECT Host, Port, HttpPath FROM Nodes WHERE Id = ?;", nodeID).Scan(&host, &port, &httpPath); err != nil {
			t.Fatal(err)
		}
		if host != wantHost || port != wantPort || httpPath != wantPath {
			t.Fatalf("stored web target = %q, %d, %q", host, port, httpPath)
		}
		tree, err := loadTree(database)
		if err != nil {
			t.Fatal(err)
		}
		if len(tree) != 1 || tree[0].HTTPPath != wantPath {
			t.Fatalf("workspace snapshot lost the web context path: %#v", tree)
		}
		target, err := resolveWebTarget(databasePath, webTargetRequest{NodeID: nodeID})
		if err != nil {
			t.Fatal(err)
		}
		if target.URL != wantURL {
			t.Fatalf("resolved web URL = %q, want %q", target.URL, wantURL)
		}
	}

	assertStoredWebTarget(
		"target.example",
		8443,
		"/admin/dashboard?tab=network#routes",
		"https://target.example:8443/admin/dashboard?tab=network#routes",
	)
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Admin", Kind: "connection", Protocol: "https",
		Host: "target.example/operations", Port: 9443, CredentialMode: 0,
	}); err != nil {
		t.Fatal(err)
	}
	assertStoredWebTarget(
		"target.example",
		9443,
		"/operations",
		"https://target.example:9443/operations",
	)
}

func TestWorkspaceNodeCreateAllowsBlankManualCredentials(t *testing.T) {
	for _, protocol := range []string{"ssh", "rdp"} {
		t.Run(protocol, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			createWorkspaceNodeTestSchema(t, databasePath)
			request := workspaceNodeWriteRequest{
				Name: protocol, Kind: "connection", Protocol: protocol, Host: "target.example",
				CredentialMode: 1, InlinePasswordAction: "clear",
			}
			if protocol == "rdp" {
				settings := defaultWorkspaceRdpSettings()
				request.RDP = &settings
			}

			nodeID, err := createWorkspaceNode(databasePath, request)
			if err != nil {
				t.Fatal(err)
			}

			database, err := openDatabase(databasePath, false)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			var username, credentialID sql.NullString
			var credentialMode, useInlinePassword, secretCount int
			if err := database.QueryRow(`
SELECT Username, CredentialId, CredentialMode, UseInlinePassword,
       (SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = lower(Nodes.Id))
FROM Nodes WHERE Id = ?;`, nodeID).Scan(
				&username, &credentialID, &credentialMode, &useInlinePassword, &secretCount,
			); err != nil {
				t.Fatal(err)
			}
			if username.Valid || credentialID.Valid || credentialMode != 1 || useInlinePassword != 0 || secretCount != 0 {
				t.Fatalf(
					"blank manual credentials = user=%#v id=%#v mode=%d inline=%d secrets=%d",
					username, credentialID, credentialMode, useInlinePassword, secretCount,
				)
			}
		})
	}
}

func TestWorkspaceNodeUpdateClearsInlinePasswordForBlankManualCredentials(t *testing.T) {
	for _, protocol := range []string{"ssh", "rdp"} {
		t.Run(protocol, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			createWorkspaceNodeTestSchema(t, databasePath)
			request := workspaceNodeWriteRequest{
				Name: protocol, Kind: "connection", Protocol: protocol, Host: "target.example",
				Username: "operator", InlinePasswordAction: "set", InlinePassword: "secret",
			}
			if protocol == "rdp" {
				settings := defaultWorkspaceRdpSettings()
				request.RDP = &settings
			}

			nodeID, err := createWorkspaceNode(databasePath, request)
			if err != nil {
				t.Fatal(err)
			}
			request.ID = nodeID
			request.Username = ""
			request.InlinePasswordAction = "clear"
			request.InlinePassword = ""
			request.CredentialMode = 1
			if err := updateWorkspaceNode(databasePath, request); err != nil {
				t.Fatal(err)
			}

			database, err := openDatabase(databasePath, false)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			var username, credentialID sql.NullString
			var credentialMode, useInlinePassword, secretCount int
			if err := database.QueryRow(`
SELECT Username, CredentialId, CredentialMode, UseInlinePassword,
       (SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = lower(Nodes.Id))
FROM Nodes WHERE Id = ?;`, nodeID).Scan(
				&username, &credentialID, &credentialMode, &useInlinePassword, &secretCount,
			); err != nil {
				t.Fatal(err)
			}
			if username.Valid || credentialID.Valid || credentialMode != 1 || useInlinePassword != 0 || secretCount != 0 {
				t.Fatalf(
					"cleared manual credentials = user=%#v id=%#v mode=%d inline=%d secrets=%d",
					username, credentialID, credentialMode, useInlinePassword, secretCount,
				)
			}
		})
	}
}

func TestWorkspaceNodeCreateRejectsInvalidNetworkPorts(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)

	for _, port := range []int{-1, 65536} {
		if _, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
			Name: "SSH", Kind: "connection", Protocol: "ssh", Host: "target.example", Port: port,
		}); err == nil {
			t.Fatalf("accepted invalid network port %d", port)
		}
	}
	if _, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Serial", Kind: "connection", Protocol: "serial", Host: "COM1", Port: 9600,
		SerialBaudRate: 9600, SerialDataBits: 8, SerialStopBits: 1,
	}); err == nil {
		t.Fatal("accepted a network port for a serial connection")
	}
}

func TestWorkspaceNodeUpdatePreservesCustomPortAndHiddenLegacyFields(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "SSH", Kind: "connection", Protocol: "ssh", Host: "target.example",
		Port: 2222, CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("ALTER TABLE Nodes ADD COLUMN LegacyOpaque TEXT NULL;"); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(
		"UPDATE Nodes SET RdpDomain = 'hidden-domain', RdpGatewayHostname = 'hidden-gateway', LegacyOpaque = 'keep-me' WHERE Id = ?;",
		nodeID,
	); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Renamed SSH", Kind: "connection", Protocol: "ssh",
		Host: "target.example", Port: 2222, CredentialMode: 0, InlinePasswordAction: "clear",
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var port int
	var domain, gateway, opaque string
	if err := database.QueryRow(
		"SELECT Port, RdpDomain, RdpGatewayHostname, LegacyOpaque FROM Nodes WHERE Id = ?;",
		nodeID,
	).Scan(&port, &domain, &gateway, &opaque); err != nil {
		t.Fatal(err)
	}
	if port != 2222 || domain != "hidden-domain" || gateway != "hidden-gateway" || opaque != "keep-me" {
		t.Fatalf("partial edit clobbered persisted fields: port=%d domain=%q gateway=%q opaque=%q", port, domain, gateway, opaque)
	}
}

func TestWorkspaceNodeUpdateIsAtomicWhenCredentialProtocolDoesNotMatch(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	credentialID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO CredentialProfiles (Id, Protocol) VALUES (?, 1);", credentialID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	connectionID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Original", Kind: "connection", Protocol: "ssh", Host: "host.example", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: connectionID, Name: "Changed", Kind: "connection", Protocol: "ssh", Host: "changed.example",
		CredentialMode: 2, CredentialID: credentialID,
	})
	if err == nil {
		t.Fatal("protocol-mismatched credential was accepted")
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name, host string
	var credentialIDAfter sql.NullString
	if err := database.QueryRow("SELECT Name, Host, CredentialId FROM Nodes WHERE Id = ?;", connectionID).
		Scan(&name, &host, &credentialIDAfter); err != nil {
		t.Fatal(err)
	}
	if name != "Original" || host != "host.example" || credentialIDAfter.Valid {
		t.Fatalf("rejected update changed the node: name=%q host=%q credential=%+v", name, host, credentialIDAfter)
	}
}

func TestWorkspaceNodeWriteRejectsMissingCredential(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)

	_, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Missing credential", Kind: "connection", Protocol: "ssh", Host: "host.example",
		CredentialMode: 2, CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	})
	if err == nil || err.Error() != "selected credential was not found" {
		t.Fatalf("missing credential error = %v", err)
	}
}

func TestWorkspaceNodeWriteRejectsCredentialKindsUnsupportedByConnectionProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO CredentialProfiles (Id, Protocol, Kind) VALUES
    ('20000000-0000-4000-8000-000000000001', 0, 1),
    ('20000000-0000-4000-8000-000000000002', 1, 1),
    ('20000000-0000-4000-8000-000000000003', 6, 1),
    ('20000000-0000-4000-8000-000000000004', 0, 9);`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if _, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "SSH key", Kind: "connection", Protocol: "ssh", Host: "ssh.example",
		CredentialMode: 2, CredentialID: "20000000-0000-4000-8000-000000000001",
	}); err != nil {
		t.Fatalf("valid SSH key was rejected: %v", err)
	}
	for _, test := range []struct {
		name       string
		protocol   string
		credential string
	}{
		{name: "RDP key", protocol: "rdp", credential: "20000000-0000-4000-8000-000000000002"},
		{name: "VNC key", protocol: "vnc", credential: "20000000-0000-4000-8000-000000000003"},
		{name: "unsupported SSH kind", protocol: "ssh", credential: "20000000-0000-4000-8000-000000000004"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
				Name: test.name, Kind: "connection", Protocol: test.protocol, Host: "target.example",
				CredentialMode: 2, CredentialID: test.credential,
			}); err == nil {
				t.Fatal("unsupported credential kind was accepted")
			}
		})
	}

	rdp := defaultWorkspaceRdpSettings()
	rdp.GatewayCredentialID = "20000000-0000-4000-8000-000000000002"
	if _, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "RDP gateway", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		CredentialMode: 0, RDP: &rdp,
	}); err == nil {
		t.Fatal("SSH-key RDP Gateway credential was accepted")
	}
}

func TestWorkspaceNodeCredentialSettingRejectsSshKeyForPasswordOnlyProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "RDP", Kind: "connection", Protocol: "rdp", Host: "rdp.example", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := "30000000-0000-4000-8000-000000000001"
	if _, err := database.Exec(
		"INSERT INTO CredentialProfiles (Id, Protocol, Kind) VALUES (?, 1, 1);",
		credentialID,
	); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if err := updateWorkspaceNodeCredentialSettings(databasePath, workspaceNodeCredentialSettingsRequest{
		NodeID: nodeID, Mode: 2, CredentialID: credentialID,
	}); err == nil {
		t.Fatal("RDP connection accepted an SSH-key credential through the credential-only write path")
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var mode sql.NullInt64
	var storedID sql.NullString
	if err := database.QueryRow(
		"SELECT CredentialMode, CredentialId FROM Nodes WHERE Id = ?;",
		nodeID,
	).Scan(&mode, &storedID); err != nil {
		t.Fatal(err)
	}
	if !mode.Valid || mode.Int64 != 0 || storedID.Valid {
		t.Fatalf("rejected credential-only update changed the node: mode=%#v id=%#v", mode, storedID)
	}
}

func TestRuntimeCredentialPersistenceReplacesInlineAndSavedBindingsAtomically(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	settings := defaultWorkspaceRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "RDP", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		InlinePasswordAction: "set", InlinePassword: "initial", Username: "old-user", RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialID := "40000000-0000-4000-8000-000000000001"
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(
		"INSERT INTO CredentialProfiles (Id, Username, Domain, Protocol, Kind) VALUES (?, ?, ?, 1, 0);",
		credentialID, "saved-user", "SAVED",
	); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if err := updateWorkspaceNodeCredentialSettings(databasePath, workspaceNodeCredentialSettingsRequest{
		NodeID: nodeID, Mode: 2, CredentialID: credentialID,
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	var username, domain string
	var mode, inline int
	var storedID string
	var secretCount int
	if err := database.QueryRow(`
SELECT Username, RdpDomain, CredentialMode, UseInlinePassword, CredentialId
FROM Nodes WHERE Id = ?;`, nodeID).Scan(&username, &domain, &mode, &inline, &storedID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.QueryRow(
		"SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = ?;", nodeID,
	).Scan(&secretCount); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if username != "saved-user" || domain != "SAVED" || mode != 2 || inline != 0 ||
		storedID != credentialID || secretCount != 0 {
		t.Fatalf("saved binding = user=%q domain=%q mode=%d inline=%d id=%q secrets=%d",
			username, domain, mode, inline, storedID, secretCount)
	}

	if err := updateWorkspaceNodeInlineCredential(databasePath, workspaceNodeInlineCredentialRequest{
		NodeID: nodeID, Protocol: "rdp", Username: "manual-user", Domain: "MANUAL", Password: "replacement",
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var nullableID sql.NullString
	if err := database.QueryRow(`
SELECT Username, RdpDomain, CredentialMode, UseInlinePassword, CredentialId
FROM Nodes WHERE Id = ?;`, nodeID).Scan(&username, &domain, &mode, &inline, &nullableID); err != nil {
		t.Fatal(err)
	}
	secret, found, err := readStoredSecret(database, nodeID, "")
	if err != nil {
		t.Fatal(err)
	}
	if username != "manual-user" || domain != "MANUAL" || mode != 1 || inline != 1 ||
		nullableID.Valid || !found || secret != "replacement" {
		t.Fatalf("manual binding = user=%q domain=%q mode=%d inline=%d id=%#v secret=%q found=%v",
			username, domain, mode, inline, nullableID, secret, found)
	}
}

func TestWorkspaceInlineSecretReplacementRollsBackOnNodeWriteFailure(t *testing.T) {
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	storeCount := 0
	deleted := make([]string, 0)
	credentialSecretStore = func(_, _, _ string) (string, string, error) {
		storeCount++
		return fmt.Sprintf("protected-%d", storeCount), "test-protected-v1", nil
	}
	credentialSecretDelete = func(_ string, encoded, _ string) error {
		deleted = append(deleted, encoded)
		return nil
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	settings := defaultWorkspaceRdpSettings()
	nodeID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "RDP", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		InlinePasswordAction: "set", InlinePassword: "initial", RDP: &settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_rdp_node_update
BEFORE UPDATE ON Nodes BEGIN SELECT RAISE(FAIL, 'simulated write failure'); END;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	err = updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: nodeID, Name: "Changed", Kind: "connection", Protocol: "rdp", Host: "rdp.example",
		InlinePasswordAction: "set", InlinePassword: "replacement", RDP: &settings,
	})
	if err == nil {
		t.Fatal("inline password replacement should fail with the node write")
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name, secret string
	if err := database.QueryRow(`SELECT n.Name, s.Secret FROM Nodes n
JOIN CredentialSecrets s ON s.Id = n.Id WHERE n.Id = ?;`, nodeID).Scan(&name, &secret); err != nil {
		t.Fatal(err)
	}
	if name != "RDP" || secret != "protected-1" {
		t.Fatalf("failed replacement changed persisted state: name=%q secret=%q", name, secret)
	}
	if len(deleted) != 1 || deleted[0] != "protected-2" {
		t.Fatalf("staged protected secret was not cleaned up: %#v", deleted)
	}
}

func TestWorkspaceNodeUpdateRejectsFolderCycle(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	parentID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Parent", Kind: "folder", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	childID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ParentID: parentID, Name: "Child", Kind: "folder", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: parentID, ParentID: childID, Name: "Parent", Kind: "folder", CredentialMode: 0,
	}); err == nil {
		t.Fatal("folder cycle was accepted")
	}
}

func TestWorkspaceFolderCredentialEditPreservesHiddenWinUIInheritanceDefaults(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	createWorkspaceNodeTestSchema(t, databasePath)
	folderID, err := createWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		Name: "Defaults", Kind: "folder", CredentialMode: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
UPDATE Nodes SET Protocol = 0, Host = 'jump.example', Port = 2222,
    SerialBaudRate = 115200, SerialDataBits = 7
WHERE Id = ?;`, folderID)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if err := updateWorkspaceNode(databasePath, workspaceNodeWriteRequest{
		ID: folderID, Name: "Renamed defaults", Kind: "folder", CredentialMode: 1,
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name, host string
	var protocol, port, baudRate, dataBits, credentialMode int
	if err := database.QueryRow(`
SELECT Name, Protocol, Host, Port, SerialBaudRate, SerialDataBits, CredentialMode
FROM Nodes WHERE Id = ?;`, folderID).Scan(
		&name, &protocol, &host, &port, &baudRate, &dataBits, &credentialMode,
	); err != nil {
		t.Fatal(err)
	}
	if name != "Renamed defaults" || protocol != 0 || host != "jump.example" || port != 2222 ||
		baudRate != 115200 || dataBits != 7 || credentialMode != 1 {
		t.Fatalf(
			"folder edit lost hidden inheritance defaults: name=%q protocol=%d host=%q port=%d baud=%d data=%d credential=%d",
			name, protocol, host, port, baudRate, dataBits, credentialMode,
		)
	}
}
