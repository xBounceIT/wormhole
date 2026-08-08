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
    Id TEXT PRIMARY KEY NOT NULL
);`)
	if err != nil {
		t.Fatal(err)
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

func TestWorkspaceInlineSecretReplacementRollsBackOnNodeWriteFailure(t *testing.T) {
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	storeCount := 0
	deleted := make([]string, 0)
	credentialSecretStore = func(_ string, _ string) (string, string, error) {
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
