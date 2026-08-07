package main

import (
	"database/sql"
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
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    SshAutoSudo INTEGER NULL,
    HttpIgnoreCertErrors INTEGER NULL,
    TunnelEnabled INTEGER NULL,
    TunnelConfigId TEXT NULL,
    SerialBaudRate INTEGER NULL,
    SerialDataBits INTEGER NULL,
    SerialStopBits INTEGER NULL,
    SerialParity INTEGER NULL,
    SerialFlowControl INTEGER NULL,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Protocol INTEGER NOT NULL
);
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
