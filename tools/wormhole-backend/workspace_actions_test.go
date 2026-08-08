package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestDuplicateWorkspaceNodeCopiesConnectionWithNewIdentity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL,
    SshKnownHostFingerprint TEXT NULL,
    TunnelEnabled INTEGER NULL,
    TunnelConfigId TEXT NULL,
    CreatedAt TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes
    (Id, ParentId, Name, Kind, SortOrder, Protocol, Host, CredentialId, CredentialMode,
     UseInlinePassword, SshKnownHostFingerprint, TunnelEnabled, TunnelConfigId, CreatedAt, UpdatedAt)
VALUES
    ('folder', NULL, 'Servers', 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'old', 'old'),
    ('source', 'folder', 'Production', 1, 2, 0, 'prod.example.test',
     'credential-id', 2, 1, 'SHA256:old', 1, 'tunnel-id', 'old', 'old'),
    ('sibling', 'folder', 'Existing', 1, 8, 0, 'existing.example.test',
     NULL, NULL, 0, NULL, NULL, NULL, 'old', 'old');`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	result, err := duplicateWorkspaceNode(databasePath, workspaceNodeRequest{NodeID: "SOURCE"})
	if err != nil {
		t.Fatal(err)
	}
	if result.NodeID == "" || result.NodeID == "source" || result.Name != "Production (copy)" {
		t.Fatalf("unexpected duplicate response: %#v", result)
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var parentID, name, credentialID, fingerprint, tunnelID sql.NullString
	var kind, sortOrder, inlinePassword, tunnelEnabled int64
	err = database.QueryRow(`
SELECT ParentId, Name, Kind, SortOrder, CredentialId, CredentialMode, UseInlinePassword,
       SshKnownHostFingerprint, TunnelEnabled, TunnelConfigId
FROM Nodes WHERE Id = ?;`, result.NodeID).Scan(
		&parentID, &name, &kind, &sortOrder, &credentialID, new(sql.NullInt64), &inlinePassword,
		&fingerprint, &tunnelEnabled, &tunnelID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if parentID.String != "folder" || name.String != "Production (copy)" || kind != 1 {
		t.Fatalf("duplicate lost identity fields: parent=%q name=%q kind=%d", parentID.String, name.String, kind)
	}
	if sortOrder != 9 {
		t.Fatalf("duplicate sort order = %d, want 9", sortOrder)
	}
	if credentialID.String != "credential-id" || inlinePassword != 0 {
		t.Fatalf("duplicate credential binding changed: credential=%q inline=%d", credentialID.String, inlinePassword)
	}
	if fingerprint.Valid || tunnelEnabled != 1 || tunnelID.String != "tunnel-id" {
		t.Fatalf("duplicate did not preserve shared settings/reset host state: fingerprint=%q tunnel=%d/%q", fingerprint.String, tunnelEnabled, tunnelID.String)
	}
}

func TestDeleteWorkspaceNodeDeletesSubtreeAndInlineSecret(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    UseInlinePassword INTEGER NULL
);
CREATE TABLE CredentialProfiles (Id TEXT PRIMARY KEY NOT NULL);
CREATE TABLE CredentialSecrets (
    Id TEXT PRIMARY KEY NOT NULL,
    Secret TEXT NOT NULL,
    Encoding TEXT NOT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, UseInlinePassword)
VALUES ('folder', NULL, 'Servers', 0, 0),
       ('nested', 'folder', 'Nested', 0, 0),
       ('inline', 'nested', 'Inline password', 1, 1),
       ('stale', 'nested', 'Stale password', 1, 0),
       ('sibling', NULL, 'Keep me', 1, 0);
INSERT INTO CredentialProfiles (Id) VALUES ('shared-profile');
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES ('inline', 'inline-secret', 'test', 'now'),
       ('stale', 'stale-secret', 'test', 'now'),
       ('shared-profile', 'shared-secret', 'test', 'now');`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	result, err := deleteWorkspaceNode(databasePath, workspaceNodeRequest{NodeID: "FOLDER"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Deleted {
		t.Fatal("workspace node deletion was not reported")
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var nodeCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM Nodes;").Scan(&nodeCount); err != nil {
		t.Fatal(err)
	}
	if nodeCount != 1 {
		t.Fatalf("remaining node count = %d, want 1", nodeCount)
	}
	var remainingID string
	if err := database.QueryRow("SELECT Id FROM Nodes LIMIT 1;").Scan(&remainingID); err != nil {
		t.Fatal(err)
	}
	if remainingID != "sibling" {
		t.Fatalf("remaining node = %q, want sibling", remainingID)
	}
	var inlineSecretCount, staleSecretCount, sharedSecretCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = 'inline';").Scan(&inlineSecretCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = 'stale';").Scan(&staleSecretCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = 'shared-profile';").Scan(&sharedSecretCount); err != nil {
		t.Fatal(err)
	}
	if inlineSecretCount != 0 || staleSecretCount != 0 || sharedSecretCount != 1 {
		t.Fatalf("secret cleanup = inline %d, stale %d, shared %d; want 0, 0, 1", inlineSecretCount, staleSecretCount, sharedSecretCount)
	}
}

func TestDeleteWorkspaceNodesDeletesCanonicalSubtreesInOneTransaction(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind)
VALUES ('folder', NULL, 'Servers', 0),
       ('child', 'folder', 'Nested connection', 1),
       ('root-connection', NULL, 'Root connection', 1),
       ('keep', NULL, 'Keep me', 1);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	result, err := deleteWorkspaceNodes(databasePath, workspaceNodesRequest{
		NodeIDs: []string{"CHILD", "folder", "root-connection", "folder"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Deleted {
		t.Fatal("workspace node batch deletion was not reported")
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var remainingID string
	if err := database.QueryRow("SELECT Id FROM Nodes;").Scan(&remainingID); err != nil {
		t.Fatal(err)
	}
	if remainingID != "keep" {
		t.Fatalf("remaining node = %q, want keep", remainingID)
	}
}

func TestDeleteWorkspaceNodesRejectsMissingTargetBeforeDeletingAnything(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind)
VALUES ('existing', NULL, 'Existing', 1);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = deleteWorkspaceNodes(databasePath, workspaceNodesRequest{
		NodeIDs: []string{"existing", "missing"},
	})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("deleteWorkspaceNodes error = %v, want missing-node failure", err)
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM Nodes WHERE Id = 'existing';").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("existing node count = %d, want 1", count)
	}
}

func TestDeleteWorkspaceNodesValidatesBatchBounds(t *testing.T) {
	if _, err := deleteWorkspaceNodes("unused.db", workspaceNodesRequest{}); err == nil {
		t.Fatal("empty workspace node batch was accepted")
	}
	tooMany := make([]string, 1001)
	for index := range tooMany {
		tooMany[index] = "node"
	}
	if _, err := deleteWorkspaceNodes("unused.db", workspaceNodesRequest{NodeIDs: tooMany}); err == nil {
		t.Fatal("oversized workspace node batch was accepted")
	}
}

func TestShowWorkspaceNodeCredentialsResolvesInheritedMetadataWithoutExposingMissingSecret(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    Domain TEXT NULL,
    Kind INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NOT NULL DEFAULT 0,
    SecretProvider INTEGER NOT NULL DEFAULT 0
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Username, CredentialId, CredentialMode)
VALUES ('folder', NULL, 'Servers', 0, 0, NULL, 'credential-id', 2),
       ('leaf', 'folder', 'Production', 1, NULL, NULL, NULL, NULL);
INSERT INTO CredentialProfiles (Id, Name, Username, Domain, Kind, Protocol, SecretProvider)
VALUES ('credential-id', 'Production login', 'operator', NULL, 0, 0, 0);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	result, err := showWorkspaceNodeCredentials(
		databasePath,
		workspaceNodeRequest{NodeID: "leaf"},
		filepath.Dir(databasePath),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Found || result.Secret != "" {
		t.Fatalf("missing secret was exposed: %#v", result)
	}
	if result.ConnectionName != "Production" || result.CredentialName != "Production login" || result.Username != "operator" {
		t.Fatalf("inherited credential metadata = %#v", result)
	}
	if !strings.Contains(result.ConnectionName, "Production") {
		t.Fatalf("unexpected connection name: %q", result.ConnectionName)
	}
}

func TestShowWorkspaceNodeCredentialsUsesSavedCredentialUsernameBoundary(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    Username TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    Domain TEXT NULL,
    Kind INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NOT NULL DEFAULT 0,
    SecretProvider INTEGER NOT NULL DEFAULT 0
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Username, CredentialId, CredentialMode)
VALUES ('root', NULL, 'All servers', 0, 0, 'root-user', NULL, NULL),
       ('profile-folder', 'root', 'Production', 0, NULL, NULL, 'credential-id', 2),
       ('leaf', 'profile-folder', 'Web', 1, NULL, NULL, NULL, NULL);
INSERT INTO CredentialProfiles (Id, Name, Username, Protocol, Kind, SecretProvider)
VALUES ('credential-id', 'Production login', 'credential-user', 0, 0, 0);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	result, err := showWorkspaceNodeCredentials(
		databasePath,
		workspaceNodeRequest{NodeID: "leaf"},
		filepath.Dir(databasePath),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Username != "credential-user" {
		t.Fatalf("username crossed the saved credential boundary: %#v", result)
	}
}

func TestWorkspaceActionsRejectCaseInsensitiveNodeIDAmbiguity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL
);
INSERT INTO Nodes (Id, Name, Kind, Protocol)
VALUES ('source', 'First', 1, 0), ('SOURCE', 'Second', 1, 0);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if _, err := duplicateWorkspaceNode(databasePath, workspaceNodeRequest{NodeID: "source"}); err == nil {
		t.Fatal("duplicate unexpectedly selected one of two case-insensitive node IDs")
	}
	if _, err := showWorkspaceNodeCredentials(
		databasePath,
		workspaceNodeRequest{NodeID: "source"},
		filepath.Dir(databasePath),
	); err == nil {
		t.Fatal("show credentials unexpectedly selected one of two case-insensitive node IDs")
	}
}

func TestShowWorkspaceNodeCredentialsRejectsCaseInsensitiveProfileAmbiguity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    Protocol INTEGER NOT NULL DEFAULT 0,
    Kind INTEGER NOT NULL DEFAULT 0,
    SecretProvider INTEGER NOT NULL DEFAULT 0
);
INSERT INTO Nodes (Id, Name, Kind, Protocol, CredentialId, CredentialMode)
VALUES ('leaf', 'Web', 1, 0, 'credential-id', 2);
INSERT INTO CredentialProfiles (Id, Name, Username, Protocol, Kind, SecretProvider)
VALUES ('credential-id', 'First', 'first-user', 0, 0, 0),
       ('CREDENTIAL-ID', 'Second', 'second-user', 0, 0, 0);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	if _, err := showWorkspaceNodeCredentials(
		databasePath,
		workspaceNodeRequest{NodeID: "leaf"},
		filepath.Dir(databasePath),
	); err == nil {
		t.Fatal("show credentials unexpectedly selected one of two case-insensitive profiles")
	}
}
