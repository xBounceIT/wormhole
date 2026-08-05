package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeInputRejectsOversizedRequest(t *testing.T) {
	var request authVerifyRequest
	input := `{"method":"pin","secret":"` + strings.Repeat("x", backendMaxRequestBytes) + `"}`
	if err := decodeInputReader(bytes.NewBufferString(input), &request); err == nil {
		t.Fatal("oversized backend request was accepted")
	}
}

func TestLoadWorkspaceMapsPersistedRowsWithoutDemoData(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
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
    Host TEXT NULL
);
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    Domain TEXT NULL,
    Kind INTEGER NOT NULL,
    Protocol INTEGER NOT NULL DEFAULT 0,
    SecretProvider INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE TunnelConfigs (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host) VALUES
    ('folder', NULL, 'Real folder', 0, 0, NULL, NULL),
    ('connection', 'folder', 'Real connection', 1, 0, 3, 'real.example'),
    ('root', NULL, 'Root SSH', 1, 1, 0, '192.0.2.1');
INSERT INTO CredentialProfiles (Id, Name, Username, Domain, Kind, Protocol, SecretProvider) VALUES
    ('credential', 'Real credential', 'operator', 'CORP', 0, 1, 1);
INSERT INTO TunnelConfigs (Id, Name, Kind) VALUES
    ('tunnel', 'Real tunnel', 6);
`)
	if err != nil {
		t.Fatal(err)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tree) != 2 {
		t.Fatalf("expected 2 root nodes, got %d", len(workspace.Tree))
	}
	if workspace.Tree[0].Name != "Real folder" || len(workspace.Tree[0].Children) != 1 {
		t.Fatalf("unexpected persisted tree: %#v", workspace.Tree)
	}
	if workspace.Tree[0].Children[0].Protocol != "http" {
		t.Fatalf("expected HTTP protocol, got %q", workspace.Tree[0].Children[0].Protocol)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].Provider != "Bitwarden" {
		t.Fatalf("unexpected persisted credentials: %#v", workspace.Credentials)
	}
	if len(workspace.Tunnels) != 1 || workspace.Tunnels[0].Kind != "Cisco Secure Client" {
		t.Fatalf("unexpected persisted tunnels: %#v", workspace.Tunnels)
	}
}

func TestWorkspaceNodeSshAutoSudoSettingsRoundTrip(t *testing.T) {
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
    SshAutoSudo INTEGER NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host, SshAutoSudo, UpdatedAt) VALUES
    ('folder', NULL, 'SSH defaults', 0, 0, NULL, NULL, 1, 'now'),
    ('leaf', 'folder', 'SSH connection', 1, 0, 0, 'ssh.example', NULL, 'now'),
    ('off', 'folder', 'Disabled SSH connection', 1, 1, 0, 'off.example', 0, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tree) != 1 || len(workspace.Tree[0].Children) != 2 {
		t.Fatalf("unexpected workspace tree: %#v", workspace.Tree)
	}
	if workspace.Tree[0].SshAutoSudo == nil || !*workspace.Tree[0].SshAutoSudo || !workspace.Tree[0].Persisted {
		t.Fatalf("folder auto-sudo override was not loaded: %#v", workspace.Tree[0])
	}
	if workspace.Tree[0].Children[1].SshAutoSudo == nil || *workspace.Tree[0].Children[1].SshAutoSudo || !workspace.Tree[0].Children[1].Persisted {
		t.Fatalf("explicit connection auto-sudo off was not loaded: %#v", workspace.Tree[0].Children[1])
	}

	enabled := true
	if err := updateWorkspaceNodeSshSettings(databasePath, workspaceNodeSshSettingsRequest{
		NodeID:      "leaf",
		SshAutoSudo: &enabled,
	}); err != nil {
		t.Fatal(err)
	}
	workspace, err = loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Tree[0].Children[0].SshAutoSudo == nil || !*workspace.Tree[0].Children[0].SshAutoSudo {
		t.Fatalf("connection auto-sudo override was not saved: %#v", workspace.Tree[0].Children[0])
	}

	if err := updateWorkspaceNodeSshSettings(databasePath, workspaceNodeSshSettingsRequest{
		NodeID:      "leaf",
		SshAutoSudo: nil,
	}); err != nil {
		t.Fatal(err)
	}
	workspace, err = loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Tree[0].Children[0].SshAutoSudo != nil {
		t.Fatalf("inherit should clear the connection override: %#v", workspace.Tree[0].Children[0])
	}
}

func TestWorkspaceNodeSshAutoSudoUpdateRequiresMigration(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    UpdatedAt TEXT NOT NULL
);
INSERT INTO Nodes (Id, Name, Kind, UpdatedAt) VALUES ('leaf', 'SSH connection', 1, 'now');
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	enabled := true
	err = updateWorkspaceNodeSshSettings(databasePath, workspaceNodeSshSettingsRequest{
		NodeID:      "leaf",
		SshAutoSudo: &enabled,
	})
	if err == nil || err.Error() != "Wormhole database schema is missing the SSH auto-sudo migration" {
		t.Fatalf("expected a migration error, got %v", err)
	}

	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var columnCount int
	if err := database.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info('Nodes') WHERE name = 'SshAutoSudo';",
	).Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatalf("auto-sudo write should not mutate the schema: %d columns found", columnCount)
	}
}

func TestLoadWorkspaceReturnsEmptyForMissingDatabase(t *testing.T) {
	workspace, err := loadWorkspace(filepath.Join(t.TempDir(), "missing.db"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Tree) != 0 || len(workspace.Credentials) != 0 || len(workspace.Tunnels) != 0 {
		t.Fatalf("missing database returned data: %#v", workspace)
	}
}

func TestCredentialPasswordsRequireTheLegacyNamespace(t *testing.T) {
	entries := []credentialReaderEntry{
		{Target: "Wormhole:ABC", Account: "abc", Password: "first"},
		{Target: "Wormhole:abc", Account: "abc", Password: "second"},
		{Target: "Wormhole:other", Account: "abc", Password: "wrong target"},
	}

	passwords := credentialPasswords(entries)
	if passwords["abc"] != "second" {
		t.Fatalf("expected the exact namespaced entry, got %#v", passwords)
	}
	if len(passwords) != 1 {
		t.Fatalf("unexpected credential map: %#v", passwords)
	}
}

func TestMigrationDoesNotWriteCompletionWhenReaderIsMissing(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("credential migration is Windows-only")
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, err := migrateCredentials(databasePath, "")
	if err == nil {
		t.Fatal("expected a missing reader error")
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM ElectronMigrations WHERE Id = ?", windowsCredentialMigrationID).Scan(&count); !errors.Is(err, sql.ErrNoRows) && err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed migration wrote a completion marker: %d", count)
	}
}

func TestMigrationCopiesLocalSecretsOnceAndLeavesBitwardenAlone(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("credential migration is Windows-only")
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    SecretProvider INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    UseInlinePassword INTEGER NULL
);
INSERT INTO CredentialProfiles (Id, SecretProvider) VALUES ('local-id', 0), ('remote-id', 1);
INSERT INTO Nodes (Id, UseInlinePassword) VALUES ('inline-id', 1);
`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	reader := func(string) ([]credentialReaderEntry, error) {
		return []credentialReaderEntry{
			{Target: credentialTarget("local-id"), Account: "local-id", Password: "päss🔐"},
			{Target: credentialTarget("inline-id"), Account: "inline-id", Password: "inline-secret"},
		}, nil
	}
	result, err := migrateCredentialsWithReader(databasePath, "test-reader", reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.Migrated != 2 || result.Missing != 1 {
		t.Fatalf("unexpected migration result: %#v", result)
	}

	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var secretCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets").Scan(&secretCount); err != nil {
		t.Fatal(err)
	}
	if secretCount != 2 {
		t.Fatalf("expected two migrated secrets, got %d", secretCount)
	}
	var encoding string
	if err := database.QueryRow("SELECT Encoding FROM CredentialSecrets LIMIT 1").Scan(&encoding); err != nil {
		t.Fatal(err)
	}
	if encoding != protectedSecretEncoding {
		t.Fatalf("unexpected secret encoding: %q", encoding)
	}
	var markerStatus string
	if err := database.QueryRow("SELECT Status FROM ElectronMigrations WHERE Id = ?", windowsCredentialMigrationID).Scan(&markerStatus); err != nil {
		t.Fatal(err)
	}
	if markerStatus != "completed" {
		t.Fatalf("unexpected migration marker: %q", markerStatus)
	}
	database.Close()

	called := false
	secondResult, err := migrateCredentialsWithReader(databasePath, "test-reader", func(string) ([]credentialReaderEntry, error) {
		called = true
		return nil, errors.New("reader should not run after completion")
	})
	if err != nil {
		t.Fatal(err)
	}
	if called || secondResult.Status != "already-completed" {
		t.Fatalf("migration was not idempotent: called=%v result=%#v", called, secondResult)
	}
}

func TestCredentialReaderEntryBounds(t *testing.T) {
	if validCredentialReaderEntry(credentialReaderEntry{Target: "Wormhole:id", Account: "id", Password: string(make([]rune, maxCredentialPasswordUnits+1))}) {
		t.Fatal("oversized UTF-16 password was accepted")
	}
	if !validCredentialReaderEntry(credentialReaderEntry{Target: "Wormhole:id", Account: "id", Password: "päss🔐"}) {
		t.Fatal("valid Unicode password was rejected")
	}
	if validCredentialReaderEntry(credentialReaderEntry{Target: "", Account: "id", Password: "password"}) {
		t.Fatal("empty target was accepted")
	}
}

func TestCredentialReaderOutputIsBounded(t *testing.T) {
	output := &limitedOutput{limit: 4}
	if _, err := output.Write([]byte("12345")); !errors.Is(err, errCredentialReaderOutputTooLarge) {
		t.Fatalf("expected output limit error, got %v", err)
	}
	if output.Len() != 4 || !output.exceeded {
		t.Fatalf("output was not bounded: length=%d exceeded=%v", output.Len(), output.exceeded)
	}
}

func TestProtectSecretSupportsEmptyPasswords(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("Windows DPAPI is Windows-only")
	}
	protected, err := protectSecret("")
	if err != nil {
		t.Fatal(err)
	}
	if protected == "" {
		t.Fatal("DPAPI returned an empty protected value")
	}
}

func TestOpenDatabaseReadOnlyDoesNotCreateMissingFile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "missing.db")
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Tree == nil || workspace.Credentials == nil || workspace.Tunnels == nil {
		t.Fatal("empty workspace slices must be non-nil")
	}
	if _, err := os.Stat(databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only load created a database: %v", err)
	}
}
