package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestEnsureElectronWorkspaceSchemaCreatesWinUICompatibleFreshDatabase(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	for _, table := range []string{
		"Nodes", "CredentialProfiles", "TunnelConfigs", "BitwardenCredentialCache",
		"CredentialSecrets", "CredentialPrivateKeyOperations", "CredentialSecretOperations",
	} {
		exists, err := tableExists(database, table)
		if err != nil || !exists {
			t.Fatalf("table %s exists=%v err=%v", table, exists, err)
		}
	}
	for table, names := range map[string][]string{
		"Nodes":                          {"CredentialMode", "SshAutoSudo", "HttpIgnoreCertErrors", "HttpPath", "SerialFlowControl", "RdpGatewayCredentialId"},
		"CredentialProfiles":             {"Protocol", "SecretProvider", "BitwardenItemId", "BitwardenFieldPath"},
		"CredentialPrivateKeyOperations": {"CredentialId", "OperationKind", "ProtectedSha256", "CreatedAtUtc"},
		"CredentialSecretOperations":     {"SecretReference", "CredentialId", "Encoding", "CreatedAtUtc"},
	} {
		columns, err := tableColumns(database, table)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if _, ok := columns[name]; !ok {
				t.Fatalf("column %s.%s is missing", table, name)
			}
		}
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM __migration_history;").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 21 {
		t.Fatalf("migration history count = %d", count)
	}
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatalf("second migration pass: %v", err)
	}
}

func TestEnsureElectronWorkspaceSchemaRemovesSecretBearingHTTPPathComponents(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
DELETE FROM __migration_history WHERE Id = '0019_http_path_context_only';
INSERT INTO Nodes (Id, Name, Kind, SortOrder, Protocol, Host, HttpPath, CreatedAt, UpdatedAt)
VALUES ('web', 'Web', 1, 0, 4, 'example.test', '/admin?access_token=secret#callback', 'now', 'now');`); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	_ = database.Close()

	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var httpPath sql.NullString
	if err := database.QueryRow("SELECT HttpPath FROM Nodes WHERE Id = 'web';").Scan(&httpPath); err != nil {
		t.Fatal(err)
	}
	if !httpPath.Valid || httpPath.String != "/admin" {
		t.Fatalf("sanitized HttpPath = %#v", httpPath)
	}
}

func TestEnsureElectronWorkspaceSchemaAdoptsExistingElectronCredentialTables(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TABLE CredentialProfiles (
    Id TEXT PRIMARY KEY NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    Domain TEXT NULL,
    Kind INTEGER NOT NULL DEFAULT 0,
    PrivateKeyFileName TEXT NULL,
    Protocol INTEGER NOT NULL DEFAULT 0,
    SecretProvider INTEGER NOT NULL DEFAULT 0,
    BitwardenItemId TEXT NULL,
    BitwardenItemName TEXT NULL,
    BitwardenFieldPath TEXT NOT NULL DEFAULT 'login.password',
    CreatedAt TEXT NOT NULL
);
CREATE UNIQUE INDEX UX_CredentialProfiles_Name ON CredentialProfiles(Name);
CREATE TABLE BitwardenCredentialCache (
    ItemId TEXT PRIMARY KEY NOT NULL,
    SshCredentialId TEXT NOT NULL,
    RdpCredentialId TEXT NOT NULL,
    VncCredentialId TEXT NOT NULL,
    Name TEXT NOT NULL,
    Username TEXT NULL,
    RevisionDate TEXT NULL,
    LastSeenSyncUtc TEXT NOT NULL,
    UpdatedAtUtc TEXT NOT NULL
);`); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, id := range []string{
		"0001_initial", "0002_credential_protocol", "0014_bitwarden_credentials",
		"0015_bitwarden_credential_cache", "0016_credential_private_key_operations",
		"0017_credential_secret_operations",
	} {
		var present int
		if err := database.QueryRow("SELECT COUNT(*) FROM __migration_history WHERE Id = ?;", id).Scan(&present); err != nil || present != 1 {
			t.Fatalf("migration %s present=%d err=%v", id, present, err)
		}
	}
	exists, err := tableExists(database, "Nodes")
	if err != nil || !exists {
		t.Fatalf("Nodes exists=%v err=%v", exists, err)
	}
}

func TestEnsureElectronWorkspaceSchemaRunsNonIdempotentTransformOnce(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
DELETE FROM __migration_history WHERE Id = '0007_rdp_server_auth_warn_mapping';
INSERT INTO Nodes (Id, Name, Kind, SortOrder, Protocol, CreatedAt, UpdatedAt, RdpServerAuthentication)
VALUES ('rdp', 'RDP', 1, 0, 1, 'now', 'now', 0);`); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value sql.NullInt64
	if err := database.QueryRow("SELECT RdpServerAuthentication FROM Nodes WHERE Id = 'rdp';").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if !value.Valid || value.Int64 != 2 {
		t.Fatalf("RdpServerAuthentication = %+v", value)
	}
}
