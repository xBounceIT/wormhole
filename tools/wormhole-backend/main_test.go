package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBackendCLIValidatesProcessContract(t *testing.T) {
	t.Run("flag parse failure", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := runBackendCLI([]string{"-unknown"}, strings.NewReader(""), io.Discard, &stderr); code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		if !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("unexpected flag error: %q", stderr.String())
		}
	})

	t.Run("help", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := runBackendCLI([]string{"-h"}, strings.NewReader(""), io.Discard, &stderr); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stderr.String(), "Usage of wormhole-backend") {
			t.Fatalf("help did not include usage: %q", stderr.String())
		}
	})

	t.Run("missing database", func(t *testing.T) {
		var stderr bytes.Buffer
		if code := runBackendCLI(nil, strings.NewReader(""), io.Discard, &stderr); code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if stderr.String() != "database path is required\n" {
			t.Fatalf("unexpected database error: %q", stderr.String())
		}
	})

	t.Run("unsupported operation", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		databasePath := filepath.Join(t.TempDir(), "wormhole.db")
		code := runBackendCLI(
			[]string{"-database", databasePath, "-operation", "unknown"},
			strings.NewReader(""), &stdout, &stderr,
		)
		if code != 1 || !strings.Contains(stderr.String(), "unsupported operation") {
			t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
	})
}

func TestRunBackendCLIRejectsMalformedRequestsForEveryInputOperation(t *testing.T) {
	operations := []string{
		"startup-unlock",
		"workspace-duplicate-node",
		"workspace-delete-node",
		"workspace-delete-nodes",
		"workspace-show-credentials",
		"mremote-import-inspect",
		"mremote-import-analyze",
		"mremote-import-commit",
		"backup-inspect",
		"backup-export",
		"backup-import",
		"web-target",
		"watchguard-import",
		"azure-vpn-import",
		"rdp-external-client-requirement",
		"cisco-profile-import",
		"ovpn-file-import",
		"credential-create",
		"credential-update",
		"credential-delete",
		"credentials-for-protocol",
		"workspace-update-node",
		"workspace-update-node-web-settings",
		"workspace-update-node-tunnel",
		"workspace-update-node-credential",
		"workspace-update-node-inline-credential",
		"workspace-node-create",
		"workspace-node-update",
		"tunnel-create",
		"tunnel-read",
		"tunnel-update",
		"tunnel-delete",
		"auth-verify",
		"auth-set-secret",
		"auth-update-settings",
		"settings-set-theme",
		"settings-set-prompt-before-tunnel",
		"settings-set-auto-copy-on-select",
		"settings-set-confirm-on-tab-close",
		"settings-set-sidebar-width",
		"settings-set-connection-tree-expansion",
		"settings-set-update-preferences",
		"update-check",
		"settings-set-log-retention",
		"settings-set-log-level",
		"bitwarden-onboarding-read",
		"extension-set-enabled",
		"extension-import-zip",
		"extension-import-folder",
		"auth-hello-verify",
		"ssh-trust-host-key",
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runBackendCLI(
				[]string{"-database", databasePath, "-operation", operation},
				strings.NewReader("{"), &stdout, &stderr,
			)
			if code != 1 || stderr.String() != "Wormhole request was invalid\n" {
				t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunBackendCLIDispatchesSemanticallyInvalidRequests(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	missingPath := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		operation string
		input     string
	}{
		{operation: "startup-unlock", input: `{}`},
		{operation: "workspace-duplicate-node", input: `{}`},
		{operation: "workspace-delete-node", input: `{}`},
		{operation: "workspace-delete-nodes", input: `{}`},
		{operation: "workspace-show-credentials", input: `{}`},
		{operation: "mremote-import-inspect", input: `{}`},
		{operation: "mremote-import-analyze", input: `{}`},
		{operation: "mremote-import-commit", input: `{}`},
		{operation: "backup-inspect", input: `{}`},
		{operation: "backup-export", input: `{}`},
		{operation: "backup-import", input: `{}`},
		{operation: "web-target", input: `{}`},
		{operation: "watchguard-import", input: `{}`},
		{operation: "azure-vpn-import", input: `{}`},
		{operation: "rdp-external-client-requirement", input: `{}`},
		{operation: "cisco-profile-import", input: `{}`},
		{operation: "ovpn-file-import", input: `{}`},
		{operation: "credential-create", input: `{}`},
		{operation: "credential-update", input: `{}`},
		{operation: "credential-delete", input: `{}`},
		{operation: "credentials-for-protocol", input: `{}`},
		{operation: "workspace-update-node", input: `{}`},
		{operation: "workspace-update-node-web-settings", input: `{}`},
		{operation: "workspace-update-node-tunnel", input: `{}`},
		{operation: "workspace-update-node-credential", input: `{}`},
		{operation: "workspace-update-node-inline-credential", input: `{}`},
		{operation: "workspace-node-create", input: `{}`},
		{operation: "workspace-node-update", input: `{}`},
		{operation: "tunnel-create", input: `{}`},
		{operation: "tunnel-read", input: `{}`},
		{operation: "tunnel-update", input: `{}`},
		{operation: "tunnel-delete", input: `{}`},
		{operation: "auth-verify", input: `{}`},
		{operation: "auth-set-secret", input: `{}`},
		{operation: "auth-update-settings", input: `{}`},
		{operation: "settings-set-theme", input: `{"theme":"invalid"}`},
		{operation: "settings-set-confirm-on-tab-close", input: `{}`},
		{operation: "settings-set-sidebar-width", input: `{}`},
		{operation: "settings-set-connection-tree-expansion", input: `{}`},
		{operation: "settings-set-update-preferences", input: `{"skippedUpdateVersion":42}`},
		{operation: "settings-set-log-retention", input: `{"days":-1}`},
		{operation: "settings-set-log-level", input: `{"level":"invalid"}`},
		{operation: "bitwarden-onboarding-read", input: `{}`},
		{operation: "extension-set-enabled", input: `{}`},
		{operation: "extension-import-zip", input: fmt.Sprintf(`{"path":%q}`, missingPath)},
		{operation: "extension-import-folder", input: fmt.Sprintf(`{"path":%q}`, missingPath)},
		{operation: "auth-hello-verify", input: `{}`},
		{operation: "ssh-trust-host-key", input: `{}`},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runBackendCLI(
				[]string{"-database", databasePath, "-operation", test.operation},
				strings.NewReader(test.input), &stdout, &stderr,
			)
			if code == 0 {
				if !json.Valid(stdout.Bytes()) {
					t.Fatalf("successful response is not JSON: %q", stdout.String())
				}
			} else if strings.TrimSpace(stderr.String()) == "" {
				t.Fatalf("failed operation returned no error; stdout=%q", stdout.String())
			}
		})
	}

	var stdout, stderr bytes.Buffer
	code := runBackendCLI(
		[]string{"-database", databasePath, "-operation", "migrate", "-credential-reader", missingPath},
		strings.NewReader(""), &stdout, &stderr,
	)
	if code != 1 || strings.TrimSpace(stderr.String()) == "" {
		t.Fatalf("missing migration reader: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunBackendCLIExecutesSafeOneShotOperations(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		input     string
	}{
		{name: "startup", operation: "startup", input: ""},
		{name: "workspace", operation: "workspace"},
		{name: "auth status", operation: "auth-status"},
		{name: "settings read", operation: "settings-read"},
		{name: "settings migrate", operation: "settings-migrate"},
		{name: "set theme", operation: "settings-set-theme", input: `{"theme":"dark"}`},
		{name: "set tunnel prompt", operation: "settings-set-prompt-before-tunnel", input: `{"enabled":false}`},
		{name: "set auto copy", operation: "settings-set-auto-copy-on-select", input: `{"enabled":true}`},
		{name: "set tab confirmation", operation: "settings-set-confirm-on-tab-close", input: `{"enabled":false}`},
		{name: "set sidebar width", operation: "settings-set-sidebar-width", input: `{"width":420}`},
		{name: "set connection tree expansion", operation: "settings-set-connection-tree-expansion", input: `{"defaultExpanded":false,"folderIds":[]}`},
		{name: "set update preferences", operation: "settings-set-update-preferences", input: `{"autoCheckForUpdates":false,"skippedUpdateVersion":"9.9.9"}`},
		{name: "logs info", operation: "logs-info"},
		{name: "set log retention", operation: "settings-set-log-retention", input: `{"days":14}`},
		{name: "set log level", operation: "settings-set-log-level", input: `{"level":"debug"}`},
		{name: "dismiss bitwarden onboarding", operation: "bitwarden-onboarding-dismiss"},
		{name: "extension state", operation: "extension-read"},
		{name: "system idle", operation: "auth-system-idle"},
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runBackendCLI(
				[]string{"-database", databasePath, "-operation", test.operation},
				strings.NewReader(test.input), &stdout, &stderr,
			)
			if code != 0 {
				t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			if !json.Valid(stdout.Bytes()) {
				t.Fatalf("stdout is not JSON: %q", stdout.String())
			}
		})
	}
}

type backendFailingWriter struct{}

func (backendFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type backendFailingReader struct{}

func (backendFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestRunBackendCLIReportsResponseEncodingFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := runBackendCLI(
		[]string{"-database", filepath.Join(t.TempDir(), "wormhole.db"), "-operation", "workspace"},
		strings.NewReader(""), backendFailingWriter{}, &stderr,
	)
	if code != 1 || stderr.String() != "Wormhole could not complete the request\n" {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestDecodeOptionalInputReader(t *testing.T) {
	for _, test := range []struct {
		name  string
		input io.Reader
		valid bool
	}{
		{name: "empty", input: strings.NewReader(""), valid: true},
		{name: "whitespace", input: strings.NewReader(" \n\t"), valid: true},
		{name: "json", input: strings.NewReader(`{"legacyTheme":"dark"}`), valid: true},
		{name: "malformed", input: strings.NewReader("{"), valid: false},
		{name: "oversized", input: strings.NewReader(strings.Repeat("x", backendMaxRequestBytes+1)), valid: false},
		{name: "read failure", input: backendFailingReader{}, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var request startupRequest
			err := decodeOptionalInputReader(test.input, &request)
			if (err == nil) != test.valid {
				t.Fatalf("error = %v, valid = %v", err, test.valid)
			}
		})
	}
}

func TestProtocolAndTunnelNamesCoverKnownAndUnknownValues(t *testing.T) {
	for _, test := range []struct {
		value sql.NullInt64
		name  string
	}{
		{value: sql.NullInt64{}, name: "ssh"},
		{value: sql.NullInt64{Int64: 0, Valid: true}, name: "ssh"},
		{value: sql.NullInt64{Int64: 1, Valid: true}, name: "rdp"},
		{value: sql.NullInt64{Int64: 3, Valid: true}, name: "http"},
		{value: sql.NullInt64{Int64: 4, Valid: true}, name: "https"},
		{value: sql.NullInt64{Int64: 5, Valid: true}, name: "serial"},
		{value: sql.NullInt64{Int64: 6, Valid: true}, name: "vnc"},
	} {
		if name := protocolName(test.value); name != test.name {
			t.Fatalf("protocolName(%+v) = %q, want %q", test.value, name, test.name)
		}
	}

	for _, test := range []struct {
		value int64
		name  string
	}{
		{value: 0, name: "WireGuard"},
		{value: 1, name: "OpenVPN"},
		{value: 2, name: "Fortinet"},
		{value: 3, name: "WatchGuard"},
		{value: 4, name: "Stormshield"},
		{value: 5, name: "Azure VPN"},
		{value: 6, name: "Cisco Secure Client"},
		{value: 99, name: "Unknown"},
	} {
		if name := tunnelName(test.value); name != test.name {
			t.Fatalf("tunnelName(%d) = %q, want %q", test.value, name, test.name)
		}
	}
}

func TestDecodeInputRejectsOversizedRequest(t *testing.T) {
	var request authVerifyRequest
	input := `{"method":"pin","secret":"` + strings.Repeat("x", backendMaxRequestBytes) + `"}`
	if err := decodeInputReader(bytes.NewBufferString(input), &request); err == nil {
		t.Fatal("oversized backend request was accepted")
	}
}

func TestMcpStatusSkipsUnneededProcessInitialization(t *testing.T) {
	if operationNeedsProcessInitialization("mcp-status") {
		t.Fatal("mcp-status unexpectedly initializes logging or the workspace schema")
	}
	for _, operation := range []string{"startup", "workspace", "ssh"} {
		if !operationNeedsProcessInitialization(operation) {
			t.Fatalf("%s unexpectedly skips process initialization", operation)
		}
	}
}

func TestEnsureMigrationSchemaBootstrapsTunnelStorageWithoutLegacyApp(t *testing.T) {
	database, err := openDatabase(filepath.Join(t.TempDir(), "wormhole.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	if exists, err := tableExists(database, "TunnelConfigs"); err != nil || !exists {
		t.Fatalf("TunnelConfigs exists = %v, %v", exists, err)
	}
}

func TestEnsureMigrationSchemaAddsNodeTunnelColumnsAndLegacyMarker(t *testing.T) {
	database, err := openDatabase(filepath.Join(t.TempDir(), "wormhole.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TABLE Nodes (Id TEXT PRIMARY KEY NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	columns, err := tableColumns(database, "Nodes")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := columns["TunnelEnabled"]; !ok {
		t.Fatal("TunnelEnabled was not added")
	}
	if _, ok := columns["TunnelConfigId"]; !ok {
		t.Fatal("TunnelConfigId was not added")
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM __migration_history WHERE Id = '0003_add_tunnel_config';`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration marker count = %d, %v", count, err)
	}
}

func TestStartupMigrationsAlreadyAppliedUsesCompletionMarkers(t *testing.T) {
	databasePath := prepareStartupTestDatabase(t)
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	completed, err := startupMigrationsAlreadyApplied(database)
	if err != nil || !completed {
		t.Fatalf("startup migrations complete = %v, %v", completed, err)
	}
	if _, err := database.Exec(`DELETE FROM __migration_history WHERE Id = ?;`, tunnelConfigMigrationID); err != nil {
		t.Fatal(err)
	}
	completed, err = startupMigrationsAlreadyApplied(database)
	if err != nil || completed {
		t.Fatalf("startup migrations complete without schema marker = %v, %v", completed, err)
	}
}

func TestLoadStartupSnapshotReturnsUnlockedWorkspaceAndSettings(t *testing.T) {
	databasePath := prepareStartupTestDatabase(t)
	startup, err := loadStartupSnapshot(databasePath, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if startup.Auth.Configured {
		t.Fatal("fresh startup unexpectedly requires authentication")
	}
	if startup.Workspace == nil || len(startup.Workspace.Tree) != 1 || startup.Workspace.Tree[0].ID != "startup-node" {
		t.Fatalf("unexpected startup workspace: %#v", startup.Workspace)
	}
	if !startup.Settings.PromptBeforeTunnelConnect || !startup.Settings.AutoCheckForUpdates {
		t.Fatalf("unexpected default startup settings: %#v", startup.Settings)
	}
	if startup.Settings.Theme != applicationThemeSystem {
		t.Fatalf("unexpected default startup theme: %q", startup.Settings.Theme)
	}
	if startup.Migration.Status != "already-completed" || startup.MigrationFailed {
		t.Fatalf("unexpected migration result: %#v, failed=%v", startup.Migration, startup.MigrationFailed)
	}
}

func TestLoadStartupSnapshotPersistsLegacySettingsInBootstrapProcess(t *testing.T) {
	databasePath := prepareStartupTestDatabase(t)
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey: 5,
		bwCliKeyServerRegion:     bitwardenCliServerEurope,
	})

	if _, err := loadStartupSnapshot(databasePath, "", nil); err != nil {
		t.Fatal(err)
	}
	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if version := readSettingsInteger(document, settingsSchemaVersionKey); version != currentSettingsSchemaVersion {
		t.Fatalf("settings schema version = %d", version)
	}
}

func TestLoadStartupSnapshotKeepsLockedWorkspacePrivate(t *testing.T) {
	databasePath := prepareStartupTestDatabase(t)
	storePath, settingsPath := authPaths(databasePath)
	verifier, err := newAuthVerifier("1234")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAuthDocument(storePath, authDocument{Version: authStoreVersion, Pin: verifier}); err != nil {
		t.Fatal(err)
	}
	settings := defaultAuthSettings()
	settings.Mode = 1
	if err := saveAuthSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}

	legacyTheme := "dark"
	startup, err := loadStartupSnapshot(databasePath, "", &legacyTheme)
	if err != nil {
		t.Fatal(err)
	}
	if !startup.Auth.Configured {
		t.Fatal("configured startup was reported as unlocked")
	}
	if startup.Workspace != nil {
		t.Fatalf("locked startup exposed workspace: %#v", startup.Workspace)
	}
	if startup.Settings.Theme != applicationThemeDark ||
		!startup.ThemeMigration.Handled || !startup.ThemeMigration.Migrated {
		t.Fatalf("locked startup did not import the legacy theme: %#v", startup)
	}

	failed, err := unlockStartup(databasePath, authVerifyRequest{Method: "pin", Secret: "0000"})
	if err != nil {
		t.Fatal(err)
	}
	if failed.Succeeded || failed.Workspace != nil {
		t.Fatalf("failed unlock exposed workspace: %#v", failed)
	}
	succeeded, err := unlockStartup(databasePath, authVerifyRequest{Method: "pin", Secret: "1234"})
	if err != nil {
		t.Fatal(err)
	}
	if !succeeded.Succeeded || succeeded.Workspace == nil || len(succeeded.Workspace.Tree) != 1 {
		t.Fatalf("successful startup unlock did not return workspace: %#v", succeeded)
	}
}

func prepareStartupTestDatabase(t *testing.T) string {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`
CREATE TABLE Nodes (
    Id TEXT PRIMARY KEY NOT NULL,
    ParentId TEXT NULL,
    Name TEXT NOT NULL,
    Kind INTEGER NOT NULL,
    SortOrder INTEGER NOT NULL DEFAULT 0,
    Protocol INTEGER NULL,
    Host TEXT NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, SortOrder, Protocol, Host)
VALUES ('startup-node', NULL, 'Startup connection', 1, 0, 0, 'startup.example');`); err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO ElectronMigrations (Id, AppliedAt, Status, MigratedCount, MissingCount)
VALUES (?, '2026-01-01T00:00:00Z', 'completed', 0, 0);`, windowsCredentialMigrationID); err != nil {
		t.Fatal(err)
	}
	return databasePath
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
	if !workspace.Credentials[0].CanEdit || !workspace.Credentials[0].CanDelete {
		t.Fatalf("unexpected Bitwarden profile capabilities: %#v", workspace.Credentials[0])
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

func TestWorkspaceDoesNotOfferEditForUnsupportedCredentialProtocol(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO CredentialProfiles (Id, Name, Kind, Protocol, SecretProvider, CreatedAt)
VALUES ('33333333-3333-4333-8333-333333333333', 'Unexpected HTTP credential', 0, 3, 0, 'now');`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].CanEdit || !workspace.Credentials[0].CanDelete {
		t.Fatalf("unexpected unsupported-protocol capabilities: %#v", workspace.Credentials)
	}
}

func TestWorkspaceProjectsCredentialKindsAndFiltersKeysFromPasswordOnlyProtocols(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO CredentialProfiles (Id, Name, Kind, Protocol, SecretProvider, CreatedAt) VALUES
    ('10000000-0000-4000-8000-000000000001', 'SSH key', 1, 0, 0, 'now'),
    ('10000000-0000-4000-8000-000000000002', 'Invalid RDP key', 1, 1, 0, 'now'),
    ('10000000-0000-4000-8000-000000000003', 'RDP password', 0, 1, 0, 'now'),
    ('10000000-0000-4000-8000-000000000004', 'Invalid VNC key', 1, 6, 0, 'now'),
    ('10000000-0000-4000-8000-000000000005', 'VNC password', 0, 6, 0, 'now'),
    ('10000000-0000-4000-8000-000000000006', 'Unsupported SSH credential', 9, 0, 0, 'now');`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 6 {
		t.Fatalf("credentials = %#v", workspace.Credentials)
	}
	kinds := make(map[string]string, len(workspace.Credentials))
	for _, credential := range workspace.Credentials {
		kinds[credential.Name] = credential.Kind
	}
	if kinds["SSH key"] != "sshKey" || kinds["Invalid RDP key"] != "sshKey" ||
		kinds["RDP password"] != "password" || kinds["Unsupported SSH credential"] != "unsupported" {
		t.Fatalf("credential kinds = %#v", kinds)
	}
	if options := workspace.CredentialOptions["ssh"]; len(options) != 1 || options[0].Name != "SSH key" {
		t.Fatalf("SSH options = %#v", options)
	}
	if options := workspace.CredentialOptions["rdp"]; len(options) != 1 || options[0].Name != "RDP password" {
		t.Fatalf("RDP options = %#v", options)
	}
	if options := workspace.CredentialOptions["vnc"]; len(options) != 1 || options[0].Name != "VNC password" {
		t.Fatalf("VNC options = %#v", options)
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

func TestCredentialCrudStoresOnlyProtectedReferences(t *testing.T) {
	installUnjournaledCredentialSecretStoreTest(t)
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	deleted := make([]string, 0)
	storeCount := 0
	credentialSecretStore = func(id, _ string, password string) (string, string, error) {
		if password == "" {
			t.Fatal("the password should have been validated before storing")
		}
		storeCount++
		return fmt.Sprintf("protected-reference-%s-%d", id, storeCount), "test-protected-v1", nil
	}
	credentialSecretDelete = func(id, encoded, encoding string) error {
		deleted = append(deleted, id+":"+encoded+":"+encoding)
		return nil
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name:     "Production SSH",
		Protocol: "ssh",
		Username: "operator",
		Password: "do-not-store-me",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validCredentialID(created.ID) || created.Protocol != "ssh" || created.Kind != "password" ||
		created.Username != "operator" || created.Provider != "Local" {
		t.Fatalf("unexpected created credential: %#v", created)
	}

	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	var storedSecret, encoding string
	if err := database.QueryRow("SELECT Secret, Encoding FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&storedSecret, &encoding); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if strings.Contains(storedSecret, "do-not-store-me") || encoding != "test-protected-v1" {
		t.Fatalf("credential secret was not protected: secret=%q encoding=%q", storedSecret, encoding)
	}

	updated, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Production RDP", Protocol: "rdp", Username: "administrator", Domain: "CORP", Password: "new-password",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Protocol != "rdp" || updated.Kind != "password" || updated.Domain != "CORP" {
		t.Fatalf("credential update was not returned: %#v", updated)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].Name != "Production RDP" || workspace.Credentials[0].Protocol != "rdp" {
		t.Fatalf("workspace did not return the saved credential: %#v", workspace.Credentials)
	}

	_, err = createCredential(databasePath, credentialCreateRequest{
		Name: "Production RDP", Protocol: "vnc", Password: "vnc-password",
	})
	if err == nil || err.Error() != "a credential with this name already exists" {
		t.Fatalf("duplicate credential name should be rejected, got %v", err)
	}

	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: created.ID}); err != nil {
		t.Fatal(err)
	}
	workspace, err = loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 0 {
		t.Fatalf("credential was not deleted: %#v", workspace.Credentials)
	}
	if len(deleted) != 2 || !strings.Contains(deleted[0], created.ID) || !strings.Contains(deleted[1], created.ID) {
		t.Fatalf("protected credential cleanup was not requested: %#v", deleted)
	}
}

func TestCredentialCreationRejectsBitwardenProfiles(t *testing.T) {
	for _, provider := range []string{"Bitwarden", " bitwarden ", "BITWARDEN"} {
		t.Run(provider, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			_, err := createCredential(databasePath, credentialCreateRequest{
				Name:              "Vault item",
				Protocol:          "ssh",
				Username:          "operator",
				Provider:          provider,
				BitwardenItemID:   "vault-item",
				BitwardenItemName: "Production",
			})
			if err == nil || err.Error() != "Bitwarden credential profiles cannot be created manually" {
				t.Fatalf("Bitwarden credential creation should be rejected, got %v", err)
			}
			if _, statErr := os.Stat(databasePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected Bitwarden creation touched credential storage: %v", statErr)
			}
		})
	}
}

func TestCredentialUpdateKeepsPreviousSecretWhenDatabaseWriteFails(t *testing.T) {
	installUnjournaledCredentialSecretStoreTest(t)
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	deleted := make([]string, 0)
	storeCount := 0
	credentialSecretStore = func(id, _ string, password string) (string, string, error) {
		storeCount++
		return fmt.Sprintf("reference-%d", storeCount), "test-protected-v1", nil
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
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "operator", Password: "old-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TRIGGER reject_credential_update
BEFORE UPDATE ON CredentialProfiles
BEGIN
    SELECT RAISE(FAIL, 'simulated write failure');
END;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Changed", Protocol: "ssh", Username: "operator", Password: "new-password",
		},
	})
	if err == nil {
		t.Fatal("update should fail when the profile write is rejected")
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name, storedReference string
	if err := database.QueryRow(`
SELECT p.Name, s.Secret
FROM CredentialProfiles p JOIN CredentialSecrets s ON s.Id = p.Id
WHERE p.Id = ?;`, created.ID).Scan(&name, &storedReference); err != nil {
		t.Fatal(err)
	}
	if name != "SSH" || storedReference != "reference-1" {
		t.Fatalf("failed update changed persisted state: name=%q secret=%q", name, storedReference)
	}
	if len(deleted) != 1 || deleted[0] != "reference-2" {
		t.Fatalf("staged replacement was not cleaned up: %#v", deleted)
	}
}

func TestCredentialUpdateWithoutNewPasswordDoesNotDeleteExistingPlatformSecretOnFailure(t *testing.T) {
	installUnjournaledCredentialSecretStoreTest(t)
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	credentialSecretStore = func(_, _, _ string) (string, string, error) {
		return "existing-reference", "test-protected-v1", nil
	}
	deleteCount := 0
	credentialSecretDelete = func(string, string, string) error {
		deleteCount++
		return nil
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "operator", Password: "existing-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TRIGGER reject_credential_update_without_password
BEFORE UPDATE ON CredentialProfiles
BEGIN
    SELECT RAISE(FAIL, 'simulated write failure');
END;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Changed", Protocol: "ssh", Username: "operator",
		},
	})
	if err == nil {
		t.Fatal("update should fail when the profile write is rejected")
	}
	if deleteCount != 0 {
		t.Fatalf("failed metadata-only update tried to delete the existing platform secret %d time(s)", deleteCount)
	}
}

func TestCredentialUpdateRechecksReadOnlyStateAtWrite(t *testing.T) {
	installUnjournaledCredentialSecretStoreTest(t)
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	credentialSecretStore = func(id, _ string, password string) (string, string, error) {
		if password == "initial" {
			return "original-reference", "test-protected-v1", nil
		}
		database, err := openDatabase(databasePath, false)
		if err != nil {
			return "", "", err
		}
		_, updateErr := database.Exec("UPDATE CredentialProfiles SET SecretProvider = 2 WHERE lower(Id) = ?;", normalizeID(id))
		database.Close()
		if updateErr != nil {
			return "", "", updateErr
		}
		return "staged-reference", "test-protected-v1", nil
	}
	deleted := make([]string, 0)
	credentialSecretDelete = func(_ string, encoded, _ string) error {
		deleted = append(deleted, encoded)
		return nil
	}
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "operator", Password: "initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "Changed", Protocol: "ssh", Username: "operator", Password: "replacement",
		},
	})
	if err == nil {
		t.Fatal("update should not convert a concurrently changed provider into a local credential")
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name string
	var provider int
	if err := database.QueryRow("SELECT Name, SecretProvider FROM CredentialProfiles WHERE Id = ?;", created.ID).Scan(&name, &provider); err != nil {
		t.Fatal(err)
	}
	if name != "SSH" || provider != 2 {
		t.Fatalf("read-only state was overwritten: name=%q provider=%d", name, provider)
	}
	if len(deleted) != 1 || deleted[0] != "staged-reference" {
		t.Fatalf("staged replacement was not cleaned up: %#v", deleted)
	}
}

func TestCredentialUpdateCanonicalizesLegacySecretIDCase(t *testing.T) {
	installUnjournaledCredentialSecretStoreTest(t)
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	credentialSecretStore = func(_, _, _ string) (string, string, error) {
		return "replacement-reference", "test-protected-v1", nil
	}
	credentialSecretDelete = func(string, string, string) error { return nil }
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "operator", Password: "initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	upperID := strings.ToUpper(created.ID)
	if _, err := database.Exec("UPDATE CredentialSecrets SET Id = ? WHERE Id = ?;", upperID, created.ID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	_, err = updateCredential(databasePath, credentialUpdateRequest{
		ID: upperID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "SSH updated", Protocol: "ssh", Username: "operator", Password: "replacement",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	var storedID, storedReference string
	if err := database.QueryRow(
		"SELECT COUNT(*), MIN(Id), MIN(Secret) FROM CredentialSecrets WHERE lower(Id) = ?;",
		created.ID,
	).Scan(&count, &storedID, &storedReference); err != nil {
		t.Fatal(err)
	}
	if count != 1 || storedID != created.ID || storedReference != "replacement-reference" {
		t.Fatalf("legacy id variants were not canonicalized: count=%d id=%q secret=%q", count, storedID, storedReference)
	}
}

func TestCredentialDeleteSupportsLegacyKeyAndBitwardenProfiles(t *testing.T) {
	previousDelete := credentialSecretDelete
	credentialSecretDelete = func(string, string, string) error { return nil }
	t.Cleanup(func() { credentialSecretDelete = previousDelete })

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	keyID := "11111111-1111-4111-8111-111111111111"
	bitwardenID := "22222222-2222-4222-8222-222222222222"
	if _, err := database.Exec(`
INSERT INTO CredentialProfiles (Id, Name, Kind, Protocol, SecretProvider, CreatedAt)
VALUES (?, 'Imported key', 1, 0, 0, 'now'), (?, 'Vault item', 0, 0, 1, 'now');`, keyID, bitwardenID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	keyDirectory := filepath.Join(filepath.Dir(databasePath), "keys")
	if err := os.MkdirAll(keyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDirectory, strings.ReplaceAll(keyID, "-", "")+".dpapi")
	if err := os.WriteFile(keyPath, []byte("protected-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: keyID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private key file was not removed: %v", err)
	}
	if err := deleteCredential(databasePath, credentialDeleteRequest{ID: bitwardenID}); err != nil {
		t.Fatal(err)
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 0 {
		t.Fatalf("legacy profiles were not deleted: %#v", workspace.Credentials)
	}
}

func TestCredentialValidationMatchesSupportedProtocols(t *testing.T) {
	tests := []struct {
		name    string
		request credentialCreateRequest
		valid   bool
	}{
		{"blank name", credentialCreateRequest{Protocol: "ssh", Username: "user", Password: "password"}, false},
		{"SSH needs username", credentialCreateRequest{Name: "SSH", Protocol: "ssh", Password: "password"}, false},
		{"RDP needs domain", credentialCreateRequest{Name: "RDP", Protocol: "rdp", Username: "user", Password: "password"}, false},
		{"VNC can omit username", credentialCreateRequest{Name: "VNC", Protocol: "vnc", Password: "password"}, true},
		{"HTTP is not a credential protocol", credentialCreateRequest{Name: "HTTP", Protocol: "http", Password: "password"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeCredentialDraft(test.request, false)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, err=%v", test.valid, err)
			}
		})
	}
}

func TestWindowsCredentialCreationUsesDPAPI(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("Windows DPAPI is Windows-only")
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name:     "DPAPI credential",
		Protocol: "ssh",
		Username: "operator",
		Password: "integration-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	var encoding string
	if err := database.QueryRow("SELECT Encoding FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&encoding); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if encoding != protectedSecretEncoding {
		t.Fatalf("credential did not use DPAPI encoding: %q", encoding)

	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := readCredentialSecret(database, created.ID)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "integration-password" {
		t.Fatal("credential could not be read back through the DPAPI provider")
	}
}
