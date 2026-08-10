package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seedLegacyBitwardenCredential(
	t *testing.T,
	databasePath string,
	request credentialCreateRequest,
) credentialRecord {
	t.Helper()
	draft, err := normalizeCredentialDraft(request, true)
	if err != nil {
		t.Fatal(err)
	}
	if draft.provider != 1 {
		t.Fatal("legacy Bitwarden fixture needs a Bitwarden provider")
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := ensureCredentialWriteSchema(database); err != nil {
		t.Fatal(err)
	}
	id, err := newCredentialID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
INSERT INTO CredentialProfiles
    (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol, SecretProvider,
     BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
VALUES (?, ?, ?, ?, 0, NULL, ?, 1, ?, ?, ?, ?);`,
		id, draft.name, nullableCredentialField(draft.username), nullableCredentialField(draft.domain),
		draft.protocolValue, draft.itemID, nullableCredentialField(draft.itemName), draft.fieldPath,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	return credentialRecord{ID: id}
}

func TestBitwardenVirtualCredentialIDsMatchWinUI(t *testing.T) {
	tests := []struct {
		protocol int64
		expected string
	}{
		{0, "e3753518-250f-9e77-0a7d-55f1ff7bac30"},
		{1, "ce5ff631-93a3-1ec1-9fb3-e14dda13519c"},
		{6, "9e9a0857-4971-5beb-acef-cd9c14228169"},
	}
	for _, test := range tests {
		if actual := bitwardenVirtualCredentialID("item-1", test.protocol); actual != test.expected {
			t.Fatalf("protocol %d id = %q, want %q", test.protocol, actual, test.expected)
		}
	}
}

func TestBitwardenCredentialCacheFullSyncPrunesAndProjectsVirtualProfile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureCredentialWriteSchema(database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	if count, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{
		{ID: "item-1", Name: "One", Username: "alice"},
		{ID: "item-2", Name: "Two", Username: "bob"},
	}, now); err != nil || count != 2 {
		t.Fatalf("initial cache replacement = %d, %v", count, err)
	}
	if count, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{
		{ID: "item-2", Name: "Two updated", Username: "robert"},
	}, now.Add(time.Minute)); err != nil || count != 1 {
		t.Fatalf("second cache replacement = %d, %v", count, err)
	}

	settings := defaultBitwardenCliSettings()
	settings.Enabled = true
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 {
		t.Fatalf("credentials = %#v", workspace.Credentials)
	}
	credential := workspace.Credentials[0]
	if credential.ID != bitwardenVirtualCredentialID("item-2", 0) ||
		credential.Name != "Two updated" || credential.Kind != "password" || credential.Username != "robert" ||
		!credential.IsVirtualBitwarden || credential.CanEdit || credential.CanDelete {
		t.Fatalf("virtual credential = %#v", credential)
	}
}

func TestBitwardenVirtualProfilesLoadBeforeCredentialTableExists(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if _, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{
		{ID: "item-1", Name: "First launch", Username: "alice"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	settings := defaultBitwardenCliSettings()
	settings.Enabled = true
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}

	profiles, err := loadCredentialsForProtocol(databasePath, "rdp")
	if err != nil || len(profiles) != 1 || profiles[0].ID != bitwardenVirtualCredentialID("item-1", 1) {
		t.Fatalf("first-launch RDP profiles = %#v, %v", profiles, err)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for protocol, protocolValue := range map[string]int64{"ssh": 0, "rdp": 1, "vnc": 6} {
		options := workspace.CredentialOptions[protocol]
		if len(options) != 1 || options[0].ID != bitwardenVirtualCredentialID("item-1", protocolValue) {
			t.Fatalf("workspace %s credential options = %#v", protocol, options)
		}
	}
}

func TestBitwardenCredentialCachePrunesLargeVaultWithoutSqlParameterFanout(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	items := make([]bitwardenCliLoginItem, 1500)
	for index := range items {
		items[index] = bitwardenCliLoginItem{
			ID:   fmt.Sprintf("item-%04d", index),
			Name: fmt.Sprintf("Item %04d", index),
		}
	}
	stamp := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	if count, err := replaceBitwardenCredentialCache(databasePath, items, stamp); err != nil || count != len(items) {
		t.Fatalf("large cache replacement = %d, %v", count, err)
	}
	if count, err := replaceBitwardenCredentialCache(databasePath, items[:1], stamp); err != nil || count != 1 {
		t.Fatalf("same-stamp cache replacement = %d, %v", count, err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	entries, err := loadBitwardenCredentialCache(database)
	if err != nil || len(entries) != 1 || entries[0].ItemID != items[0].ID {
		t.Fatalf("pruned entries = %#v, %v", entries, err)
	}
}

func TestBitwardenCliLoginItemValidationBoundsUntrustedOutput(t *testing.T) {
	valid, err := bitwardenCliMapLoginItem(map[string]any{
		"id":   " item-1 ",
		"name": " Server ",
		"login": map[string]any{
			"username": " CORP\\alice ",
			"password": " secret ",
		},
	}, true)
	if err != nil || valid == nil || valid.ID != "item-1" || valid.Username != "CORP\\alice" || valid.Password != " secret " {
		t.Fatalf("valid item = %#v, %v", valid, err)
	}
	if _, err := bitwardenCliMapLoginItem(map[string]any{
		"id": "item-1",
		"login": map[string]any{
			"password": strings.Repeat("x", maxStoredCredentialPassword+1),
		},
	}, true); err == nil {
		t.Fatal("oversized Bitwarden password was accepted")
	}
}

func TestBitwardenCliLoginItemPreservesOpaquePasswordCharacters(t *testing.T) {
	password := "line one\nline two\t\x00tail"
	item, err := bitwardenCliMapLoginItem(map[string]any{
		"id":   "item-id",
		"name": "Item",
		"login": map[string]any{
			"username": "user",
			"password": password,
		},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if item == nil || item.Password != password {
		t.Fatalf("password was not preserved: %#v", item)
	}
}

func TestSplitRdpDomainUsernameMatchesWinUI(t *testing.T) {
	username, domain := splitRdpDomainUsername(" CORP\\alice ")
	if username != "alice" || domain != "CORP" {
		t.Fatalf("split identity = %q / %q", username, domain)
	}
	username, domain = splitRdpDomainUsername("alice")
	if username != "alice" || domain != "" {
		t.Fatalf("plain identity = %q / %q", username, domain)
	}
}

func TestResolveNodeRdpIdentityStopsAtSavedCredentialBoundary(t *testing.T) {
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
    Username TEXT NULL,
    RdpDomain TEXT NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Username, RdpDomain, CredentialId, CredentialMode) VALUES
    ('parent', NULL, 'parent-user', 'PARENT', NULL, NULL),
    ('leaf', 'parent', ' ACME\alice ', NULL, 'credential-id', 2);`)
	if err != nil {
		t.Fatal(err)
	}
	username, domain, err := resolveNodeRdpIdentity(database, "leaf")
	if err != nil || username != `ACME\alice` || domain != "" {
		t.Fatalf("resolved node identity = %q / %q, %v", username, domain, err)
	}
}

func TestLinkedBitwardenCredentialSuppressesPageProjectionAndResolvesInheritance(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	profile := seedLegacyBitwardenCredential(t, databasePath, credentialCreateRequest{
		Name: "RDP vault", Protocol: "rdp", Username: "alice", Domain: "CORP",
		Provider: "Bitwarden", BitwardenItemID: "item-1", BitwardenItemName: "RDP item",
	})
	if _, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{
		{ID: "item-1", Name: "RDP item", Username: "alice"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	settings := defaultBitwardenCliSettings()
	settings.Enabled = true
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}

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
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, CredentialId, CredentialMode)
VALUES
    ('folder', NULL, 'Folder', 0, NULL, ?, 2),
    ('connection', 'folder', 'RDP', 1, 1, NULL, 0);`, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := resolveNodeCredentialID(database, "connection", 1)
	if err != nil || reference != profile.ID {
		t.Fatalf("resolved credential = %q, %v", reference, err)
	}
	resolved, found, err := resolveBitwardenCredentialReference(database, reference, 1)
	if err != nil || !found || resolved.ItemID != "item-1" || resolved.Virtual {
		t.Fatalf("resolved Bitwarden reference = %#v, %v, %v", resolved, found, err)
	}

	workspace, err := loadWorkspace(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Credentials) != 1 || workspace.Credentials[0].ID != profile.ID {
		t.Fatalf("linked item was duplicated by a virtual page profile: %#v", workspace.Credentials)
	}
	rdpProfiles, err := loadCredentialsForProtocol(databasePath, "rdp")
	if err != nil || len(rdpProfiles) != 1 || rdpProfiles[0].ID != profile.ID {
		t.Fatalf("RDP picker profiles = %#v, %v", rdpProfiles, err)
	}
	sshProfiles, err := loadCredentialsForProtocol(databasePath, "ssh")
	if err != nil || len(sshProfiles) != 1 ||
		sshProfiles[0].ID != bitwardenVirtualCredentialID("item-1", 0) ||
		!sshProfiles[0].IsVirtualBitwarden {
		t.Fatalf("SSH picker profiles = %#v, %v", sshProfiles, err)
	}
	if err := updateWorkspaceNodeCredentialSettings(databasePath, workspaceNodeCredentialSettingsRequest{
		NodeID: "connection", Mode: 2, CredentialID: sshProfiles[0].ID,
	}); err == nil {
		t.Fatal("RDP connection accepted an SSH virtual credential")
	}
	if err := updateWorkspaceNodeCredentialSettings(databasePath, workspaceNodeCredentialSettingsRequest{
		NodeID: "connection", Mode: 1,
	}); err != nil {
		t.Fatal(err)
	}
	var mode int
	var storedID sql.NullString
	if err := database.QueryRow(
		"SELECT CredentialMode, CredentialId FROM Nodes WHERE Id = 'connection';",
	).Scan(&mode, &storedID); err != nil {
		t.Fatal(err)
	}
	if mode != 1 || storedID.Valid {
		t.Fatalf("cleared credential assignment = mode %d, id %#v", mode, storedID)
	}
}

func TestResolveNodeCredentialIDUnknownModeStopsSavedCredentialInheritance(t *testing.T) {
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
    Protocol INTEGER NULL,
    CredentialId TEXT NULL,
    CredentialMode INTEGER NULL,
    UseInlinePassword INTEGER NULL
);
INSERT INTO Nodes (Id, ParentId, Protocol, CredentialId, CredentialMode) VALUES
    ('folder', NULL, 1, 'parent-credential', 2),
    ('leaf', 'folder', 1, NULL, 99);`)
	if err != nil {
		t.Fatal(err)
	}

	credentialID, err := resolveNodeCredentialID(database, "leaf", 1)
	if err != nil {
		t.Fatal(err)
	}
	if credentialID != "" {
		t.Fatalf("unknown credential mode inherited %q", credentialID)
	}
}

func TestCredentialCanTransitionBetweenLocalAndBitwardenWithoutOrphanedSecret(t *testing.T) {
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	credentialSecretStore = func(_ string, password string) (string, string, error) {
		return "protected-" + password, "test-protected-v1", nil
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

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "alice", Password: "local-secret", Provider: "Local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "SSH renamed", Protocol: "ssh", Username: "alice", Provider: "Local",
		},
	}); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	var preserved string
	if err := database.QueryRow("SELECT Secret FROM CredentialSecrets WHERE Id = ?;", created.ID).Scan(&preserved); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if preserved != "protected-local-secret" || len(deleted) != 0 {
		t.Fatalf("blank local edit replaced the saved secret: secret=%q deleted=%#v", preserved, deleted)
	}
	if _, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "SSH renamed", Protocol: "ssh", Username: "alice", Provider: "Bitwarden",
			BitwardenItemID: "item-1", BitwardenItemName: "SSH item",
		},
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM CredentialSecrets WHERE lower(Id) = ?;", created.ID).Scan(&count); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	if count != 0 || len(deleted) != 1 || deleted[0] != "protected-local-secret" {
		t.Fatalf("local-to-Bitwarden cleanup: count=%d deleted=%#v", count, deleted)
	}

	if _, err := updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "SSH", Protocol: "ssh", Username: "alice", Password: "new-local", Provider: "Local",
		},
	}); err != nil {
		t.Fatal(err)
	}
	database, err = openDatabase(databasePath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var provider int
	var itemID sql.NullString
	var encoded string
	if err := database.QueryRow(`
SELECT p.SecretProvider, p.BitwardenItemId, s.Secret
FROM CredentialProfiles p JOIN CredentialSecrets s ON s.Id = p.Id
WHERE p.Id = ?;`, created.ID).Scan(&provider, &itemID, &encoded); err != nil {
		t.Fatal(err)
	}
	if provider != 0 || itemID.Valid || encoded != "protected-new-local" {
		t.Fatalf("Bitwarden-to-local state: provider=%d item=%#v secret=%q", provider, itemID, encoded)
	}
}

func TestCredentialBlankEditRequiresAnExistingLocalSecret(t *testing.T) {
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	credentialSecretStore = func(_ string, password string) (string, string, error) {
		return "protected-" + password, "test-protected-v1", nil
	}
	credentialSecretDelete = func(_, _, _ string) error { return nil }
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
	})

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	created, err := createCredential(databasePath, credentialCreateRequest{
		Name: "SSH", Protocol: "ssh", Username: "alice", Password: "local-secret", Provider: "Local",
	})
	if err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("DELETE FROM CredentialSecrets WHERE lower(Id) = ?;", created.ID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = updateCredential(databasePath, credentialUpdateRequest{
		ID: created.ID,
		credentialCreateRequest: credentialCreateRequest{
			Name: "SSH renamed", Protocol: "ssh", Username: "alice", Provider: "Local",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "password is missing") {
		t.Fatalf("blank edit accepted a missing local secret: %v", err)
	}
}
