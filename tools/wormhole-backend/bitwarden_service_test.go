package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHandleBitwardenDispatchesVaultLifecycle(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Bitwarden service fixture is built as a Windows executable")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	helper := buildBitwardenServiceHelper(t)
	settings := bitwardenCliSettings{
		Enabled: true,
		Path:    helper,
		// Current avoids a logout/config detour in the login command while the dedicated
		// set-config test below still covers session invalidation after a real change.
		ServerRegion: bitwardenCliServerCurrent,
	}
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var output bytes.Buffer
	manager := newVncManager(database, newBackendLineWriter(&output))
	manager.databasePath = databasePath
	generation := manager.bitwardenGeneration()
	commands := []backendCommand{
		{ID: "read", Action: "bitwarden.read"},
		{ID: "ensure", Action: "bitwarden.ensure-installed"},
		{ID: "status", Action: "bitwarden.status"},
		{ID: "login", Action: "bitwarden.login", Email: "operator@example.com", MasterPassword: "master", AuthenticatorCode: "123 456"},
		{ID: "list", Action: "bitwarden.list", Query: "site"},
		{ID: "search", Action: "bitwarden.search", Query: "site"},
		{ID: "get", Action: "bitwarden.get", ItemID: "item-1"},
		{ID: "sync", Action: "bitwarden.sync"},
		{ID: "sync-stale", Action: "bitwarden.sync-if-stale"},
		{ID: "logout", Action: "bitwarden.logout"},
		{ID: "unlock", Action: "bitwarden.unlock", MasterPassword: "master"},
	}
	for _, command := range commands {
		manager.handleBitwarden(command, generation)
	}
	if manager.bitwardenSession() != "session-key" {
		t.Fatalf("session after unlock = %q", manager.bitwardenSession())
	}

	responses := decodeBackendResponses(t, output.Bytes())
	if len(responses) != len(commands) {
		t.Fatalf("responses = %d, want %d: %#v", len(responses), len(commands), responses)
	}
	for _, response := range responses {
		if !response.OK {
			t.Fatalf("Bitwarden action %q failed: %s", response.ID, response.Error)
		}
	}
}

func TestHandleBitwardenCoversValidationAndSessionInvalidation(t *testing.T) {
	previousInstall := installBitwardenCliForService
	installBitwardenCliForService = func(string) (any, error) {
		return nil, errors.New("fixture install failure")
	}
	t.Cleanup(func() { installBitwardenCliForService = previousInstall })

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var output bytes.Buffer
	manager := newVncManager(database, newBackendLineWriter(&output))
	manager.databasePath = databasePath
	generation := manager.bitwardenGeneration()

	enabled := false
	commands := []backendCommand{
		{ID: "disable", Action: "bitwarden.set-enabled", Enabled: &enabled},
		{ID: "config-invalid", Action: "bitwarden.set-config", ServerRegion: -1},
		{ID: "login-disabled", Action: "bitwarden.login", Email: "operator@example.com", MasterPassword: "master"},
		{ID: "unlock-disabled", Action: "bitwarden.unlock", MasterPassword: "master"},
		{ID: "list-disabled", Action: "bitwarden.list"},
		{ID: "search-disabled", Action: "bitwarden.search"},
		{ID: "get-disabled", Action: "bitwarden.get", ItemID: "item"},
		{ID: "sync-disabled", Action: "bitwarden.sync"},
		{ID: "sync-stale-disabled", Action: "bitwarden.sync-if-stale"},
		{ID: "credential-invalid", Action: "bitwarden.resolve-credential", CredentialID: "credential", Protocol: "invalid"},
		{ID: "node-invalid", Action: "bitwarden.resolve-node", NodeID: "node", Protocol: "invalid"},
		{ID: "reference-invalid", Action: "bitwarden.node-reference", NodeID: "node", Protocol: "invalid"},
		{ID: "rdp-credential", Action: "rdp.resolve-credential", CredentialID: "missing"},
		{ID: "rdp-profile", Action: "rdp.resolve-profile", NodeID: "missing", ManualCredentials: true, Username: "operator", Domain: "DOMAIN", Password: "secret"},
		{ID: "rdp-capability", Action: "rdp.system-client-capability", NodeID: "missing"},
		{ID: "rdp-system-profile", Action: "rdp.resolve-system-profile", NodeID: "missing"},
		{ID: "browser-read", Action: "bitwarden.browser-storage-read", ProfilePath: t.TempDir()},
		{ID: "browser-capture", Action: "bitwarden.browser-storage-capture", LocalJSON: `{}`, SessionJSON: `{}`, ProfilePath: t.TempDir()},
		{ID: "browser-seed", Action: "bitwarden.browser-profile-seed", ProfilePath: "", Path: ""},
		{ID: "browser-register", Action: "bitwarden.browser-profile-register", ProfilePath: "", Path: ""},
		{ID: "unsupported", Action: "bitwarden.unsupported"},
	}
	for _, command := range commands {
		manager.handleBitwarden(command, generation)
	}

	manager.handleBitwarden(backendCommand{ID: "install-local-error", Action: "bitwarden.install"}, generation)

	manager.handleBitwarden(backendCommand{ID: "stale-generation", Action: "bitwarden.read"}, generation+1)
	manager.handleBitwarden(backendCommand{ID: "clear", Action: "bitwarden.clear-session"}, generation)
	if manager.bitwardenGeneration() == generation || manager.bitwardenSession() != "" {
		t.Fatal("clear-session did not invalidate the vault generation")
	}

	responses := decodeBackendResponses(t, output.Bytes())
	if len(responses) != len(commands)+3 {
		t.Fatalf("responses = %d, want %d", len(responses), len(commands)+3)
	}
	byID := make(map[string]backendResponse, len(responses))
	for _, response := range responses {
		byID[response.ID] = response
	}
	if !byID["disable"].OK || !byID["sync-disabled"].OK || !byID["browser-read"].OK || !byID["clear"].OK {
		t.Fatalf("safe validation actions failed: %#v", byID)
	}
	for _, id := range []string{"login-disabled", "credential-invalid", "unsupported", "install-local-error", "stale-generation"} {
		if byID[id].OK || strings.TrimSpace(byID[id].Error) == "" {
			t.Fatalf("%s did not report a bounded error: %#v", id, byID[id])
		}
	}
}

func TestBitwardenServiceHelpersCoverProtocolsStalenessAndDisabledVault(t *testing.T) {
	for protocol, want := range map[string]int64{"ssh": 0, " RDP ": 1, "vnc": 6, "other": -1} {
		if got := bitwardenProtocolValue(protocol); got != want {
			t.Fatalf("protocol %q = %d, want %d", protocol, got, want)
		}
	}
	now := time.Now()
	if !bitwardenSyncIsStale(bitwardenCliSettings{}, now) {
		t.Fatal("missing sync timestamp was treated as fresh")
	}
	recent := now.Add(-time.Minute)
	if bitwardenSyncIsStale(bitwardenCliSettings{LastSyncUtc: &recent}, now) {
		t.Fatal("recent sync was treated as stale")
	}
	old := now.Add(-10 * time.Minute)
	if !bitwardenSyncIsStale(bitwardenCliSettings{LastSyncUtc: &old}, now) {
		t.Fatal("old sync was treated as fresh")
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	manager := newVncManager(nil, newBackendLineWriter(&bytes.Buffer{}))
	manager.databasePath = databasePath
	if err := manager.requireBitwardenEnabled(); err == nil {
		t.Fatal("disabled vault was accepted")
	}
	manager.resetBitwardenSession()
}

func TestBitwardenServiceResolvesLinkedCredentialsAndRefreshesStaleCache(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Bitwarden service fixture is built as a Windows executable")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	profile := seedLegacyBitwardenCredential(t, databasePath, credentialCreateRequest{
		Name: "RDP vault", Protocol: "rdp", Username: "alice", Domain: "CORP",
		Provider: "Bitwarden", BitwardenItemID: "item-1", BitwardenItemName: "RDP item",
	})
	helper := buildBitwardenServiceHelper(t)
	oldSync := time.Now().Add(-time.Hour).UTC()
	settings := bitwardenCliSettings{
		Enabled: true, Path: helper, ServerRegion: bitwardenCliServerCurrent, LastSyncUtc: &oldSync,
	}
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`
INSERT INTO Nodes (Id, ParentId, Name, Kind, Protocol, Host, CredentialId, CredentialMode, CreatedAt, UpdatedAt)
VALUES ('rdp-node', NULL, 'RDP', 1, 1, 'rdp.example', ?, 2, '2026-08-09T00:00:00Z', '2026-08-09T00:00:00Z');`, profile.ID)
	if err != nil {
		t.Fatal(err)
	}

	manager := newVncManager(database, newBackendLineWriter(&bytes.Buffer{}))
	manager.databasePath = databasePath
	if err := manager.setBitwardenSessionForGeneration("session-key", manager.bitwardenGeneration()); err != nil {
		t.Fatal("could not seed the Bitwarden test session")
	}
	resolved, err := manager.resolveBitwardenCredential(profile.ID, 1)
	if err != nil || !resolved.Bitwarden || resolved.Username != "alice" || resolved.Domain != "CORP" || resolved.Password != "secret" {
		t.Fatalf("resolved linked credential = %#v, %v", resolved, err)
	}
	resolved, err = manager.resolveBitwardenNodeCredential("rdp-node", 1)
	if err != nil || !resolved.Bitwarden || resolved.Username != "alice" || resolved.Domain != "CORP" {
		t.Fatalf("resolved node credential = %#v, %v", resolved, err)
	}
	if reference, err := manager.bitwardenNodeReference("rdp-node", 1); err != nil || !reference["bitwarden"] {
		t.Fatalf("node reference = %#v, %v", reference, err)
	}
	if _, err := manager.bitwardenNodeReference("rdp-node", -1); err == nil {
		t.Fatal("negative Bitwarden protocol was accepted")
	}
	if missing, err := manager.resolveBitwardenCredentialRaw("missing", 1); err != nil || missing.Bitwarden {
		t.Fatalf("missing credential = %#v, %v", missing, err)
	}
	if _, err := manager.resolveBitwardenCredentialRaw(profile.ID, -1); err == nil {
		t.Fatal("negative credential protocol was accepted")
	}
	if _, err := (&vncManager{}).resolveBitwardenCredentialRaw(profile.ID, 1); err == nil {
		t.Fatal("credential resolution without a database was accepted")
	}

	result, err := manager.syncBitwardenCredentialsIfStale()
	if err != nil {
		t.Fatal(err)
	}
	if state, ok := result.(map[string]any); !ok || state == nil {
		t.Fatalf("stale sync result = %#v", result)
	}
	settings, err = readBitwardenCliSettings(databasePath)
	if err != nil || settings.LastSyncUtc == nil || !settings.LastSyncUtc.After(oldSync) {
		t.Fatalf("stale sync settings = %#v, %v", settings, err)
	}

	settings.Enabled = false
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.resolveBitwardenCredentialRaw(profile.ID, 1); err == nil {
		t.Fatal("disabled Bitwarden vault resolved a credential")
	}
}

func TestBitwardenVirtualSSHCredentialUsesLiveVaultIdentity(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := ensureElectronWorkspaceSchema(databasePath); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceBitwardenCredentialCache(databasePath, []bitwardenCliLoginItem{
		{ID: "item-1", Name: "SSH", Username: "old-account"},
		{ID: "item-no-username", Name: "SSH without username", Username: "old-account"},
		{ID: "item-no-password", Name: "SSH without password", Username: "old-account"},
		{ID: "item-missing", Name: "Deleted SSH item", Username: "old-account"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	settings := bitwardenCliSettings{
		Enabled: true, Path: buildBitwardenServiceHelper(t), ServerRegion: bitwardenCliServerCurrent,
	}
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		t.Fatal(err)
	}
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := newVncManager(database, newBackendLineWriter(&bytes.Buffer{}))
	manager.databasePath = databasePath
	// This test exercises credential resolution, not session persistence or OS keychains.
	manager.bitwardenSessionKey = "session-key"
	// Both the saved connection and the explicit credential picker must pair the live
	// username with the live password, rather than reuse the catalog's old username.
	for itemID, username := range map[string]string{"item-1": "operator", "item-no-username": ""} {
		t.Run(itemID, func(t *testing.T) {
			credentialID := bitwardenVirtualCredentialID(itemID, 0)
			_, err := database.Exec(`
INSERT INTO Nodes (Id, Name, Kind, Protocol, Host, CredentialId, CredentialMode, CreatedAt, UpdatedAt)
VALUES (?, 'SSH', 1, 0, 'ssh.example', ?, 2, 'now', 'now');`, itemID, credentialID)
			if err != nil {
				t.Fatal(err)
			}
			for name, resolve := range map[string]func() (bitwardenResolvedCredential, error){
				"saved": func() (bitwardenResolvedCredential, error) {
					return manager.resolveBitwardenNodeCredential(itemID, 0)
				},
				"picker": func() (bitwardenResolvedCredential, error) {
					return manager.resolveBitwardenCredential(credentialID, 0)
				},
			} {
				t.Run(name, func(t *testing.T) {
					resolved, err := resolve()
					if err != nil || !resolved.Bitwarden || resolved.Username != username || resolved.Password != "secret" {
						t.Fatalf("virtual SSH identity did not match the live vault item (error: %v)", err)
					}
					target, err := loadSSHTargetWithOverrides(databasePath, itemID, resolved.Username, resolved.Password, true, false)
					if username == "" {
						if err == nil || err.Error() != "SSH connection has no username" {
							t.Fatal("a missing live username reused the stale catalog account")
						}
					} else if err != nil || target.username != username || target.password != "secret" {
						t.Fatalf("saved SSH target did not preserve the resolved vault identity (error: %v)", err)
					}
				})
			}
		})
	}
	for itemID, message := range map[string]string{
		"item-no-password": "the linked Bitwarden item does not contain login.password",
		"item-missing":     "the linked Bitwarden item was not found",
	} {
		t.Run(itemID, func(t *testing.T) {
			resolved, err := manager.resolveBitwardenCredential(bitwardenVirtualCredentialID(itemID, 0), 0)
			if err == nil || err.Error() != message || resolved.Username != "" || resolved.Password != "" {
				t.Fatalf("unavailable live vault item did not fail closed (error: %v)", err)
			}
		})
	}
	t.Run("saved username overrides an empty vault username", func(t *testing.T) {
		_, err := database.Exec(`
INSERT INTO Nodes (Id, Name, Kind, Protocol, Host, Username, CredentialId, CredentialMode, CreatedAt, UpdatedAt)
VALUES ('explicit-user', 'SSH', 1, 0, 'ssh.example', 'connection-user', ?, 2, 'now', 'now');`,
			bitwardenVirtualCredentialID("item-no-username", 0))
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := manager.resolveBitwardenNodeCredential("explicit-user", 0)
		if err != nil || resolved.Username != "" {
			t.Fatal("expected the vault to have no username")
		}
		target, err := loadSSHTargetWithOverrides(databasePath, "explicit-user", resolved.Username, resolved.Password, true, false)
		if err != nil || target.username != "connection-user" || target.password != "secret" {
			t.Fatalf("explicit node username was not preserved (error: %v)", err)
		}
	})
	for _, protocol := range []int64{1, 6} {
		resolved, err := manager.resolveBitwardenCredential(bitwardenVirtualCredentialID("item-1", protocol), protocol)
		if err != nil || resolved.Username != "operator" || resolved.Password != "secret" {
			t.Fatalf("protocol %d did not use the live vault identity (error: %v)", protocol, err)
		}
	}
	legacy := seedLegacyBitwardenCredential(t, databasePath, credentialCreateRequest{
		Name: "SSH override", Protocol: "ssh", Username: "custom-user",
		Provider: "Bitwarden", BitwardenItemID: "item-1",
	})
	resolved, err := manager.resolveBitwardenCredential(legacy.ID, 0)
	if err != nil || resolved.Username != "custom-user" || resolved.Password != "secret" {
		t.Fatalf("legacy explicit username was not preserved (error: %v)", err)
	}
}

func buildBitwardenServiceHelper(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	helper := filepath.Join(directory, "bw.exe")
	source := filepath.Join(directory, "main.go")
	code := `package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 { os.Exit(1) }
	switch os.Args[1] {
	case "status":
		if os.Getenv("BW_SESSION") != "session-key" { fmt.Print("{\"status\":\"locked\"}"); return }
		fmt.Print("{\"status\":\"unlocked\",\"userEmail\":\"operator@example.com\",\"serverUrl\":\"https://vault.bitwarden.com\"}")
	case "login", "unlock":
		fmt.Print("session-key")
	case "logout", "sync", "config":
		fmt.Print("{}")
	case "list":
		fmt.Print("[{\"id\":\"item-1\",\"name\":\"Site\",\"login\":{\"username\":\"operator\",\"password\":\"secret\"}}]")
	case "get":
		if os.Getenv("BW_SESSION") != "session-key" { fmt.Fprint(os.Stderr, "Vault is locked."); os.Exit(1) }
		if os.Args[len(os.Args)-1] == "item-missing" {
			fmt.Fprint(os.Stderr, "Not found.")
			os.Exit(1)
		}
		if os.Args[len(os.Args)-1] == "item-no-password" {
			fmt.Print("{\"id\":\"item-no-password\",\"name\":\"Site\",\"type\":1,\"login\":{\"username\":\"operator\",\"password\":\"\"}}")
			return
		}
		if os.Args[len(os.Args)-1] == "item-no-username" {
			fmt.Print("{\"id\":\"item-no-username\",\"name\":\"Site\",\"type\":1,\"login\":{\"username\":\"\",\"password\":\"secret\"}}")
			return
		}
		fmt.Print("{\"id\":\"item-1\",\"name\":\"Site\",\"type\":1,\"login\":{\"username\":\"operator\",\"password\":\"secret\"}}")
	default:
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(source, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", helper, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("could not build Bitwarden fixture: %v\n%s", err, output)
	}
	return helper
}

func decodeBackendResponses(t *testing.T, data []byte) []backendResponse {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var responses []backendResponse
	for decoder.More() {
		var response backendResponse
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	return responses
}
