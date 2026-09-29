package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func importAzureTestKey(t *testing.T, databasePath, secret string) azureImportResult {
	t.Helper()
	profile := strings.Replace(azureVPNClientExportFixture(), strings.Repeat("ab", 256), secret, 1)
	path := filepath.Join(t.TempDir(), "profile.xml")
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := importAzureVPNFile(databasePath, azureImportRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertAzureEditorKeyHidden(t *testing.T, raw []byte, secret, refPrefix string) map[string]json.RawMessage {
	t.Helper()
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("ServerSecretHex")) {
		t.Fatal("Azure server key crossed the editor boundary")
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tunnelSettingString(settings, "ServerSecretRef"), refPrefix) {
		t.Fatal("editor response did not preserve the opaque key reference")
	}
	return settings
}

func TestAzureImportedKeyStaysProtectedAcrossSaveReadEditAndRuntime(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	secret := strings.Repeat("ab", 256)
	imported := importAzureTestKey(t, databasePath, secret)
	public, err := json.Marshal(imported)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte(secret)) || bytes.Contains(public, []byte("ServerSecretHex")) {
		t.Fatal("import exposed the server key")
	}
	ref := imported.Settings["ServerSecretRef"].(string)
	keyPath := azureImportKeyPath(databasePath, strings.TrimPrefix(ref, "import:"))
	protected, err := os.ReadFile(keyPath)
	if err != nil || bytes.Contains(protected, []byte(secret)) {
		t.Fatal("import did not protect the key on disk")
	}
	raw, _ := json.Marshal(imported.Settings)
	created, err := createTunnel(databasePath, tunnelWriteRequest{Name: "Azure", Kind: 5, Settings: raw})
	if err != nil {
		t.Fatal(err)
	}
	assertAzureEditorKeyHidden(t, created.Settings, secret, "tunnel:")
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed import retained its temporary key record")
	}
	read, err := readTunnel(databasePath, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	settings := assertAzureEditorKeyHidden(t, read.Settings, secret, "tunnel:")
	settings["Servers"] = json.RawMessage(`["changed.vpn.azure.com"]`)
	updatedRaw, _ := json.Marshal(settings)
	updated, err := updateTunnel(databasePath, tunnelWriteRequest{ID: created.ID, Name: "Azure edited", Kind: 5, Settings: updatedRaw})
	if err != nil {
		t.Fatal(err)
	}
	assertAzureEditorKeyHidden(t, updated.Settings, secret, "tunnel:")
	// Internal ownership/cache checks and runtime reads must retain the native key.
	native, err := readTunnelUnlocked(databasePath, tunnelReadRequest{ID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(native.Settings)
	var runtimeSettings map[string]json.RawMessage
	if err := json.Unmarshal(native.Settings, &runtimeSettings); err != nil {
		t.Fatal(err)
	}
	defer clearTunnelSettingsMap(runtimeSettings)
	if tunnelSettingString(runtimeSettings, "ServerSecretHex") != secret || runtimeSettings["ServerSecretRef"] != nil {
		t.Fatal("protected native settings lost the key or retained an editor reference")
	}
	profile, err := buildAzureVPNProfile(runtimeSettings)
	if err != nil || !strings.Contains(profile, "<tls-auth>") {
		t.Fatal("runtime did not receive the imported TLS authentication key")
	}
	// Re-import replaces the key, including explicitly clearing a prior key.
	for _, replacement := range []string{strings.Repeat("cd", 256), ""} {
		reimported := importAzureTestKey(t, databasePath, replacement)
		replacementRaw, _ := json.Marshal(reimported.Settings)
		updated, err = updateTunnel(databasePath, tunnelWriteRequest{ID: created.ID, Name: "Azure edited", Kind: 5, Settings: replacementRaw})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(updated.Settings, []byte("ServerSecretHex")) {
			t.Fatal("re-import exposed the replacement key")
		}
		native, err = readTunnelUnlocked(databasePath, tunnelReadRequest{ID: created.ID})
		if err != nil {
			t.Fatal(err)
		}
		clearTunnelSettingsMap(runtimeSettings)
		runtimeSettings = nil
		if err := json.Unmarshal(native.Settings, &runtimeSettings); err != nil {
			t.Fatal(err)
		}
		if tunnelSettingString(runtimeSettings, "ServerSecretHex") != replacement {
			t.Fatal("re-import did not replace or clear the native key")
		}
		clearBytes(native.Settings)
	}
}

func TestAzureImportKeySurvivesFailedSave(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	secret := strings.Repeat("ab", 256)
	imported := importAzureTestKey(t, databasePath, secret)
	raw, _ := json.Marshal(imported.Settings)
	previousSync := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { privateFileDirectorySync = previousSync })
	_, err := createTunnel(databasePath, tunnelWriteRequest{Name: "Azure", Kind: 5, Settings: raw})
	privateFileDirectorySync = previousSync
	if err == nil {
		t.Fatal("failed protected write committed the tunnel")
	}
	id := strings.TrimPrefix(imported.Settings["ServerSecretRef"].(string), "import:")
	if retained, err := loadAzureImportKey(databasePath, id); err != nil || retained != secret {
		t.Fatal("failed save consumed the key needed to retry")
	}
	if _, err := createTunnel(databasePath, tunnelWriteRequest{Name: "Azure", Kind: 5, Settings: raw}); err != nil {
		t.Fatal("save could not be retried after rollback")
	}
}

func TestAzureImportCLIResponsesNeverExposeServerKey(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	path := filepath.Join(t.TempDir(), "profile.xml")
	if err := os.WriteFile(path, []byte(azureVPNClientExportFixture()), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(operation string, input any, result any) {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runBackendCLI([]string{"-database", databasePath, "-operation", operation}, bytes.NewReader(raw), &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatal("Azure backend operation failed")
		}
		if bytes.Contains(stdout.Bytes(), []byte(strings.Repeat("ab", 256))) || bytes.Contains(stdout.Bytes(), []byte("ServerSecretHex")) {
			t.Fatal("backend protocol output exposed the server key")
		}
		if err := json.Unmarshal(stdout.Bytes(), result); err != nil {
			t.Fatal(err)
		}
	}
	var imported azureImportResult
	call("azure-vpn-import", azureImportRequest{Path: path}, &imported)
	raw, _ := json.Marshal(imported.Settings)
	var created tunnelDetails
	call("tunnel-create", tunnelWriteRequest{Name: "Azure CLI", Kind: 5, Settings: raw}, &created)
	var read tunnelDetails
	call("tunnel-read", tunnelReadRequest{ID: created.ID}, &read)
	call("tunnel-update", tunnelWriteRequest{ID: read.ID, Name: "Azure CLI edited", Kind: 5, Settings: read.Settings}, &created)
}

func TestAzureKeyReferencesFailClosed(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	imported := importAzureTestKey(t, databasePath, strings.Repeat("ab", 256))
	for _, ref := range []any{nil, 42, "../key", "import:../key", "unknown:11111111-2222-3333-4444-555555555555", "tunnel:11111111-2222-3333-4444-555555555555", "import:11111111-2222-3333-4444-555555555555"} {
		imported.Settings["ServerSecretRef"] = ref
		raw, _ := json.Marshal(imported.Settings)
		if result, err := createTunnel(databasePath, tunnelWriteRequest{Name: "invalid", Kind: 5, Settings: raw}); err == nil || result.Settings != nil {
			t.Fatal("invalid reference produced a tunnel instead of failing closed")
		}
	}
	valid := importAzureTestKey(t, databasePath, strings.Repeat("ab", 256))
	raw, _ := json.Marshal(valid.Settings)
	otherDatabase := filepath.Join(filepath.Dir(databasePath), "other.db")
	if _, err := createTunnel(otherDatabase, tunnelWriteRequest{Name: "cross-workspace", Kind: 5, Settings: raw}); err == nil {
		t.Fatal("key reference crossed the database boundary")
	}
	valid.Settings["ServerSecretHex"] = strings.Repeat("cd", 256)
	raw, _ = json.Marshal(valid.Settings)
	if _, err := createTunnel(databasePath, tunnelWriteRequest{Name: "conflict", Kind: 5, Settings: raw}); err == nil {
		t.Fatal("ambiguous raw key/reference pair was accepted")
	}
	otherProvider, err := createTunnel(databasePath, tunnelWriteRequest{
		Name: "Other provider", Kind: 0,
		Settings: json.RawMessage(`{"InterfacePrivateKey":"private","InterfaceAddress":"10.0.0.2/32","PeerPublicKey":"public","PeerEndpoint":"gateway:51820"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(valid.Settings, "ServerSecretHex")
	valid.Settings["ServerSecretRef"] = "tunnel:" + otherProvider.ID
	raw, _ = json.Marshal(valid.Settings)
	if _, err := createTunnel(databasePath, tunnelWriteRequest{Name: "wrong provider", Kind: 5, Settings: raw}); err == nil {
		t.Fatal("key reference was accepted for a different VPN provider")
	}
}

func TestAzureImportKeyRejectsCorruptionExpiryAndOversize(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	secret := strings.Repeat("ab", 256)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "malformed record", data: []byte("not-json")},
		{name: "unsupported version", data: []byte(`{"version":2}`)},
		{name: "expired", data: mustAzureKeyRecord(t, secret, time.Now().Add(-2*azureImportKeyMaxAge))},
		{name: "future timestamp", data: mustAzureKeyRecord(t, secret, time.Now().Add(time.Hour))},
		{name: "invalid key", data: mustAzureKeyRecord(t, "invalid", time.Now())},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := newTunnelID()
			if err := protectFile(azureImportKeyPath(databasePath, id), test.data); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAzureImportKey(databasePath, id); err == nil {
				t.Fatal("invalid protected record was accepted")
			}
		})
	}
	for _, contents := range [][]byte{[]byte("not-encrypted"), make([]byte, 8*1024+1)} {
		id := newTunnelID()
		path := azureImportKeyPath(databasePath, id)
		if err := writePrivateFileAtomic(path, contents); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAzureImportKey(databasePath, id); err == nil {
			t.Fatal("corrupt or oversized protected file was accepted")
		}
	}
}

func mustAzureKeyRecord(t *testing.T, secret string, createdAt time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(azureImportKey{Version: 1, CreatedAt: createdAt, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAzureImportKeyCleanupAndProtectionFailure(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	secret := strings.Repeat("ab", 256)
	oldRef, err := storeAzureImportKey(databasePath, secret)
	if err != nil {
		t.Fatal(err)
	}
	oldID := strings.TrimPrefix(oldRef, "import:")
	oldPath := azureImportKeyPath(databasePath, oldID)
	oldTime := time.Now().Add(-2 * azureImportKeyMaxAge)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(oldPath)
	if err := os.WriteFile(filepath.Join(directory, "unrelated.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, strings.Repeat("z", 32)+".dpapi"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := storeAzureImportKey(databasePath, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("abandoned stale import key was not removed")
	}
	for _, name := range []string{"unrelated.txt", strings.Repeat("z", 32) + ".dpapi"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal("cleanup removed an unrelated file")
		}
	}
	if azureImportKeyPath(databasePath, "../escape") != "" || azureImportKeyPath("", newTunnelID()) != "" {
		t.Fatal("invalid key identity produced a filesystem path")
	}
	cleanupAzureImportKeys(databasePath, "invalid")
	removeAzureImportKey(databasePath, "invalid")
	if _, err := storeAzureImportKey(databasePath, "invalid"); err == nil {
		t.Fatal("invalid server key was protected")
	}
	if _, err := storeAzureImportKey(databasePath, strings.Repeat("z", azureServerSecretChars)); err == nil {
		t.Fatal("non-hexadecimal server key was protected")
	}
	if _, err := storeAzureImportKey("", secret); err == nil {
		t.Fatal("key was protected without a database owner")
	}
	previousSync := privateFileDirectorySync
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { privateFileDirectorySync = previousSync })
	if _, err := storeAzureImportKey(databasePath, secret); err == nil {
		t.Fatal("failed protection returned an import reference")
	}
	privateFileDirectorySync = previousSync
}

func TestAzureEditorProjectionPreservesOtherProvidersAndRejectsInvalidSettings(t *testing.T) {
	raw := json.RawMessage(`{"Password":"other-provider"}`)
	unchanged, err := azureVPNEditorSettings(2, newTunnelID(), raw)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("Azure projection changed another VPN provider")
	}
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage("{")} {
		if _, err := azureVPNEditorSettings(5, newTunnelID(), raw); err == nil {
			t.Fatal("invalid editor settings were accepted")
		}
		if _, _, err := resolveAzureVPNServerSecret(nil, "unused", raw); err == nil {
			t.Fatal("invalid native settings were accepted")
		}
	}
}
