//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestVaultMigrationStageNativeLocalState(t *testing.T) {
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	legacyVaultSecrets(t, db)
	userData := t.TempDir()
	scope := uuid.NewString()
	compact := strings.ReplaceAll(scope, "-", "")
	root := filepath.Dir(source)
	token := writeElectronSafeStorageFixture(t, userData, "native-mcp-token-fixture", []byte("01234567890123456789012345678901"))
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, mcpTokenCredentialID, token, electronSafeStorageSecretEncoding)
	files := map[string]struct {
		kind  string
		value []byte
	}{
		bitwardenSessionPath(source):                                            {"bitwarden-cli", []byte(`{"key":"native-bitwarden-session","path":"bw.exe","region":0}`)},
		filepath.Join(root, "azure-token-cache", compact+".token"):              {"azure-refresh", []byte(`{"RefreshToken":"native-azure-token"}`)},
		filepath.Join(root, "azurevpn-cache", compact+".tokencache"):            {"azure-legacy", []byte("legacy-azure-token")},
		filepath.Join(root, "electron-watchguard-cache", compact+".ovpncache"):  {"watchguard-cache", []byte("native-watchguard-profile")},
		filepath.Join(root, "watchguard-cache", compact+".ovpncache"):           {"watchguard-legacy", []byte("legacy-watchguard-profile")},
		filepath.Join(root, "electron-stormshield-cache", compact+".ovpncache"): {"stormshield-cache", []byte("native-stormshield-profile")},
		filepath.Join(root, "stormshield-cache", compact+".ovpncache"):          {"stormshield-legacy", []byte("legacy-stormshield-profile")},
		azureImportKeyPath(source, scope):                                       {"azure-import", []byte(`{"secret":"pending-import-key"}`)},
	}
	for path, item := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := protectFile(path, item.value); err != nil {
			t.Fatal(err)
		}
	}
	for _, backup := range []bool{false, true} {
		path, kind := bitwardenBrowserStoragePath(source), "bitwarden-browser"
		local := `{"secret":"` + strings.Repeat("native-browser-fixture", 250000) + `"}`
		if backup {
			path += ".bak"
			kind += "-backup"
			local = `{"old":"different-browser-recovery-fixture"}`
		}
		payload, err := json.Marshal(bitwardenBrowserStorageRecord{SchemaVersion: 1, Revision: 7, LocalJson: local})
		if err != nil {
			t.Fatal(err)
		}
		if !backup && len(payload) <= 4*1024*1024 {
			t.Fatal("browser fixture must span chunks")
		}
		if err := protectBitwardenBrowserStorage(path, payload); err != nil {
			t.Fatal(err)
		}
		files[path] = struct {
			kind  string
			value []byte
		}{kind, payload}
	}
	before := map[string][]byte{}
	for path := range files {
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = value
	}
	result, err := stageLegacyVaultDomains(context.Background(), source, userData, doc, key, plan)
	if err != nil || result.LocalStates != 11 {
		t.Fatal("local state not copied", result, err)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	if err := owner.WithLocalState(context.Background(), "mcp-token", doc.VaultID, 1, equalLegacyVaultValue([]byte("native-mcp-token-fixture"))); err != nil {
		t.Fatal(err)
	}
	for path, item := range files {
		id := scope
		if strings.HasPrefix(item.kind, "bitwarden-") {
			id = doc.VaultID
		}
		if err := owner.WithLocalState(context.Background(), item.kind, id, 1, equalLegacyVaultValue(item.value)); err != nil {
			t.Fatal(item.kind, err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before[path], after) {
			t.Fatal("source mutated", err)
		}
	}
	owner.Close()
	disk, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"native-mcp-token-fixture", "native-browser-fixture", "native-bitwarden-session", "pending-import-key"} {
		if bytes.Contains(disk, []byte(secret)) {
			t.Fatal("plaintext local state persisted")
		}
	}
}

func TestVaultMigrationStageNativeLocalStateFailureAndRetry(t *testing.T) {
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	legacyVaultSecrets(t, db)
	encoded, err := protectSecret("fixture-mcp-token")
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'now')`, mcpTokenCredentialID, encoded, protectedSecretEncoding)
	writeLegacyStateFixture(t, bitwardenSessionPath(source), []byte("corrupt protected bytes"))
	if result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err == nil || result.LocalStates != 0 {
		t.Fatal("partial local state reported success", err)
	}
	stage := source + ".migrating-" + doc.FileID
	owner := openNativeMigrationStage(t, stage, key)
	if _, err := owner.ReadLocalState(context.Background(), "mcp-token", doc.VaultID, 1); err != nil {
		t.Fatal("fixture did not fail after first import", err)
	}
	owner.Close()
	if err := protectFile(bitwardenSessionPath(source), []byte("restored-session-fixture")); err != nil {
		t.Fatal(err)
	}
	if result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err != nil || result.LocalStates != 2 {
		t.Fatal("retry failed", result, err)
	}
}
