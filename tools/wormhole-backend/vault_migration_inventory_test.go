package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultMigrationInventoryAllSourcesAndValueBinding(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	// Older layouts allowed nullable provenance; keep its distinction from an empty timestamp.
	legacyVaultSQL(t, db, `DROP TABLE CredentialSecrets`)
	legacyVaultSQL(t, db, `CREATE TABLE CredentialSecrets (Id TEXT PRIMARY KEY, Secret TEXT NOT NULL, Encoding TEXT NOT NULL, UpdatedAt TEXT)`)
	workspace := uuid.NewString()
	key := bytes.Repeat([]byte{7}, 32)
	reader := resolverCaptureReader{context.Background(), db}
	scope := uuid.NewString()
	for _, file := range legacyLocalStateFiles(source, workspace) {
		writeLegacyStateFixture(t, file.path, []byte("protected-file-fixture"))
	}
	directories := append(legacyLocalStateDirectories(source, workspace),
		legacyLocalStateDirectory{filepath.Dir(credentialPrivateKeyPath(source, scope)), "credential-private-key", ".dpapi", maxProtectedSshKeyBytes},
		legacyLocalStateDirectory{filepath.Dir(legacyTunnelSecretPath(source, scope)), "tunnel-file", ".dpapi", maxTunnelProtectedBytes})
	for _, directory := range directories {
		for _, id := range []string{scope, uuid.NewString()} {
			writeLegacyStateFixture(t, filepath.Join(directory.path, strings.ReplaceAll(id, "-", "")+directory.suffix), []byte("protected-file-fixture"))
		}
	}
	var borrowed [][]byte
	secretValue := "native-plain-fixture"
	decrypt := func(id, encoded, encoding string, paths ...string) ([]byte, error) {
		if len(paths) != 1 || paths[0] != "user-data" || strings.ToLower(id) != id {
			t.Fatal("wrong source authority")
		}
		value := []byte(secretValue)
		borrowed = append(borrowed, value)
		return value, nil
	}
	for i := 0; i < 66; i++ {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
		encoding, encoded := "fixture", "protected-row-fixture"
		if i < 3 {
			encoding = []string{linuxLegacySecretServiceEncoding, linuxSecretServiceEncoding, darwinKeychainEncoding}[i]
			encoded = strings.ToUpper(id + ":" + uuid.NewString())
			if i == 1 {
				encoding = " " + encoding + " "
			}
		}
		legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,?,?,NULL)`, id, encoded, encoding)
	}
	tunnelID := tunnelSecretID(uuid.NewString())
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'protected-row-fixture','fixture','now')`, tunnelID)
	raw, err := captureLegacySourceInventory(reader, source, "user-data", workspace, key, decrypt)
	if err != nil {
		t.Fatal(err)
	}
	var inventory legacySourceInventory
	if err := json.Unmarshal(raw, &inventory); err != nil || inventory.Version != 2 || len(inventory.DatabaseMAC) != 32 || inventory.Source != source || inventory.WorkspaceID != workspace || len(inventory.Files) != 21 || len(inventory.Secrets) != 67 {
		t.Fatal("incomplete inventory", inventory, err)
	}
	for _, field := range []string{secretValue, "protected-row-fixture", "protected-file-fixture"} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatal("inventory retained source value")
		}
	}
	for _, b := range borrowed {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("decrypted source retained")
		}
	}
	for i, row := range inventory.Secrets {
		if len(row.Authentication) != 32 || (i < 3) != (row.Reference != "") || (i < 66 && row.UpdatedAt != nil) {
			t.Fatal("keychain retirement reference lost", row)
		}
	}
	again, err := captureLegacySourceInventory(reader, source, "user-data", workspace, key, decrypt)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("inventory is not deterministic", err)
	}
	secretValue = "changed-keychain-value-at-same-reference"
	changed, err := captureLegacySourceInventory(reader, source, "user-data", workspace, key, decrypt)
	if err != nil || bytes.Equal(raw, changed) {
		t.Fatal("mutable keychain value not bound", err)
	}
	secretValue = "native-plain-fixture"
	other, err := captureLegacySourceInventory(reader, source, "user-data", workspace, bytes.Repeat([]byte{8}, 32), decrypt)
	if err != nil || bytes.Equal(raw, other) {
		t.Fatal("inventory not bound to root key", err)
	}
	writeLegacyStateFixture(t, bitwardenSessionPath(source), []byte("changed-protected-file"))
	other, err = captureLegacySourceInventory(reader, source, "user-data", workspace, key, decrypt)
	if err != nil || bytes.Equal(raw, other) {
		t.Fatal("file contents not bound", err)
	}
}

func TestVaultMigrationInventoryFailuresAndWiping(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	workspace := "abcdefab-cdef-4abc-8def-abcdefabcdef"
	key := bytes.Repeat([]byte{9}, 32)
	reader := resolverCaptureReader{context.Background(), db}
	decrypt := func(string, string, string, ...string) ([]byte, error) { return []byte("value"), nil }
	for _, bad := range []struct {
		source, workspace string
		key               []byte
		decrypt           legacyVaultSecretReader
	}{
		{"relative", workspace, key, decrypt}, {source + string([]byte{0xff}), workspace, key, decrypt}, {source, "bad", key, decrypt}, {source, uuid.Nil.String(), key, decrypt},
		{source, strings.ToUpper(workspace), key, decrypt}, {source, workspace, nil, decrypt}, {source, workspace, key, nil},
	} {
		if _, err := captureLegacySourceInventory(reader, bad.source, "", bad.workspace, bad.key, bad.decrypt); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureLegacySourceInventory(resolverCaptureReader{cancelled, db}, source, "", workspace, key, decrypt); err == nil {
		t.Fatal("cancelled capture accepted")
	}
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte{1}, 64*1024+1)} {
		writeLegacyStateFixture(t, bitwardenSessionPath(source), payload)
		if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err == nil {
			t.Fatal("invalid protected artifact accepted")
		}
	}
	if err := os.Remove(bitwardenSessionPath(source)); err != nil {
		t.Fatal(err)
	}
	directory := legacyLocalStateDirectories(source, workspace)[0]
	writeLegacyStateFixture(t, filepath.Join(directory.path, "invalid.token"), []byte("bad"))
	if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err == nil {
		t.Fatal("invalid artifact name accepted")
	}
	if err := os.Remove(filepath.Join(directory.path, "invalid.token")); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	row := legacyVaultOrphan{Source: id}
	if _, err := captureLegacyInventoryRow(reader, source, "", key, row, decrypt); err == nil {
		t.Fatal("missing row accepted")
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'not-a-reference',?,'now')`, id, linuxSecretServiceEncoding)
	if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err == nil {
		t.Fatal("invalid native keychain reference accepted")
	}
	legacyVaultSQL(t, db, `UPDATE CredentialSecrets SET Encoding='fixture'`)
	for _, mode := range []string{"error", "oversized", "cancel"} {
		ctx, stop := context.WithCancel(context.Background())
		var borrowed []byte
		decoder := func(string, string, string, ...string) ([]byte, error) {
			borrowed = []byte("private-partial-value")
			if mode == "oversized" {
				borrowed = bytes.Repeat([]byte{1}, maxStoredCredentialBytes+1)
			}
			if mode == "cancel" {
				stop()
			}
			if mode == "error" {
				return borrowed, errors.New("private source diagnostic")
			}
			return borrowed, nil
		}
		if _, err := captureLegacySourceInventory(resolverCaptureReader{ctx, db}, source, "", workspace, key, decoder); err != errVaultMigrationSource {
			t.Fatal(mode, err)
		}
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("failed capture retained plaintext")
		}
		stop()
	}
	legacyVaultSQL(t, db, `UPDATE CredentialSecrets SET Id='invalid-id'`)
	if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err == nil {
		t.Fatal("invalid row identity accepted")
	}
	legacyVaultSQL(t, db, `DROP TABLE CredentialSecrets`)
	if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err != nil {
		t.Fatal("absent legacy secret table rejected", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLegacySourceInventory(reader, source, "", workspace, key, decrypt); err == nil {
		t.Fatal("failed source query ignored")
	}
}

func TestVaultMigrationInventoryFileBoundsAndMACDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if _, err := readLegacyInventoryFile(path, 8); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyInventoryFile(path, 8); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("123456789"), []byte("12345678")} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readLegacyInventoryFile(path, 8)
		if len(data) == 8 {
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal(got, err)
			}
		} else if err == nil || got != nil {
			t.Fatal("bounds ignored")
		}
	}
	key := bytes.Repeat([]byte{4}, 32)
	first, err := legacyInventoryMAC(key, "source", legacyInventoryFile{Kind: "one"}, []byte("ab"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		source, kind string
		parts        [][]byte
	}{
		{"source", "one", [][]byte{[]byte("a"), []byte("bc")}}, {"other", "one", [][]byte{[]byte("ab"), []byte("c")}},
		{"source", "two", [][]byte{[]byte("ab"), []byte("c")}},
	} {
		got, err := legacyInventoryMAC(key, args.source, legacyInventoryFile{Kind: args.kind}, args.parts...)
		if err != nil || bytes.Equal(got, first) {
			t.Fatal("ambiguous source commitment", err)
		}
	}
	if _, err := legacyInventoryMAC(key, "source", func() {}); err == nil {
		t.Fatal("invalid metadata encoded")
	}
	t.Run("links", func(t *testing.T) {
		link := path + ".link"
		if err := os.Symlink(path, link); err != nil {
			t.Skip("host cannot create symlinks")
		}
		if _, err := readLegacyInventoryFile(link, 8); err == nil {
			t.Fatal("source link followed")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := readLegacyInventoryFile(link, 8); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatal("dangling link treated as optional absence")
		}
	})
}

func TestVaultMigrationInventoryPersistenceAndSourceDrift(t *testing.T) {
	db, source := snapshotDatabase(t)
	h := vaultCredentialFixture(t)
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{1}, 32)
	reader := resolverCaptureReader{context.Background(), db}
	writeLegacyStateFixture(t, bitwardenSessionPath(source), []byte("protected-source"))
	before, err := captureLegacySourceInventory(reader, source, "", doc.VaultID, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"replace", "remove", "add"} {
		extra := filepath.Join(legacyLocalStateDirectories(source, doc.VaultID)[0].path, strings.ReplaceAll(uuid.NewString(), "-", "")+".token")
		switch change {
		case "replace":
			writeLegacyStateFixture(t, bitwardenSessionPath(source), []byte("changed-source"))
		case "remove":
			if err := os.Remove(bitwardenSessionPath(source)); err != nil {
				t.Fatal(err)
			}
		case "add":
			writeLegacyStateFixture(t, extra, []byte("new-source"))
		}
		if err := persistLegacySourceInventory(reader, source, "", doc.VaultID, key, before, h.owner); err != errVaultMigrationSource {
			t.Fatal("changed source accepted", change, err)
		}
		if _, err := h.owner.ReadLocalState(reader.ctx, migrationSourceInventoryKind, doc.VaultID, 0); err != vaultstore.ErrMissing {
			t.Fatal("partial inventory published", err)
		}
		writeLegacyStateFixture(t, bitwardenSessionPath(source), []byte("protected-source"))
		if change == "add" {
			if err := os.Remove(extra); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := persistLegacySourceInventory(reader, source, "", doc.VaultID, key, before, h.owner); err != nil {
		t.Fatal(err)
	}
	if err := h.owner.WithLocalState(reader.ctx, migrationSourceInventoryKind, doc.VaultID, 1, equalLegacyVaultValue(before)); err != nil {
		t.Fatal(err)
	}
	if err := persistLegacySourceInventory(reader, source, "", doc.VaultID, key, before, h.owner); err != vaultstore.ErrConflict {
		t.Fatal("inventory overwrite accepted", err)
	}
	if _, err := h.owner.PutLocalState(reader.ctx, migrationSourceInventoryKind, uuid.NewString(), before, 0); err != vault.ErrFormat {
		t.Fatal("cross-workspace inventory accepted", err)
	}
	if err := h.owner.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(h.databasePath)
	if err != nil || bytes.Contains(file, []byte(source)) || bytes.Contains(file, []byte("protected-source")) {
		t.Fatal("inventory persisted outside ciphertext", err)
	}
	if err := persistLegacySourceInventory(reader, source, "", doc.VaultID, key, before, h.owner); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if err := os.WriteFile(bitwardenSessionPath(source), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistLegacySourceInventory(reader, source, "", doc.VaultID, key, before, h.owner); err != errVaultMigrationSource {
		t.Fatal(err)
	}
}

func TestVaultMigrationStagePersistsSourceInventory(t *testing.T) {
	db, source, doc, key, plan, _ := migrationStageFixture(t)
	result, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	reader := resolverCaptureReader{context.Background(), db}
	expected, err := captureLegacySourceInventory(reader, source, "", doc.VaultID, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	if err != nil {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	defer owner.Close()
	if err := owner.WithLocalState(context.Background(), migrationSourceInventoryKind, doc.VaultID, 1, equalLegacyVaultValue(expected)); err != nil {
		t.Fatal(err)
	}
	manifest, err := owner.ReadLocalState(context.Background(), migrationSourceInventoryKind, doc.VaultID, 1)
	if err != nil || manifest.Size != len(expected) || len(manifest.Seal) != 32 {
		t.Fatal("unsealed inventory", err)
	}
	var decoded legacySourceInventory
	if err := json.Unmarshal(expected, &decoded); err != nil || !reflect.DeepEqual(decoded.Files, []legacyInventoryFile{}) {
		t.Fatal(err)
	}
}
