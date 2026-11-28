package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func writeLegacyStateFixture(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVaultLegacyLocalStateAllSourcesAndBorrowedLifetime(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	h := vaultCredentialFixture(t)
	doc, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	workspace := doc.VaultID
	scope := uuid.NewString()
	compact := strings.ReplaceAll(scope, "-", "")
	root := filepath.Dir(source)
	files := map[string]string{
		bitwardenSessionPath(source): "bitwarden-cli", bitwardenBrowserStoragePath(source): "bitwarden-browser", bitwardenBrowserStoragePath(source) + ".bak": "bitwarden-browser-backup",
		filepath.Join(root, "azure-token-cache", compact+".token"): "azure-refresh", filepath.Join(root, "azurevpn-cache", compact+".tokencache"): "azure-legacy",
		filepath.Join(root, "electron-watchguard-cache", compact+".ovpncache"): "watchguard-cache", filepath.Join(root, "watchguard-cache", compact+".ovpncache"): "watchguard-legacy",
		filepath.Join(root, "electron-stormshield-cache", compact+".ovpncache"): "stormshield-cache", filepath.Join(root, "stormshield-cache", compact+".ovpncache"): "stormshield-legacy", azureImportKeyPath(source, scope): "azure-import",
	}
	for path := range files {
		writeLegacyStateFixture(t, path, []byte("protected-fixture"))
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'encoded','fixture','now')`, mcpTokenCredentialID)
	var borrowed, protected [][]byte
	decrypt := func(path string, input []byte) ([]byte, error) {
		if string(input) != "protected-fixture" || files[path] == "" {
			t.Fatal("wrong file")
		}
		protected = append(protected, input)
		value := []byte("private-" + files[path])
		borrowed = append(borrowed, value)
		return value, nil
	}
	readers := legacyLocalStateReaders{file: decrypt, browser: decrypt, secret: func(id, encoded, encoding string, paths ...string) ([]byte, error) {
		if id != mcpTokenCredentialID || encoded != "encoded" || encoding != "fixture" || len(paths) != 1 || paths[0] != "user-data" {
			t.Fatal("wrong token source")
		}
		v := []byte("private-mcp-token")
		borrowed = append(borrowed, v)
		return v, nil
	}}
	seen := map[string]string{}
	err = readLegacyVaultLocalState(resolverCaptureReader{context.Background(), db}, source, "user-data", workspace, readers, func(kind, id string, value []byte) error {
		if seen[kind] != "" {
			t.Fatal("duplicate source kind")
		}
		seen[kind] = id
		_, err := h.owner.PutLocalState(context.Background(), kind, id, value, 0)
		return err
	})
	if err != nil || len(seen) != 11 {
		t.Fatal("missing archive source", seen, err)
	}
	for _, value := range append(borrowed, protected...) {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("borrowed buffer retained")
		}
	}
	for kind, id := range seen {
		if err := h.owner.WithLocalState(context.Background(), kind, id, 1, equalLegacyVaultValue([]byte("private-"+kind))); err != nil {
			t.Fatal(kind, err)
		}
		wantScope := scope
		if kind == "bitwarden-cli" || kind == "bitwarden-browser" || kind == "bitwarden-browser-backup" || kind == "mcp-token" {
			wantScope = workspace
		}
		if id != wantScope {
			t.Fatal("scope changed")
		}
	}
	for path := range files {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "protected-fixture" {
			t.Fatal("source retired", err)
		}
	}
}

func TestVaultLegacyLocalStateErrorsClearBuffers(t *testing.T) {
	db, source := snapshotDatabase(t)
	workspace := uuid.NewString()
	ctx := context.Background()
	for _, mode := range []string{"file-error", "file-oversize", "file-cancel", "sink-error", "token-error", "token-oversize", "token-cancel"} {
		t.Run(mode, func(t *testing.T) {
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			reader := resolverCaptureReader{callCtx, db}
			var value, input []byte
			decrypt := func(_ string, in []byte) ([]byte, error) {
				input = in
				value = []byte("partial-private-value")
				switch mode {
				case "file-error":
					return value, errors.New("fixture")
				case "file-oversize":
					value = make([]byte, 129)
				case "file-cancel":
					cancel()
				}
				return value, nil
			}
			visit := func(string, string, []byte) error {
				if mode == "sink-error" {
					return errors.New("sink fixture")
				}
				t.Fatal("invalid input reached sink")
				return nil
			}
			var err error
			if strings.HasPrefix(mode, "token") {
				err = borrowLegacyLocalToken(reader, "encoded", "fixture", "user-data", workspace, func(string, string, string, ...string) ([]byte, error) {
					value = []byte("partial-token")
					switch mode {
					case "token-error":
						return value, errors.New("fixture")
					case "token-oversize":
						value = make([]byte, maxStoredCredentialBytes+1)
					case "token-cancel":
						cancel()
					}
					return value, nil
				}, visit)
			} else {
				path := bitwardenSessionPath(source)
				writeLegacyStateFixture(t, path, []byte("protected"))
				err = borrowLegacyLocalFile(reader, legacyLocalStateFile{path: path, kind: "bitwarden-cli", scope: workspace, maximum: 128}, legacyLocalStateReaders{file: decrypt}, visit)
			}
			if err == nil {
				t.Fatal("invalid archive accepted")
			}
			for _, v := range [][]byte{value, input} {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("error retained bytes")
				}
			}
		})
	}
}

func TestVaultLegacyLocalStateSourceAndDirectoryBoundaries(t *testing.T) {
	db, source := snapshotDatabase(t)
	workspace := uuid.NewString()
	ctx := context.Background()
	reader := resolverCaptureReader{ctx, db}
	decrypt := func(string, []byte) ([]byte, error) { t.Fatal("unexpected decrypt"); return nil, nil }
	readers := legacyLocalStateReaders{file: decrypt, browser: decrypt, secret: func(string, string, string, ...string) ([]byte, error) { t.Fatal("unexpected token"); return nil, nil }}
	visit := func(string, string, []byte) error { t.Fatal("unexpected sink"); return nil }
	if err := readLegacyVaultLocalState(reader, source, "", workspace, readers, visit); err != nil {
		t.Fatal("empty archive failed", err)
	}
	for _, bad := range []string{"", uuid.Nil.String(), strings.ToUpper(workspace)} {
		if err := readLegacyVaultLocalState(reader, source, "", bad, readers, visit); err != errVaultMigrationSource {
			t.Fatal(err)
		}
	}
	if err := readLegacyVaultLocalState(reader, "relative", "", workspace, readers, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	if err := readLegacyVaultLocalState(reader, source, "", workspace, legacyLocalStateReaders{}, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	if err := readLegacyVaultLocalState(reader, source, "", workspace, readers, nil); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	missing := legacyLocalStateFile{path: filepath.Join(t.TempDir(), "missing"), maximum: 128, required: true}
	if err := borrowLegacyLocalFile(reader, missing, readers, visit); err != errVaultMigrationSource {
		t.Fatal("enumerated file disappearance ignored", err)
	}
	for _, size := range []int{0, 129} {
		path := filepath.Join(t.TempDir(), "invalid")
		writeLegacyStateFixture(t, path, make([]byte, size))
		if err := borrowLegacyLocalFile(reader, legacyLocalStateFile{path: path, maximum: 128}, readers, visit); err != errVaultMigrationSource {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"invalid.token", strings.Repeat("0", 32) + ".token", strings.ToUpper(strings.ReplaceAll(workspace, "-", "")) + ".token", workspace + ".token"} {
		dir := t.TempDir()
		writeLegacyStateFixture(t, filepath.Join(dir, name), []byte("protected"))
		if err := visitLegacyLocalDirectory(reader, dir, ".token", func(string, string) error { t.Fatal("bad path visited"); return nil }); err != errVaultMigrationSource {
			t.Fatal(name, err)
		}
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, strings.ReplaceAll(workspace, "-", "")+".token"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := visitLegacyLocalDirectory(reader, dir, ".token", func(string, string) error { return nil }); err != errVaultMigrationSource {
		t.Fatal("directory accepted as payload", err)
	}
	notDirectory := filepath.Join(t.TempDir(), "file")
	writeLegacyStateFixture(t, notDirectory, []byte("data"))
	if err := visitLegacyLocalDirectory(reader, notDirectory, ".token", func(string, string) error { return nil }); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	reader.ctx = canceled
	if err := borrowLegacyLocalToken(reader, "", "", "", workspace, readers.secret, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	if err := borrowLegacyLocalFile(reader, missing, readers, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	if err := visitLegacyLocalDirectory(reader, dir, ".token", func(string, string) error { return nil }); err != errVaultMigrationSource {
		t.Fatal(err)
	}
}

func TestVaultLegacyLocalStateDirectoryPagingAndFailures(t *testing.T) {
	db, _ := snapshotDatabase(t)
	reader := resolverCaptureReader{context.Background(), db}
	dir := t.TempDir()
	want := map[string]bool{}
	for i := 0; i < 130; i++ {
		id := fmt.Sprintf("abcdefab-0000-4000-8000-%012x", i+1)
		want[id] = true
		writeLegacyStateFixture(t, filepath.Join(dir, strings.ReplaceAll(id, "-", "")+".token"), []byte("protected"))
	}
	writeLegacyStateFixture(t, filepath.Join(dir, "unrelated.txt"), []byte("leave untouched"))
	seen := 0
	if err := visitLegacyLocalDirectory(reader, dir, ".token", func(path, id string) error {
		if !want[id] {
			t.Fatal("duplicate/unknown file")
		}
		delete(want, id)
		seen++
		return nil
	}); err != nil || seen != 130 || len(want) != 0 {
		t.Fatal("directory paging lost files", err)
	}
	failure := errors.New("fixture sink")
	if err := visitLegacyLocalDirectory(reader, dir, ".token", func(string, string) error { return failure }); err != failure {
		t.Fatal(err)
	}
}

func TestVaultLegacyLocalStateRejectsAmbiguousTokenAndPendingJournal(t *testing.T) {
	db, source := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	readers := legacyLocalStateReaders{file: func(string, []byte) ([]byte, error) { return nil, nil }, browser: func(string, []byte) ([]byte, error) { return nil, nil }, secret: func(string, string, string, ...string) ([]byte, error) {
		t.Fatal("bad metadata reached platform decryptor")
		return nil, nil
	}}
	workspace := uuid.NewString()
	visit := func(string, string, []byte) error { t.Fatal("bad source visited"); return nil }
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'encoded','fixture','now')`, mcpTokenCredentialID)
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES(?,'other','fixture','now')`, strings.ToUpper(mcpTokenCredentialID))
	if err := readLegacyVaultLocalState(resolverCaptureReader{context.Background(), db}, source, "", workspace, readers, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecretOperations VALUES('pending',?,'fixture','now')`, mcpTokenCredentialID)
	if err := readLegacyVaultLocalState(resolverCaptureReader{context.Background(), db}, source, "", workspace, readers, visit); err != errVaultMigrationSource {
		t.Fatal(err)
	}
}

func TestVaultMigrationStageKeepsLogicalProtectedPaths(t *testing.T) {
	_, source, doc, key, plan, _ := migrationStageFixture(t)
	alias := filepath.Join(t.TempDir(), "workspace-alias")
	if err := os.Symlink(filepath.Dir(source), alias); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	logical := filepath.Join(alias, filepath.Base(source))
	importID := uuid.NewString()
	importPath := azureImportKeyPath(logical, importID)
	if importPath == azureImportKeyPath(source, importID) {
		t.Fatal("fixture lost logical path distinction")
	}
	if err := os.MkdirAll(filepath.Dir(importPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(importPath, []byte("alias-import-key-fixture")); err != nil {
		t.Fatal(err)
	}
	if err := protectFile(bitwardenSessionPath(logical), []byte("alias-session-fixture")); err != nil {
		t.Fatal(err)
	}
	result, err := stageLegacyVaultDomains(context.Background(), logical, "", doc, key, plan)
	if err != nil || result.LocalStates != 2 {
		t.Fatal("canonicalization lost protected state", result, err)
	}
	owner := openNativeMigrationStage(t, result.Path, key)
	defer owner.Close()
	if err := owner.WithLocalState(context.Background(), "azure-import", importID, 1, equalLegacyVaultValue([]byte("alias-import-key-fixture"))); err != nil {
		t.Fatal(err)
	}
	if err := owner.WithLocalState(context.Background(), "bitwarden-cli", doc.VaultID, 1, equalLegacyVaultValue([]byte("alias-session-fixture"))); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// Even the same physical DB must not resume under a different protection
	// namespace and silently omit path-hashed imports or keyring entries.
	if _, err := stageLegacyVaultDomains(context.Background(), source, "", doc, key, plan); err == nil {
		t.Fatal("logical source binding ignored on resume")
	}
	if again, err := stageLegacyVaultDomains(context.Background(), logical, "", doc, key, plan); err != nil || again.LocalStates != 2 {
		t.Fatal("same alias could not resume", err)
	}
}
