package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationPublicationRootRejectsUnsafeNamesAndSlots(t *testing.T) {
	for _, name := range []string{"", ".", "..", "dir/file", "dir\\file", "file:stream", "file\x00", "file.", "file ", strings.Repeat("a", 4097), string([]byte{0xff})} {
		if legacyPublicationFilename(name) {
			t.Fatal("unsafe native filename accepted")
		}
	}
	for _, name := range []string{"app.db", ".vault-slot-test.tmp", "native è.data"} {
		if !legacyPublicationFilename(name) {
			t.Fatal("ordinary native filename rejected")
		}
	}
	root := t.TempDir()
	f, err := openLegacyPublicationFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	path := filepath.Join(root, "workspace.db")
	if _, _, err := borrowLegacyPublicationFS(path, []*legacyPublicationFS{nil}); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("nil capability accepted", err)
	}
	if _, _, err := borrowLegacyPublicationFS(path, []*legacyPublicationFS{f, f}); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("multiple capabilities accepted", err)
	}
	if _, err := f.relative(filepath.Join(t.TempDir(), "foreign")); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("capability escaped its parent", err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if _, err := f.lstat(foreign); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("metadata read escaped parent", err)
	}
	if _, err := f.readSlots(foreign); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("slot read escaped parent", err)
	}
	if _, _, err := borrowLegacyPublicationFS(foreign, []*legacyPublicationFS{f}); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("foreign root reused the capability", err)
	}
	if _, _, err := borrowLegacyPublicationFS(filepath.Join(root, "absent-parent", "db"), nil); err == nil {
		t.Fatal("missing native parent adopted")
	}
	if _, err := f.readSlots(path); !errors.Is(err, errVaultSlotMissing) {
		t.Fatal(err)
	}
	if err := f.writeSlots(path, nil); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("empty slot write accepted", err)
	}
	if err := f.writeSlots(path, make([]byte, vault.MaxSlotFileBytes+1)); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("oversized slot write accepted", err)
	}
	if err := os.Mkdir(vaultSlotPath(path), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readSlots(path); !errors.Is(err, errVaultSlotStorage) {
		t.Fatal("directory treated as slots", err)
	}
	if err := os.Remove(vaultSlotPath(path)); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(vaultSlotPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(vault.MaxSlotFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := f.readSlots(path); !errors.Is(err, errVaultSlotStorage) {
		t.Fatal("unbounded slot file read", err)
	}
	if err := os.WriteFile(vaultSlotPath(path), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readSlots(path); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("malformed slots accepted", err)
	}
	if err := f.root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.verify(); err == nil {
		t.Fatal("closed native capability accepted")
	}
}

func TestVaultPublicationRetainsCanonicalDirectoryAcrossCutover(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "Parent", "workspace")
	if err := os.MkdirAll(physical, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "parent")
	if runtime.GOOS != "windows" {
		alias = filepath.Join(base, "alias")
		if err := os.Symlink(filepath.Dir(physical), alias); err != nil {
			t.Fatal(err)
		}
	}
	logical := filepath.Join(alias, "workspace", "workspace.db")
	f, err := openLegacyPublicationFS(filepath.Dir(logical))
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	actual, err := filepath.EvalSymlinks(physical)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(actual, "workspace.db")
	if err := os.WriteFile(logical, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		if got, err := f.canonicalSource(logical); err != nil || got != want {
			t.Fatalf("canonical source = %q, want %q: %v", got, want, err)
		}
	}
	check()
	if err := os.WriteFile(vaultSlotPath(logical), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logical); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestVaultMigrationPublicationRootWritesLongNamesAndRejectsOverwrite(t *testing.T) {
	root := t.TempDir()
	f, err := openLegacyPublicationFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	doc, key := localSlotFixture(t)
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, strings.Repeat("a", 220)+".db")
	if err := f.writeSlots(path, raw); err != nil {
		t.Fatal("temporary name inherited the long destination", err)
	}
	loaded, err := f.readSlots(path)
	if err != nil || vault.VerifySlotFile(key, loaded, doc.VaultID, doc.FileID, 1) != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"from", "to"} {
		if err := f.root.WriteFile(name, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := renameLegacyPublicationRootFile(f.root, "from", "to", false); err == nil {
		t.Fatal("native no-replace overwrote destination")
	}
	for _, name := range []string{"", "../escape", "c:stream", "\x00"} {
		if err := renameLegacyPublicationRootFile(f.root, "from", name, true); err == nil {
			t.Fatal("native target escaped parent")
		}
	}
	if err := renameLegacyPublicationRootFile(f.root, "absent", "to", false); err == nil {
		t.Fatal("missing source accepted")
	}
	for _, name := range []string{"from", "to"} {
		value, err := f.root.ReadFile(name)
		if err != nil || string(value) != name {
			t.Fatal("native guard changed unrelated bytes", err)
		}
	}
}

func TestVaultMigrationPublicationRootDoesNotFollowReplacedParent(t *testing.T) {
	base := t.TempDir()
	directory, displaced := filepath.Join(base, "workspace"), filepath.Join(base, "displaced")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := openLegacyPublicationFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer f.root.Close()
	if err := f.root.WriteFile("from", []byte("owned original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, displaced); err != nil {
		t.Skipf("native OS prevents renaming the live parent handle: %v", err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "from"), []byte("unrelated replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := moveLegacyPublicationFile(context.Background(), filepath.Join(directory, "from"), filepath.Join(directory, "to"), f); err == nil {
		t.Fatal("replaced parent was acknowledged")
	}
	// Even bypassing the pathname-identity acknowledgement, the native adapter
	// operates in the bound original directory and cannot touch the replacement.
	if err := renameLegacyPublicationRootFile(f.root, "from", "to", false); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(directory, "from"))
	if err != nil || string(value) != "unrelated replacement" {
		t.Fatal("replacement directory changed", err)
	}
	value, err = os.ReadFile(filepath.Join(displaced, "to"))
	if err != nil || string(value) != "owned original" {
		t.Fatal("native operation escaped original parent", err)
	}
}

func TestVaultMigrationPublicationResumesWindowsCaseAlias(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows case alias semantics")
	}
	db, source, initial, key, plan, _ := migrationStageFixture(t)
	db.Close()
	alias := filepath.Join(filepath.Dir(source), strings.ToUpper(filepath.Base(source)))
	root, _ := browserInventoryFixture(t)
	if _, err := continueLegacyVaultMigration(context.Background(), alias, root, initial, key, plan); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("source deliberately absent after native rename")
	_, err := publishLegacyVaultMigrationWith(context.Background(), alias, root, initial, key, plan, func(step string) error {
		if step == "source-retired" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	publication, err := publishLegacyVaultMigration(context.Background(), alias, root, initial, key, plan)
	if err != nil {
		t.Fatal("native spelling was lost during intentional source absence", err)
	}
	if err := publication.close(); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(source)
	if err != nil || bytes.Contains(value, []byte("private stage note")) {
		t.Fatal("case alias did not publish encrypted data", err)
	}
}

func TestVaultMigrationPublicationRejectsRedirectedLogicalParent(t *testing.T) {
	db, source, initial, key, plan, _ := migrationStageFixture(t)
	db.Close()
	alias := filepath.Join(t.TempDir(), "logical-parent")
	if err := os.Symlink(filepath.Dir(source), alias); err != nil {
		t.Skipf("native directory link creation unavailable: %v", err)
	}
	logical := filepath.Join(alias, filepath.Base(source))
	root, _ := browserInventoryFixture(t)
	if _, err := continueLegacyVaultMigration(context.Background(), logical, root, initial, key, plan); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	_, err := publishLegacyVaultMigrationWith(context.Background(), logical, root, initial, key, plan, func(step string) error {
		if step != "intent" {
			t.Fatal("redirected logical parent was adopted")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		return os.Symlink(foreign, alias)
	})
	if !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("logical parent redirect accepted", err)
	}
	entries, err := os.ReadDir(foreign)
	if err != nil || len(entries) != 0 {
		t.Fatal("foreign parent changed", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(source), alias); err != nil {
		t.Fatal(err)
	}
	publication, err := publishLegacyVaultMigration(context.Background(), logical, root, initial, key, plan)
	if err != nil {
		t.Fatal("original parent could not resume", err)
	}
	if publication.canonicalSource != source {
		t.Fatal("caller would retain the mutable logical alias")
	}
	publication.close()
}
