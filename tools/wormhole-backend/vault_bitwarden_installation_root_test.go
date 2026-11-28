package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultBitwardenDatabaseRootIsolation(t *testing.T) {
	parent := t.TempDir()
	a, b := filepath.Join(parent, "a.db"), filepath.Join(parent, "b.db")
	for _, database := range []string{a, b} {
		if _, err := openVaultBitwardenInstallRoot(database, 1, false); err == nil {
			t.Fatal("created on read")
		}
		root, err := openVaultBitwardenInstallRoot(database, 1, true)
		if err != nil {
			t.Fatal(err)
		}
		if database == a {
			if err = root.WriteFile("marker", []byte("a"), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err = root.Stat("marker"); !os.IsNotExist(err) {
				t.Fatal("cross database read", err)
			}
		}
		root.Close()
	}
	root, err := openVaultBitwardenInstallRoot(a, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := root.ReadFile("marker"); err != nil || string(raw) != "a" {
		t.Fatal(err)
	}
	root.Close()
	legacy, err := openVaultBitwardenInstallRoot(a, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	for _, q := range []struct {
		path   string
		layout int
		create bool
	}{{"relative", 1, true}, {a, -1, false}, {a, 2, false}, {a, 0, true}} {
		if _, err := openVaultBitwardenInstallRoot(q.path, q.layout, q.create); err == nil {
			t.Fatal("invalid root")
		}
	}
	// Files in either directory position must never be treated as roots.
	blocked := t.TempDir()
	if err = os.WriteFile(filepath.Join(blocked, vaultBitwardenInstallDirectory), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openVaultBitwardenInstallRoot(filepath.Join(blocked, "x.db"), 1, true); err == nil {
		t.Fatal("file parent")
	}
	name := vaultBitwardenDatabaseDirectory(filepath.Join(parent, "blocked.db"))
	if err = os.WriteFile(filepath.Join(parent, vaultBitwardenInstallDirectory, name), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openVaultBitwardenInstallRoot(filepath.Join(parent, "blocked.db"), 1, true); err == nil {
		t.Fatal("file namespace")
	}
	if _, err = openVaultBitwardenInstallRoot(filepath.Join(parent, "missing", "x.db"), 1, true); err == nil {
		t.Fatal("missing parent")
	}
}

func TestVaultBitwardenLegacyReplacementUsesScopedRoot(t *testing.T) {
	ctx := context.Background()
	h := vaultCredentialFixture(t)
	parent := filepath.Join(filepath.Dir(h.databasePath), vaultBitwardenInstallDirectory)
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	id := preparedVaultExtension(t, legacy, vaultExtensionTestManifest)
	if _, err = activatePreparedVaultExtension(ctx, h.owner, legacy, id, 0); err != nil {
		t.Fatal(err)
	}
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	query := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "minimumRevision": "1"})
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", query); err != nil {
		t.Fatal("legacy unreadable", err)
	}
	_, source := installerRoots(t)
	action := browserTransferJSON(t, map[string]any{"workspaceId": workspace, "sourceDirectory": source.Name(), "expectedRevision": "1"})
	if _, err = h.Handle(ctx, "bitwarden-install-folder", action); err != nil {
		t.Fatal(err)
	}
	value, revision, err := h.owner.ReadBitwardenInstallation(ctx, 2)
	if err != nil || revision != 2 || value.Layout != 1 || value.InstallationID == id {
		t.Fatal(value, revision, err)
	}
	if _, err = legacy.Stat(id); err != nil {
		t.Fatal("legacy package removed", err)
	}
	if _, err = legacy.Stat(value.InstallationID); !os.IsNotExist(err) {
		t.Fatal("new package shared", err)
	}
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", query); err != nil {
		t.Fatal("scoped package unreadable", err)
	}
	// A rename cannot silently load a package from another namespace or legacy root.
	h.databasePath = filepath.Join(filepath.Dir(h.databasePath), "renamed.db")
	if _, err = h.Handle(ctx, "bitwarden-installation-plan", query); err == nil {
		t.Fatal("rename fallback")
	}
	if _, err = h.Handle(ctx, "bitwarden-installation-revision", query); err != nil {
		t.Fatal("rename cannot repair", err)
	}
}
