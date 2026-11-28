package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestSharedWorkspaceSelection(t *testing.T) {
	source := filepath.Join(t.TempDir(), "local.db")
	target := localSharedWorkspaceDatabase(source)
	protection := startupTestProtection()
	if path, selection, err := resolveVaultWorkspace(source, protection); err != nil || path != source || selection != nil {
		t.Fatal("missing selection should retain the local workspace", err)
	}

	fixture, account := sharedStartupFixture(t)
	anchor, err := writeSharedStartupAnchor(context.Background(), fixture.o, account, "Shared workspace", 0, protection)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishSharedWorkspaceSelection(source, anchor, protection); err != nil {
		t.Fatal(err)
	}
	if err := publishSharedWorkspaceSelection(source, anchor, protection); err != nil {
		t.Fatal("exact retry", err)
	}
	other := anchor
	other.Binding.DeviceID = uuid.New()
	if err := publishSharedWorkspaceSelection(source, other, protection); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("replaced an existing selection", err)
	}
	if err := requireLegacyWorkspace(source); !errors.Is(err, errVaultOwnerRequired) {
		t.Fatal("selection allowed legacy fallback", err)
	}

	rejectTarget := func() {
		t.Helper()
		if path, selection, err := resolveVaultWorkspace(source, protection); err == nil || path != "" || selection != nil {
			t.Fatal("invalid shared destination yielded a workspace", path, err)
		}
	}
	rejectTarget()
	if err := os.Mkdir(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	rejectTarget()
	if err := os.Mkdir(sharedWorkspaceDirectory(target), 0700); err != nil {
		t.Fatal(err)
	}
	rejectTarget()
	writeAnchor := func(a sharedStartupAnchor) {
		t.Helper()
		trust := sharedWorkspaceTrustPath(target)
		digest := sha256.Sum256([]byte(trust))
		a.PathDigest = digest[:]
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		path := sharedStartupAnchorPath(trust)
		sealed, err := protection.protect(path, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, sealed, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mismatched := anchor
	mismatched.VaultID = uuid.NewString()
	writeAnchor(mismatched)
	rejectTarget()
	writeAnchor(anchor)
	path, selection, err := resolveVaultWorkspace(source, protection)
	if err != nil || path != target || selection == nil || !selection.matches(anchor) {
		t.Fatal("failed to resolve confirmed destination", err)
	}
	h := &vaultFoundationHandler{databasePath: target, sharedSelection: selection, sharedProtection: &protection}
	if err := os.Rename(sharedWorkspaceDirectory(target), sharedWorkspaceDirectory(target)+".retired"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(context.Background(), "describe", nil); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("describe allowed fallback after launch", err)
	}
}

func TestSharedWorkspaceSelectionRejectsInvalidRecord(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "local.db")
	other := filepath.Join(root, "other.db")
	protection := startupTestProtection()
	fixture, account := sharedStartupFixture(t)
	anchor, err := writeSharedStartupAnchor(context.Background(), fixture.o, account, "Shared workspace", 0, protection)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishSharedWorkspaceSelection(source, anchor, protection); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(sharedWorkspaceSelectionPath(source))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"copied marker", sealed},
		{"corrupt marker", []byte("invalid")},
		{"empty marker", nil},
		{"oversized marker", bytes.Repeat([]byte{1}, maxSharedWorkspaceSelectionBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(sharedWorkspaceSelectionPath(other), tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			if path, selection, err := resolveVaultWorkspace(other, protection); !errors.Is(err, errSharedTrustStorage) || path != "" || selection != nil {
				t.Fatal("invalid marker was accepted", path, err)
			}
		})
	}
}
