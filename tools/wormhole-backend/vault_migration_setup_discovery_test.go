package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationSetupDiscoveryStartupAndQuarantine(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	ctx := context.Background()
	if hint, err := discoverLegacyMigrationSetup(ctx, setup.LogicalSource); err != nil || hint != nil {
		t.Fatal("absent setup discovered", err)
	}
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: setup.LogicalSource}
	raw, err := h.startup(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var metadata vaultStartupMetadata
	if json.Unmarshal(raw, &metadata) != nil || metadata.Migration == nil || !metadata.Migration.Pending || metadata.NewWorkspace || metadata.Shared != nil || metadata.Slots.VaultID != setup.Initial.VaultID {
		t.Fatal("incorrect pending startup", string(raw))
	}
	for _, private := range []string{setup.UserData, setup.CanonicalSource, "ciphertext", "binding", "initial", "candidate", "rootKey"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("startup exposed private setup", private)
		}
	}
	// Source and public marker loss must not enable fresh creation or shared
	// selection over a pending local setup, including its pre-stage crash window.
	if err := os.Remove(setup.LogicalSource); err != nil {
		t.Fatal(err)
	}
	if requireNewVaultWorkspace(setup.LogicalSource) != errVaultOwnerRequired {
		t.Fatal("source loss enabled new creation")
	}
	if err := os.Mkdir(sharedWorkspaceDirectory(setup.LogicalSource), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.describeSharedStartup(ctx); err != errVaultOwnerRequired {
		t.Fatal("shared selection bypassed setup", err)
	}
	raw, err = h.startup(ctx, nil)
	if err != nil || !bytes.Contains(raw, []byte(`"migration":{"pending":true}`)) {
		t.Fatal("shared marker hid pending setup", err)
	}
}

func TestVaultMigrationSetupDiscoveryRejectsAmbiguousAndUnsafeHints(t *testing.T) {
	for _, mutation := range []string{"bad id", "other id", "two setups", "directory", "corrupt header", "wrong order", "wrong phase", "oversize", "truncated private body"} {
		t.Run(mutation, func(t *testing.T) {
			setup, key := migrationSetupFixture(t)
			ctx := context.Background()
			if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
				t.Fatal(err)
			}
			path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "bad id":
				err = os.Rename(path, legacyMigrationSetupPath(setup.CanonicalSource, "bad-id"))
			case "other id":
				err = os.Rename(path, legacyMigrationSetupPath(setup.CanonicalSource, uuid.NewString()))
			case "two setups":
				err = os.WriteFile(legacyMigrationSetupPath(setup.CanonicalSource, uuid.NewString()), raw, 0600)
			case "directory":
				err = os.Remove(path)
				if err == nil {
					err = os.Mkdir(path, 0700)
				}
			case "corrupt header":
				err = os.WriteFile(path, []byte(`{"version":"bad"}`), 0600)
			case "wrong order":
				err = os.WriteFile(path, append([]byte(`{"bytes":1,`), raw[1:]...), 0600)
			case "wrong phase":
				err = os.WriteFile(path, bytes.Replace(raw, []byte(`"copying"`), []byte(`"retiring"`), 1), 0600)
			case "oversize":
				var file *os.File
				file, err = os.OpenFile(path, os.O_WRONLY, 0600)
				if err == nil {
					err = file.Truncate(maxLegacyMigrationCapsuleBytes + 1)
					file.Close()
				}
			case "truncated private body":
				end := bytes.Index(raw, []byte(`"chunks":[`)) + len(`"chunks":[`)
				err = os.WriteFile(path, raw[:end], 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			hint, err := discoverLegacyMigrationSetup(ctx, setup.LogicalSource)
			if mutation == "truncated private body" {
				if err != nil || hint == nil {
					t.Fatal("public hint unexpectedly decrypted private body", err)
				}
				if _, err := readLegacyMigrationSetup(ctx, hint.CanonicalSource, hint.Document, key); err == nil {
					t.Fatal("truncated private body authenticated")
				}
			} else if err == nil || hint != nil {
				t.Fatal("unsafe hint accepted")
			}
			if requireLegacyWorkspace(setup.LogicalSource) == nil {
				t.Fatal("damaged setup enabled legacy fallback")
			}
		})
	}
	if _, err := discoverLegacyMigrationSetup(context.Background(), "relative.db"); err != vault.ErrFormat {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discoverLegacyMigrationSetup(ctx, filepath.Join(t.TempDir(), "source.db")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if hint, err := discoverLegacyMigrationSetup(context.Background(), filepath.Join(t.TempDir(), "missing", "source.db")); err != nil || hint != nil {
		t.Fatal(err)
	}
}

func TestVaultMigrationSetupDiscoveryBoundsPublicHeader(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	if err := saveLegacyMigrationSetup(context.Background(), setup, key); err != nil {
		t.Fatal(err)
	}
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte(strings.Repeat(" ", vault.MaxSlotFileBytes+1025)), raw...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := discoverLegacyMigrationSetup(context.Background(), setup.LogicalSource); err == nil {
		t.Fatal("unbounded public prefix consumed")
	}
}

func TestVaultMigrationSetupDiscoveryUnicodeAndLinkedCapsule(t *testing.T) {
	setup, key := migrationSetupFixture(t)
	path := filepath.Join(filepath.Dir(setup.CanonicalSource), "κ-native-è.db")
	if err := os.Rename(setup.CanonicalSource, path); err != nil {
		t.Fatal(err)
	}
	setup.LogicalSource, setup.CanonicalSource = path, path
	ctx := context.Background()
	if err := saveLegacyMigrationSetup(ctx, setup, key); err != nil {
		t.Fatal(err)
	}
	hint, err := discoverLegacyMigrationSetup(ctx, path)
	if err != nil || hint == nil || hint.Document.FileID != setup.Initial.FileID {
		t.Fatal("Unicode filename lost its recovery hints", err)
	}
	capsule := legacyMigrationSetupPath(path, setup.Initial.FileID)
	foreign := filepath.Join(t.TempDir(), "original.setup")
	if err := os.Rename(capsule, foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, capsule); err != nil {
		t.Skipf("native symlink creation unavailable: %v", err)
	}
	if _, err := discoverLegacyMigrationSetup(ctx, path); err == nil {
		t.Fatal("linked setup trusted as native hint")
	}
	if _, err := readLegacyMigrationSetup(ctx, path, setup.Initial, key); err == nil {
		t.Fatal("linked setup decrypted")
	}
	if requireLegacyWorkspace(path) != errVaultOwnerRequired {
		t.Fatal("linked capsule enabled legacy fallback")
	}
}
