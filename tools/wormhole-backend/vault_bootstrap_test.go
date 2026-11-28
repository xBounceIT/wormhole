package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestVaultLegacyEntryPointsRefusePendingMigrationWithoutSourceSlots(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "workspace.db")
	if err := requireLegacyWorkspace(filepath.Join(root, "missing-parent", "new.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "workspace2.db.migrating-unrelated.slots"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireLegacyWorkspace(source); err != nil {
		t.Fatal("unrelated migration blocked workspace", err)
	}
	marker := source + ".migrating-malformed.slots"
	if err := os.WriteFile(marker, []byte("invalid or unauthenticated phase"), 0600); err != nil {
		t.Fatal(err)
	}
	if requireLegacyWorkspace(source) != errVaultOwnerRequired {
		t.Fatal("pending migration restored legacy access")
	}
	if _, err := openDatabase(source, true); err != errVaultOwnerRequired {
		t.Fatal("database creation bypassed migration quarantine", err)
	}
	if requireLegacySlotAbsent(source) != nil {
		t.Fatal("authenticated migration cannot resume")
	}
	var out, diagnostic strings.Builder
	code := runBackendCLI([]string{"--operation", "startup", "--database", source}, strings.NewReader(""), &out, &diagnostic)
	if code != 1 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "vault_owner_required") {
		t.Fatal("legacy startup bypassed quarantine", code, out.String(), diagnostic.String())
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	if requireLegacyWorkspace(source) != errVaultOwnerRequired {
		t.Fatal("invalid marker type re-enabled legacy")
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(root, "Σ.db.MIGRATING-malformed.SLOTS"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if requireLegacyWorkspace(filepath.Join(root, "ς.db")) != errVaultOwnerRequired {
			t.Fatal("case alias bypassed migration quarantine")
		}
	}
}

func pendingVault(t *testing.T, path string) (vault.SlotFile, []byte) {
	t.Helper()
	document, key := localSlotFixture(t)
	document.Initializing = true
	if err := writeVaultSlotFile(path, key, document, 0); err != nil {
		t.Fatal(err)
	}
	document, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return document, key
}

func TestVaultBootstrapResumesCreationWithoutRecreatingLostData(t *testing.T) {
	for _, stage := range []string{"slots-only", "torn-stage", "published"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			doc, key := pendingVault(t, path)
			defer vault.Wipe(key)
			staging := vaultStagingPath(path, doc)
			if stage == "torn-stage" {
				for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
					if err := os.WriteFile(staging+suffix, []byte("interrupted initialization"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if stage == "published" {
				s, err := vaultstore.OpenSQLite(context.Background(), path, localVaultOptions(doc).Identity, true)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			owner, err := openVaultFiles(context.Background(), path, doc, key)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := owner.ReadLocalPolicy(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			done, err := readVaultSlotFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if done.Initializing || done.Sequence != 2 || done.ProfileSequence != policy.Policy.Sequence {
				t.Fatal("pending marker not committed")
			}
			if err := vault.VerifySlotFile(key, done, doc.VaultID, doc.FileID, 2); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(staging); !os.IsNotExist(err) {
				t.Fatal("staging file survived")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := openVaultFiles(context.Background(), path, done, key); !errors.Is(err, vaultstore.ErrMissing) {
				t.Fatalf("lost database recreated: %v", err)
			}
		})
	}
}

func TestVaultBootstrapCreateAndRefuseExistingArtifacts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace.db")
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	if _, err := initializeVaultFiles(ctx, path, doc, key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	doc.Initializing = true
	owner, err := initializeVaultFiles(ctx, path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	owner.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializeVaultFiles(ctx, path, doc, key); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing vault overwritten")
	}
	legacy := filepath.Join(t.TempDir(), "legacy.db")
	plain := []byte("existing legacy database")
	if err := os.WriteFile(legacy, plain, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := initializeVaultFiles(ctx, legacy, doc, key); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := os.Lstat(vaultSlotPath(legacy)); !os.IsNotExist(err) {
		t.Fatal("existing workspace disabled")
	}
	pending := filepath.Join(t.TempDir(), "pending.db")
	pendingVault(t, pending)
	if _, err := initializeVaultFiles(ctx, pending, doc, key); err != errVaultSlotConflict {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := initializeVaultFiles(cancelled, filepath.Join(t.TempDir(), "db"), doc, key); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestVaultBootstrapRequiresAuthenticationBeforeCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	doc, key := pendingVault(t, path)
	defer vault.Wipe(key)
	staging := vaultStagingPath(path, doc)
	marker := []byte("must not delete before authentication")
	if err := os.WriteFile(staging, marker, 0600); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if _, err := openVaultFiles(context.Background(), path, doc, wrong); err != vault.ErrKeyCheck {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(staging)
	if !bytes.Equal(body, marker) {
		t.Fatal("cleanup before key check")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openVaultFiles(cancelled, path, doc, key); err != context.Canceled {
		t.Fatal(err)
	}
	// A preexisting wrong target must be preserved even with a valid pending marker.
	if err := os.WriteFile(path, marker, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openVaultFiles(context.Background(), path, doc, key); !errors.Is(err, vaultstore.ErrStorage) {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	if !bytes.Equal(body, marker) {
		t.Fatal("wrong target repaired")
	}
}

func TestVaultBootstrapFailureStatesRemainRecoverable(t *testing.T) {
	for _, mode := range []string{"stage-directory", "wrong-sequence", "cancel-after-marker", "final-sync"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			doc, key := localSlotFixture(t)
			defer vault.Wipe(key)
			doc.Initializing = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := privateFileDirectorySync
			defer func() { privateFileDirectorySync = original }()
			if mode == "cancel-after-marker" {
				privateFileDirectorySync = func(string) error { cancel(); return nil }
				if _, err := initializeVaultFiles(ctx, path, doc, key); err != context.Canceled {
					t.Fatal(err)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("database created after cancellation")
				}
				return
			}
			if err := writeVaultSlotFile(path, key, doc, 0); err != nil {
				t.Fatal(err)
			}
			doc, err := readVaultSlotFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := vault.ErrPolicy
			switch mode {
			case "stage-directory":
				if err := os.Mkdir(vaultStagingPath(path, doc), 0700); err != nil {
					t.Fatal(err)
				}
				want = errVaultSlotStorage
			case "wrong-sequence":
				doc.Sequence = 2
				raw, err := vault.EncodeSlotFile(key, doc)
				if err != nil {
					t.Fatal(err)
				}
				doc, err = vault.DecodeSlotFile(raw)
				if err != nil {
					t.Fatal(err)
				}
			case "final-sync":
				// Publication succeeds; the final slot replacement becomes durable
				// but reports uncertain directory sync. A retry must open that DB.
				calls := 0
				privateFileDirectorySync = func(string) error {
					calls++
					if calls == 2 {
						return errors.New("injected private error")
					}
					return nil
				}
				want = errVaultSlotCommitUncertain
			}
			if _, err := openVaultFiles(ctx, path, doc, key); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			if mode == "final-sync" {
				privateFileDirectorySync = original
				done, err := readVaultSlotFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if done.Initializing {
					t.Fatal("replacement did not occur")
				}
				owner, err := openVaultFiles(context.Background(), path, done, key)
				if err != nil {
					t.Fatal(err)
				}
				owner.Close()
			}
		})
	}
}

func TestVaultPublicationNeverOverwritesDestination(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "stage"), filepath.Join(dir, "db")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishVaultFile(source, target); err == nil {
		t.Fatal("existing destination replaced")
	}
	value, _ := os.ReadFile(target)
	if string(value) != "old" {
		t.Fatal("target changed")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := publishVaultFile(source, target); err != nil {
		t.Fatal(err)
	}
	value, _ = os.ReadFile(target)
	if string(value) != "new" {
		t.Fatal("source not published")
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatal("source survived")
	}
	if err := publishVaultFile("bad\x00", target); err == nil {
		t.Fatal("invalid source accepted")
	}
	if err := publishVaultFile(target, "bad\x00"); err == nil {
		t.Fatal("invalid destination accepted")
	}
}

func TestVaultLegacyEntryPointsFailClosedOnSlotPresence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if err := requireLegacyWorkspace(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(path), []byte("invalid slot metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDatabase(path, true); err != errVaultOwnerRequired {
		t.Fatal(err)
	}
	for _, operation := range []string{"startup", "migrate", "credential-create", "serve", "ssh", "backup-export", "settings-read"} {
		var out, diagnostic strings.Builder
		code := runBackendCLI([]string{"--operation", operation, "--database", path}, strings.NewReader(""), &out, &diagnostic)
		if code != 1 || !strings.Contains(diagnostic.String(), "vault_owner_required") || out.Len() != 0 {
			t.Fatalf("legacy %s not blocked: %d %s", operation, code, diagnostic.String())
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("legacy migration created DB")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "logs")); !os.IsNotExist(err) {
		t.Fatal("legacy logging started")
	}
}

func TestVaultBootstrapRejectsPendingMarkerReplayAfterUserWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	pending, key := pendingVault(t, path)
	defer vault.Wipe(key)
	owner, err := openVaultFiles(context.Background(), path, pending, key)
	if err != nil {
		t.Fatal(err)
	}
	ref := vaultstore.SecretRef{OwnerKind: "credential", OwnerID: uuid.NewString(), Field: "password"}
	if _, err := owner.Put(context.Background(), ref, []byte("keep-existing-secret"), 0); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(vaultSlotPath(path))
	if err != nil {
		t.Fatal(err)
	}
	oldMarker, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(path), oldMarker, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openVaultFiles(context.Background(), path, pending, key); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatalf("old pending marker accepted: %v", err)
	}
	unchanged, err := os.ReadFile(vaultSlotPath(path))
	if err != nil || !bytes.Equal(oldMarker, unchanged) {
		t.Fatal("replay rewrote slots")
	}
	if err := os.WriteFile(vaultSlotPath(path), committed, 0600); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := openVaultFiles(context.Background(), path, doc, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.WithSecret(context.Background(), ref, 1, func(secret []byte) error {
		if string(secret) != "keep-existing-secret" {
			t.Error("stored value changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
