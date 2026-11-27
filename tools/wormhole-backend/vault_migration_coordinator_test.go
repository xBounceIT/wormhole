package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationCoordinatorResumesUnderContinuousOwnership(t *testing.T) {
	for _, stopped := range []string{"copied", "sources-retired", "sql-retired", "complete"} {
		t.Run(stopped, func(t *testing.T) {
			db, source, document, key, plan, _ := migrationStageFixture(t)
			root, files := browserInventoryFixture(t)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			stop := errors.New("coordinator interruption")
			var checkpoints []string
			stage, err := continueLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
				checkpoints = append(checkpoints, step)
				for _, lock := range []string{filepath.Join(filepath.Dir(source), ".workspace-owner.lock"), source + ".vault-migration.lock", source + ".migrating-" + document.FileID + ".vault.lock", credentialPrivateKeyLockPath(source), tunnelConfigurationLockPath(source)} {
					if release, err := tryAcquireExclusiveFileLock(lock); err == nil {
						release()
						t.Fatalf("ownership dropped between phases: %s", filepath.Base(lock))
					}
				}
				if step != "copied" && requireLegacyWorkspace(source) != errVaultOwnerRequired {
					t.Fatal("retiring source lost quarantine")
				}
				if step == stopped {
					return stop
				}
				return nil
			})
			if stopped == "complete" && err != nil || stopped != "complete" && (!errors.Is(err, stop) || stage != "") || len(checkpoints) == 0 {
				t.Fatal("incorrect interrupted outcome", stage, checkpoints, err)
			}
			var before []byte
			if stopped != "copied" {
				before, err = os.ReadFile(source + ".migrating-" + document.FileID)
				if err != nil {
					t.Fatal(err)
				}
			}
			wantStage := physicalMigrationPath(t, source) + ".migrating-" + document.FileID
			for retry := 0; retry < 2; retry++ {
				stage, err = continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
				if err != nil || stage != wantStage {
					t.Fatal("resume failed", stage, err)
				}
			}
			if stopped == "sql-retired" || stopped == "complete" {
				after, err := os.ReadFile(stage)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("completed retry rewrote encrypted stage", err)
				}
			}
			owner := openNativeMigrationStage(t, stage, key)
			stored, err := readVaultSlotFile(stage)
			if err != nil {
				t.Fatal(err)
			}
			_, journal, err := readLegacyRetirementJournal(context.Background(), owner, stored, 0, 0)
			if err != nil || journal.SQL == nil || journal.SQL.Phase != "compacted" || journal.Browser == nil || journal.Browser.Completed != 3 {
				t.Fatal("incomplete retirement", err)
			}
			owner.Close()
			if requireLegacyWorkspace(source) != errVaultOwnerRequired {
				t.Fatal("coordinator published incomplete cutover")
			}
			for _, relative := range []string{"Local State", "Partitions/unrelated-web/Cookies"} {
				actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
				if err != nil || !bytes.Equal(actual, files[relative]) {
					t.Fatal("unrelated browser state changed", relative, err)
				}
			}
			release, err := acquireWorkspaceOwnership(source, true)
			if err != nil {
				t.Fatal("coordinator leaked ownership", err)
			}
			release()
		})
	}
}

func TestVaultMigrationCoordinatorRejectsChangedSetupAndSources(t *testing.T) {
	for _, mutation := range []string{"password-slot", "root", "workspace", "epoch", "plan", "browser-root", "stage-bytes", "late-browser", "late-source"} {
		t.Run(mutation, func(t *testing.T) {
			db, source, document, key, plan, _ := migrationStageFixture(t)
			root, _ := browserInventoryFixture(t)
			db.Close()
			stop := errors.New("checkpoint")
			_, err := continueLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
				if mutation == "late-browser" || mutation == "late-source" {
					if step != "sql-retired" {
						return nil
					}
				}
				return stop
			})
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			stage := source + ".migrating-" + document.FileID
			switch mutation {
			case "password-slot":
				document.Slots[0].ID = uuid.NewString()
			case "root":
				document.RootKeyID = uuid.NewString()
			case "workspace":
				document.VaultID, plan.WorkspaceID = uuid.NewString(), uuid.NewString()
			case "epoch":
				document.FileEpoch++
			case "plan":
				plan.Fingerprint = strings.Repeat("a", 64)
			case "browser-root":
				root = t.TempDir()
			case "stage-bytes":
				if err := os.WriteFile(stage, []byte("untrusted stage bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "late-browser":
				if err := os.Mkdir(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure"), 0700); err != nil {
					t.Fatal(err)
				}
			case "late-source":
				db, err = openLegacyMigrationSource(source)
				if err != nil {
					t.Fatal(err)
				}
				legacyVaultSQL(t, db, "UPDATE Nodes SET Notes='late modified note'")
				db.Close()
			}
			if path, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan); err == nil || path != "" {
				t.Fatal("changed migration adopted", path, err)
			}
		})
	}
}

func TestVaultMigrationCoordinatorCancellationAndInvalidRequests(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	ctx := context.Background()
	root := t.TempDir()
	if _, err := continueLegacyVaultMigration(ctx, source, "relative", document, key, plan); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	if _, err := continueLegacyVaultMigration(ctx, source, root, document, nil, plan); err == nil {
		t.Fatal("missing key admitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := continueLegacyVaultMigration(cancelled, source, root, document, key, plan); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	cancelled, cancel = context.WithCancel(ctx)
	_, err := continueLegacyVaultMigrationWith(cancelled, source, root, document, key, plan, func(string) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation after copy lost", err)
	}
	if _, err := continueLegacyVaultMigration(ctx, source, root, document, key, plan); err != nil {
		t.Fatal("cancelled copy could not resume", err)
	}
}

func TestVaultMigrationCoordinatorResumesBeforeFirstRetirementIntent(t *testing.T) {
	for _, phase := range []string{vault.MigrationCopying, vault.MigrationRetiring} {
		t.Run(phase, func(t *testing.T) {
			testVaultMigrationCoordinatorMissingIntent(t, phase)
		})
	}
}

func testVaultMigrationCoordinatorMissingIntent(t *testing.T, phase string) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	root, _ := browserInventoryFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := readVaultSlotFile(stage.Path)
	if err != nil {
		t.Fatal(err)
	}
	// The slot transition is durable before the first retirement journal write.
	marker.Sequence++
	marker.Migration.Phase = phase
	if phase == vault.MigrationCopying {
		marker.Migration.Snapshot = nil
	}
	if err := writeVaultSlotFile(stage.Path, key, marker, marker.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan); err != nil {
		t.Fatal("pre-intent interruption could not resume", err)
	}
}

func TestVaultMigrationCoordinatorResumesUnacknowledgedSQLCommit(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	root, _ := browserInventoryFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retireLegacyVaultSources(context.Background(), source, root, stage.Path, key); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("unacknowledged SQL commit")
	err = retireLegacyVaultSQLWith(context.Background(), source, stage.Path, key, openMigrationCredentialStore, func(step string) error {
		if step == "commit" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if path, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan); err != nil || path != stage.Path {
		t.Fatal("coordinator repeated retired file/key phase", path, err)
	}
}

func TestVaultMigrationCoordinatorStopsOnLateSourceChange(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	root, _ := browserInventoryFixture(t)
	_, err := continueLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
		if step != "copied" {
			t.Fatal("continued after source mutation")
		}
		return os.WriteFile(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure", "Cookies"), []byte("late Chromium cookie update"), 0600)
	})
	if err == nil {
		t.Fatal("late source bytes were retired")
	}
	if _, err := os.Lstat(vaultSlotPath(source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retirement guard published before source authentication", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure", "Cookies")); err != nil {
		t.Fatal("source was deleted after mismatch", err)
	}
}
