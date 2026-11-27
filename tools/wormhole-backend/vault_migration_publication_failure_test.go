package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationPublicationRefusesChangedFilesAndSelections(t *testing.T) {
	for _, mutation := range []string{"source", "stage", "backup", "stage-marker", "source-link", "stage-link", "backup-link", "marker-link", "missing-stage", "missing-marker", "missing-source", "duplicate-backup", "revived-browser", "revived-cache", "root-selection", "password-slot", "plan"} {
		t.Run(mutation, func(t *testing.T) {
			db, source, document, key, plan, _ := migrationStageFixture(t)
			db.Close()
			root, _ := browserInventoryFixture(t)
			stage, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("durable publication intent")
			if _, err := publishLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(string) error { return stop }); !errors.Is(err, stop) {
				t.Fatal(err)
			}
			var preserved string
			switch mutation {
			case "source-link", "stage-link", "backup-link", "marker-link":
				preserved = filepath.Join(t.TempDir(), "outside-owned-profile")
				if err := os.WriteFile(preserved, []byte("unrelated late-created data"), 0600); err != nil {
					t.Fatal(err)
				}
				link := map[string]string{"source-link": source, "stage-link": stage, "backup-link": source + ".retired-" + document.FileID, "marker-link": vaultSlotPath(stage)}[mutation]
				if mutation != "backup-link" {
					if err := os.Remove(link); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(preserved, link); err != nil {
					t.Skipf("native symlink creation unavailable: %v", err)
				}
			case "source", "stage", "backup", "stage-marker":
				preserved = map[string]string{"source": source, "stage": stage, "backup": source + ".retired-" + document.FileID, "stage-marker": vaultSlotPath(stage)}[mutation]
				if err := os.WriteFile(preserved, []byte("unrelated late-created data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-stage":
				if err := os.Remove(stage); err != nil {
					t.Fatal(err)
				}
			case "missing-marker":
				if err := os.Remove(vaultSlotPath(stage)); err != nil {
					t.Fatal(err)
				}
			case "missing-source":
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
			case "duplicate-backup":
				original, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source+".retired-"+document.FileID, original, 0600); err != nil {
					t.Fatal(err)
				}
			case "revived-browser":
				if err := os.Mkdir(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure"), 0700); err != nil {
					t.Fatal(err)
				}
			case "revived-cache":
				preserved = legacyLocalStateFiles(source, document.VaultID)[0].path
				if err := os.WriteFile(preserved, []byte("unrelated late-created data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "root-selection":
				root = t.TempDir()
			case "password-slot":
				document.Slots[0].ID = uuid.NewString()
			case "plan":
				plan.Entries[0].Choice = "invalid choice"
			}
			if publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan); err == nil || publication != nil {
				t.Fatal("unrelated/changed state adopted", err)
			}
			if preserved != "" {
				value, err := os.ReadFile(preserved)
				if err != nil || string(value) != "unrelated late-created data" {
					t.Fatal("unrelated file removed or overwritten", err)
				}
			}
			guard, err := readVaultSlotFile(source)
			if err != nil || guard.Migration == nil {
				t.Fatal("failed publication enabled ordinary unlock", err)
			}
		})
	}
}

func TestVaultMigrationPublicationPreservesLateDestinationAndMarker(t *testing.T) {
	for _, changed := range []string{"destination", "marker", "backup"} {
		t.Run(changed, func(t *testing.T) {
			db, source, document, key, plan, _ := migrationStageFixture(t)
			db.Close()
			root, _ := browserInventoryFixture(t)
			stage, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal(err)
			}
			var preserved string
			publication, err := publishLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
				switch {
				case changed == "destination" && step == "source-retired":
					preserved = source
				case changed == "marker" && step == "source-removed":
					preserved = vaultSlotPath(stage)
				case changed == "backup" && step == "source-retired":
					preserved = source + ".retired-" + document.FileID
				default:
					return nil
				}
				return os.WriteFile(preserved, []byte("late destination must survive"), 0600)
			})
			if publication != nil || err == nil || preserved == "" {
				t.Fatal("late replacement ignored", err)
			}
			value, err := os.ReadFile(preserved)
			if err != nil || string(value) != "late destination must survive" {
				t.Fatal("late data overwritten/removed", err)
			}
		})
	}
}

func TestVaultMigrationPublicationNativeFileGuards(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	from, to := filepath.Join(root, "from"), filepath.Join(root, "to")
	for _, path := range []string{from, to} {
		if err := os.WriteFile(path, []byte(path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := moveLegacyPublicationFile(cancelled, from, to); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := moveLegacyPublicationFile(ctx, from, to); !errors.Is(err, errVaultSlotCommitUncertain) {
		t.Fatal("no-replace operation overwrote destination", err)
	}
	if err := verifyLegacyPublicationFile(ctx, from, vault.SlotFile{}, nil, nil); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("missing proof accepted", err)
	}
	if err := removeLegacyPublicationFile(ctx, from, vault.SlotFile{}, nil, &vault.MigrationSnapshot{}); err == nil {
		t.Fatal("unauthenticated file removed")
	}
	if err := removeLegacyPublicationFile(ctx, root, vault.SlotFile{}, nil, nil); !errors.Is(err, errVaultSlotStorage) {
		t.Fatal("directory accepted for file retirement", err)
	}
	for _, path := range []string{from, to} {
		value, err := os.ReadFile(path)
		if err != nil || string(value) != path {
			t.Fatal("native guard changed unverified file", err)
		}
	}
}

func TestVaultMigrationPublicationResumesLinkBeforeUnlink(t *testing.T) {
	for _, phase := range []string{"old-source", "new-source"} {
		t.Run(phase, func(t *testing.T) {
			db, source, document, key, plan, _ := migrationStageFixture(t)
			db.Close()
			root, _ := browserInventoryFixture(t)
			stage, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("interrupted no-replace move")
			_, err = publishLegacyVaultMigrationWith(context.Background(), source, root, document, key, plan, func(step string) error {
				if phase == "old-source" && step == "intent" {
					if err := os.Link(source, source+".retired-"+document.FileID); err != nil {
						t.Fatal(err)
					}
					return stop
				}
				if phase == "new-source" && step == "source-retired" {
					if err := os.Link(stage, source); err != nil {
						t.Fatal(err)
					}
					return stop
				}
				return nil
			})
			if !errors.Is(err, stop) {
				t.Fatal(err)
			}
			publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
			if err != nil {
				t.Fatal("matching hardlink recovery failed", err)
			}
			if err := publication.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVaultMigrationPublicationCancellationBeforeMoves(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	root, _ := browserInventoryFixture(t)
	if _, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = publishLegacyVaultMigrationWith(ctx, source, root, document, key, plan, func(string) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("cancellation modified old database", err)
	}
	publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal("cancelled publication could not resume", err)
	}
	publication.close()
}

func TestVaultMigrationPublicationRequiresCompleteRetirement(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	db.Close()
	root, _ := browserInventoryFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	if publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan); err == nil || publication != nil {
		t.Fatal("copy-only stage published", err)
	}
	if _, err := retireLegacyVaultFiles(context.Background(), source, root, stage.Path, key); err != nil {
		t.Fatal(err)
	}
	if publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan); err == nil || publication != nil {
		t.Fatal("incomplete browser/key retirement published", err)
	}
	if _, err := continueLegacyVaultMigration(context.Background(), source, root, document, key, plan); err != nil {
		t.Fatal(err)
	}
	publication, err := publishLegacyVaultMigration(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	publication.close()
	if _, err := publishLegacyVaultMigration(context.Background(), source, root, document, nil, plan); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("missing key accepted", err)
	}
}
