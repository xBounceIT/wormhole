package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type browserRetirementFixture struct {
	retirementFixture
	root      string
	inventory *legacyBrowserInventory
}

func newBrowserRetirementFixture(t *testing.T) browserRetirementFixture {
	t.Helper()
	db, source, document, key, plan, _ := migrationStageFixture(t)
	root, _ := browserInventoryFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	doc, err := readVaultSlotFile(stage.Path)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _, _, err := readLegacyRetirementInventory(context.Background(), owner, doc, source)
	if err != nil || inventory.Browser == nil {
		t.Fatal(err)
	}
	owner.Close()
	return browserRetirementFixture{retirementFixture{db: db, source: source, stage: stage.Path, document: doc, key: key}, root, inventory.Browser}
}

func (f browserRetirementFixture) retire(ctx context.Context, remove ...func(*os.Root, string) error) (legacyRetirementProgress, error) {
	return retireLegacyVaultSourcesWith(ctx, f.source, f.root, f.stage, f.key, func(string, []byte) error { return nil }, openMigrationCredentialStore, remove...)
}

func readBrowserRetirementJournal(t *testing.T, f browserRetirementFixture) legacyRetirementJournal {
	t.Helper()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	doc, err := readVaultSlotFile(f.stage)
	if err != nil {
		t.Fatal(err)
	}
	_, journal, err := readLegacyRetirementJournal(context.Background(), owner, doc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestVaultMigrationBrowserRetirementResumesPartialAndUnacknowledgedRemoval(t *testing.T) {
	for _, partial := range []bool{true, false} {
		t.Run(map[bool]string{true: "partial", false: "removed"}[partial], func(t *testing.T) {
			f := newBrowserRetirementFixture(t)
			ctx := context.Background()
			calls := 0
			_, err := f.retire(ctx, func(root *os.Root, name string) error {
				calls++
				if name != f.inventory.Profiles[0].Name || requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
					t.Fatal("wrong deletion scope or missing quarantine")
				}
				if partial {
					if err := root.Remove(filepath.Join(name, "Cookies")); err != nil {
						t.Fatal(err)
					}
				} else if err := root.RemoveAll(name); err != nil {
					t.Fatal(err)
				}
				return errors.New("uncertain native deletion")
			})
			if err == nil || calls != 1 {
				t.Fatal(calls, err)
			}
			journal := readBrowserRetirementJournal(t, f)
			if journal.Version != 4 || journal.Browser == nil || journal.Browser.Pending == nil || *journal.Browser.Pending != 0 || journal.Browser.Completed != 0 {
				t.Fatal("lost browser intent")
			}
			if _, err := retireLegacyVaultFiles(ctx, f.source, f.root, f.stage, f.key); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("file-only entrypoint ignored browser intent", err)
			}
			if err := retireLegacyVaultSQL(ctx, f.source, f.stage, f.key); err != vault.ErrPolicy {
				t.Fatal("SQL ignored browser intent", err)
			}
			// Chromium's shared root file can update unrelated cosmetics on restart.
			// Its original exact bytes remain encrypted in the archive; it is not a
			// deletion target and must not make pending profile retirement unusable.
			if err := os.WriteFile(filepath.Join(f.root, "Local State"), []byte("updated non-retired shared state"), 0600); err != nil {
				t.Fatal(err)
			}
			progress, err := f.retire(ctx)
			if err != nil || progress.BrowserProfiles != 3 {
				t.Fatal(progress, err)
			}
			if _, err := f.retire(ctx, func(*os.Root, string) error { t.Fatal("completed profile removal repeated"); return nil }); err != nil {
				t.Fatal(err)
			}
			journal = readBrowserRetirementJournal(t, f)
			if journal.Version != 4 || journal.Browser.Completed != 3 || journal.Browser.Pending != nil || journal.SQL != nil {
				t.Fatal("invalid completed browser state")
			}
			f.db.Close()
			if err := retireLegacyVaultSQL(ctx, f.source, f.stage, f.key); err != nil {
				t.Fatal(err)
			}
			if err := retireLegacyVaultSQL(ctx, f.source, f.stage, f.key); err != nil {
				t.Fatal("SQL retry failed", err)
			}
			journal = readBrowserRetirementJournal(t, f)
			if journal.Version != 4 || journal.SQL == nil || journal.SQL.Phase != "compacted" {
				t.Fatal("SQL lost browser completion")
			}
			if _, err := f.retire(ctx); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("earlier phase resumed after SQL", err)
			}
			if value, err := os.ReadFile(filepath.Join(f.root, "Partitions", "unrelated-web", "Cookies")); err != nil || string(value) != "ordinary-web-cookie-outside-scope" {
				t.Fatal("ordinary browser profile changed", err)
			}
			owner := openNativeMigrationStage(t, f.stage, f.key)
			defer owner.Close()
			if err := owner.WithLocalState(ctx, migrationBrowserFileKind, f.inventory.RootState.ScopeID, 1, equalLegacyVaultValue([]byte("native root state with protected Chromium key"))); err != nil {
				t.Fatal("original root state lost", err)
			}
		})
	}
}

func TestVaultMigrationBrowserRetirementRejectsChangedOrUnarchivedSources(t *testing.T) {
	for _, mutation := range []string{"new-file", "changed-file", "new-profile", "missing-file", "missing-profile", "archive", "deleted-archive", "native-root", "database", "unacknowledged"} {
		t.Run(mutation, func(t *testing.T) {
			f := newBrowserRetirementFixture(t)
			ctx := context.Background()
			if _, err := f.retire(ctx, func(*os.Root, string) error { return errors.New("stop after intent") }); err == nil {
				t.Fatal("failed to stop")
			}
			first := f.inventory.Profiles[0]
			switch mutation {
			case "new-file":
				if err := os.WriteFile(filepath.Join(f.root, "Partitions", first.Name, "new-token"), []byte("not archived"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-file":
				if err := os.WriteFile(filepath.Join(f.root, "Partitions", first.Name, "Cookies"), []byte("changed cookie"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-profile":
				if err := os.Mkdir(filepath.Join(f.root, "Partitions", "wormhole-web-ext-1111111111111111"), 0700); err != nil {
					t.Fatal(err)
				}
			case "missing-file", "missing-profile":
				// A pending first profile may be a subset, but an unstarted second
				// profile must still match the complete archived source.
				second := f.inventory.Profiles[1]
				if mutation == "missing-file" {
					if err := os.Remove(filepath.Join(f.root, "Partitions", second.Name, filepath.FromSlash(second.Files[0].Path))); err != nil {
						t.Fatal(err)
					}
				} else {
					root, err := openLegacyBrowserRoot(filepath.Join(f.root, "Partitions"))
					if err != nil {
						t.Fatal(err)
					}
					if err := root.RemoveAll(second.Name); err != nil {
						t.Fatal(err)
					}
					root.Close()
				}
			case "archive", "deleted-archive":
				owner := openNativeMigrationStage(t, f.stage, f.key)
				file := first.Files[0]
				var err error
				if mutation == "archive" {
					_, err = owner.PutLocalState(ctx, migrationBrowserFileKind, file.ScopeID, []byte("modified archive"), 1)
				} else {
					_, err = owner.DeleteLocalState(ctx, migrationBrowserFileKind, file.ScopeID, 1)
				}
				if err != nil {
					t.Fatal(err)
				}
				owner.Close()
			case "native-root":
				f.root = t.TempDir()
			case "database":
				legacyVaultSQL(t, f.db, "UPDATE Nodes SET Notes='changed after browser intent'")
			}
			calls := 0
			_, err := f.retire(ctx, func(*os.Root, string) error { calls++; return nil })
			if err == nil || mutation != "unacknowledged" && calls != 0 || mutation == "unacknowledged" && calls != 1 {
				t.Fatal("changed source or false acknowledgement accepted", calls, err)
			}
			if requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
				t.Fatal("quarantine lifted after failed deletion")
			}
		})
	}
}

func TestVaultMigrationBrowserRetirementCancellationAndNewSourceAfterDelete(t *testing.T) {
	for _, scenario := range []string{"cancel", "new-profile"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBrowserRetirementFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err := f.retire(ctx, func(root *os.Root, name string) error {
				if err := root.RemoveAll(name); err != nil {
					return err
				}
				if scenario == "cancel" {
					cancel()
				} else if err := root.Mkdir("wormhole-web-ext-1111111111111111", 0700); err != nil && !errors.Is(err, os.ErrExist) {
					return err
				}
				return nil
			})
			if err == nil {
				t.Fatal("cancelled or newly populated source acknowledged")
			}
			if scenario == "cancel" {
				if journal := readBrowserRetirementJournal(t, f); journal.Browser.Pending == nil {
					t.Fatal("cancelled delete lost intent")
				}
				if _, err := f.retire(context.Background()); err != nil {
					t.Fatal("cancelled deletion could not resume", err)
				}
			} else {
				f.db.Close()
				if err := retireLegacyVaultSQL(context.Background(), f.source, f.stage, f.key); err == nil {
					t.Fatal("SQL ignored a new browser source")
				}
			}
		})
	}
}

func TestVaultMigrationBrowserEmptyProofAndSQLReappearance(t *testing.T) {
	db, source, document, key, plan, _ := migrationStageFixture(t)
	root := t.TempDir()
	stage, err := stageLegacyVaultDomains(context.Background(), source, root, document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	if progress, err := retireLegacyVaultSources(context.Background(), source, root, stage.Path, key); err != nil || progress.BrowserProfiles != 0 {
		t.Fatal(progress, err)
	}
	db.Close()
	if err := retireLegacyVaultSQL(context.Background(), source, stage.Path, key); err != nil {
		t.Fatal("empty native browser proof failed", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "Partitions", "wormhole-tunnel-auth-azure"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyVaultSQL(context.Background(), source, stage.Path, key); err != vault.ErrAuthentication {
		t.Fatal("compacted migration ignored a revived browser source", err)
	}
}

func TestVaultMigrationBrowserJournalAndNativeBoundaryValidation(t *testing.T) {
	f := newBrowserRetirementFixture(t)
	ctx := context.Background()
	if _, err := f.retire(ctx, func(*os.Root, string) error { return errors.New("intent") }); err == nil {
		t.Fatal("failed to stop")
	}
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	doc, _ := readVaultSlotFile(f.stage)
	state, journal, err := readLegacyRetirementJournal(ctx, owner, doc, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"version", "missing-browser", "negative", "too-many", "pending-negative", "pending-future", "pending-overflow", "sql-with-pending", "file-pending"} {
		next := journal
		browser := *journal.Browser
		next.Browser = &browser
		pending := *journal.Browser.Pending
		next.Browser.Pending = &pending
		switch mutation {
		case "version":
			next.Version = 2
		case "missing-browser":
			next.Browser = nil
		case "negative":
			next.Browser.Completed = -1
		case "too-many":
			next.Browser.Completed = maxMigrationBrowserProfiles + 1
		case "pending-negative":
			*next.Browser.Pending = -1
		case "pending-future":
			*next.Browser.Pending = 1
		case "pending-overflow":
			next.Browser.Completed = maxMigrationBrowserProfiles
			*next.Browser.Pending = maxMigrationBrowserProfiles
		case "sql-with-pending":
			next.SQL = &legacyRetirementSQL{Phase: "pending", Authentication: bytes.Repeat([]byte{1}, 32)}
		case "file-pending":
			next.Pending = &legacyRetirementFile{Index: 0, Protected: []byte("not a file cursor")}
		}
		state, err = writeLegacyRetirementJournal(ctx, owner, doc.VaultID, next, state.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := readLegacyRetirementJournal(ctx, owner, doc, 0, 0); err != vault.ErrFormat {
			t.Fatal("malformed browser journal accepted", mutation, err)
		}
	}
	if err := verifyLegacyBrowserSourcesAbsent(ctx, nil, f.key); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	if err := verifyLegacyBrowserSourcesAbsentWithKey(ctx, nil, f.key); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if err := verifyLegacyBrowserSourcesAbsent(ctx, f.inventory, nil); err == nil {
		t.Fatal("missing root key accepted")
	}
	if err := verifyLegacyBrowserPartitionRoot(nil, f.root); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if err := retireLegacyBrowserProfiles(ctx, nil, f.key, owner, &state, &journal, func(*os.Root, string) error { return nil }); err != vault.ErrPolicy {
		t.Fatal(err)
	}
}

func TestVaultMigrationBrowserRetirementLateLinkCannotEscapeNativeRoot(t *testing.T) {
	f := newBrowserRetirementFixture(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "must-remain")
	if err := os.WriteFile(secret, []byte("outside scoped browser root"), 0600); err != nil {
		t.Fatal(err)
	}
	injected := false
	_, err := f.retire(context.Background(), func(root *os.Root, name string) error {
		if !injected {
			if err := os.Symlink(outside, filepath.Join(root.Name(), name, "late-link")); err != nil {
				t.Skip("native symlink creation unavailable")
			}
			injected = true
		}
		return root.RemoveAll(name)
	})
	if err != nil || !injected {
		t.Fatal("scoped retirement failed", err)
	}
	value, err := os.ReadFile(secret)
	if err != nil || string(value) != "outside scoped browser root" {
		t.Fatal("recursive deletion escaped its native root", err)
	}
}

func TestVaultMigrationBrowserRetirementCannotAcknowledgeReplacedParent(t *testing.T) {
	f := newBrowserRetirementFixture(t)
	_, err := f.retire(context.Background(), func(root *os.Root, name string) error {
		if err := root.RemoveAll(name); err != nil {
			return err
		}
		if err := os.Rename(root.Name(), root.Name()+".moved"); err != nil {
			t.Skip("native open-root rename unavailable")
		}
		if err := os.Mkdir(root.Name(), 0700); err != nil {
			return err
		}
		return nil
	})
	if !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("replacement parent acknowledged native removal", err)
	}
	if journal := readBrowserRetirementJournal(t, f); journal.Browser.Pending == nil || journal.Browser.Completed != 0 {
		t.Fatal("replacement lost pending proof")
	}
}
