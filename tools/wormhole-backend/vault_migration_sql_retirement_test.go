package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func newRetirementSQLFixture(t *testing.T) *retirementKeysFixture {
	t.Helper()
	f := newRetirementKeysFixture(t)
	if _, err := f.retire(context.Background(), f.store); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func readSQLRetirement(t *testing.T, f *retirementKeysFixture) legacyRetirementJournal {
	t.Helper()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	document, err := readVaultSlotFile(f.stage)
	if err != nil {
		t.Fatal(err)
	}
	_, journal, err := readLegacyRetirementJournal(context.Background(), owner, document, len(f.files), len(f.rows))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestVaultMigrationSQLRetirementResumesEveryCheckpoint(t *testing.T) {
	ctx := context.Background()
	for _, stopped := range []string{"intent", "deleted", "commit", "committed", "vacuumed", "complete"} {
		t.Run(stopped, func(t *testing.T) {
			f := newRetirementSQLFixture(t)
			stop := errors.New("simulated process interruption")
			err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, func(step string) error {
				if requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
					t.Fatal("source quarantine lifted")
				}
				if step == stopped {
					return stop
				}
				return nil
			})
			if stopped == "complete" && err != nil || stopped != "complete" && !errors.Is(err, stop) {
				t.Fatal("wrong interruption", err)
			}
			journal := readSQLRetirement(t, f)
			if journal.Version != 3 || journal.SQL == nil {
				t.Fatal("lost durable SQL intent")
			}
			db, err := openLegacyMigrationSource(f.source)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM CredentialSecrets").Scan(&count); err != nil {
				t.Fatal(err)
			}
			db.Close()
			want := 0
			if stopped == "intent" || stopped == "deleted" {
				want = 2
			}
			if count != want {
				t.Fatal("uncertain SQL state", count, want)
			}
			for retry := 0; retry < 2; retry++ {
				var checkpoint func(string) error
				if retry == 1 {
					checkpoint = func(string) error { t.Fatal("completed retirement repeated"); return nil }
				}
				if err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, checkpoint); err != nil {
					t.Fatal("resume failed", err)
				}
			}
			journal = readSQLRetirement(t, f)
			if journal.SQL.Phase != "compacted" {
				t.Fatal("unfinished compaction")
			}
			raw, err := os.ReadFile(f.source)
			if err != nil || !bytes.Contains(raw, []byte("private stage note")) {
				t.Fatal("unrelated metadata removed", err)
			}
			for _, row := range f.rows {
				if bytes.Contains(raw, []byte(row.Reference)) {
					t.Fatal("retired SQL reference remains in main file")
				}
			}
			for _, suffix := range []string{"-journal", "-wal", "-shm"} {
				if _, err := os.Lstat(f.source + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("SQL sidecar survived", suffix, err)
				}
			}
			if _, err := f.retire(ctx, f.store); !errors.Is(err, vault.ErrPolicy) {
				t.Fatal("old phase resumed after SQL retirement", err)
			}
			if requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
				t.Fatal("SQL retirement published workspace")
			}
		})
	}
}

func TestVaultMigrationSQLRetirementWithoutSecretRows(t *testing.T) {
	f := newRetirementFixture(t)
	ctx := context.Background()
	if _, err := retireLegacyVaultSourcesWith(ctx, f.source, "", f.stage, f.key, func(string, []byte) error { return nil }, openMigrationCredentialStore); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := retireLegacyVaultSQL(ctx, f.source, f.stage, f.key); err != nil {
		t.Fatal("native continuation without OS key references failed", err)
	}
}

func TestVaultMigrationRetirementInventoryRejectsInvalidArchives(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx := context.Background()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	doc, _ := readVaultSlotFile(f.stage)
	inventory, _, _, err := readLegacyRetirementInventory(ctx, owner, doc, f.source)
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.ReadLocalState(ctx, migrationSourceInventoryKind, doc.VaultID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"malformed", "noncanonical", "source", "file-order"} {
		next := inventory
		if scenario == "source" {
			next.Source += ".changed"
		}
		if scenario == "file-order" {
			next.Files = append([]legacyInventoryFile(nil), inventory.Files...)
			next.Files[0], next.Files[1] = next.Files[1], next.Files[0]
		}
		raw, _ := json.Marshal(next)
		if scenario == "malformed" {
			raw = []byte("{")
		}
		if scenario == "noncanonical" {
			raw = append(raw, '\n')
		}
		state, err = owner.PutLocalState(ctx, migrationSourceInventoryKind, doc.VaultID, raw, state.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := readLegacyRetirementInventory(ctx, owner, doc, f.source); err != vault.ErrFormat {
			t.Fatal(scenario, err)
		}
	}
}

func TestVaultMigrationSQLPredictedCheckpoint(t *testing.T) {
	db, _ := snapshotDatabase(t)
	legacyVaultSecrets(t, db)
	legacyVaultSQL(t, db, `INSERT INTO CredentialSecrets VALUES('id', x'736563726574', 'encoding', 'date')`)
	reader := resolverCaptureReader{context.Background(), db}
	key := bytes.Repeat([]byte{8}, 32)
	expected, err := captureLegacyDatabaseRetirementState(reader, key, true)
	if err != nil {
		t.Fatal(err)
	}
	original, err := captureLegacyDatabaseState(reader, key)
	if err != nil || bytes.Equal(expected, original) {
		t.Fatal("prediction omitted no rows", err)
	}
	legacyVaultSQL(t, db, "DELETE FROM CredentialSecrets")
	actual, err := captureLegacyDatabaseState(reader, key)
	if err != nil || !bytes.Equal(expected, actual) {
		t.Fatal("prediction differs from actual deletion", err)
	}
	legacyVaultSQL(t, db, "CREATE TABLE unrelated(value)")
	actual, err = captureLegacyDatabaseState(reader, key)
	if err != nil || bytes.Equal(expected, actual) {
		t.Fatal("prediction permits unrelated changes", err)
	}
}

func TestVaultMigrationSQLRetirementRejectsChangedState(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{"source", "resumed-source", "file", "new-file", "guard", "archive", "key", "pending-files", "version-one", "phase", "stage-path", "wrong-key", "source-lock", "stage-lock", "sql-pending-mac"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRetirementSQLFixture(t)
			stage, key := f.stage, f.key
			if mutation == "resumed-source" || mutation == "sql-pending-mac" {
				if err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, func(string) error { return errors.New("stop") }); err == nil {
					t.Fatal("failed to stop at durable intent")
				}
			}
			switch mutation {
			case "source", "resumed-source":
				db, _ := openLegacyMigrationSource(f.source)
				legacyVaultSQL(t, db, "UPDATE Nodes SET Notes='changed'")
				db.Close()
			case "file", "new-file":
				path := f.files[0].path
				if mutation == "new-file" {
					path = bitwardenBrowserStoragePath(f.source)
				}
				writeLegacyStateFixture(t, path, []byte("unexpected protected file"))
			case "guard":
				if err := os.Remove(f.source + ".slots"); err != nil {
					t.Fatal(err)
				}
			case "key":
				f.values[f.rows[0].Reference] = []byte("reappeared credential")
			case "archive":
				owner := openNativeMigrationStage(t, f.stage, f.key)
				if _, err := owner.DeleteLocalState(ctx, "legacy-secret", strings.ToLower(f.rows[0].ID), 1); err != nil {
					t.Fatal(err)
				}
				owner.Close()
			case "pending-files", "version-one", "sql-pending-mac":
				owner := openNativeMigrationStage(t, f.stage, f.key)
				doc, _ := readVaultSlotFile(f.stage)
				state, journal, err := readLegacyRetirementJournal(ctx, owner, doc, len(f.files), len(f.rows))
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "pending-files":
					journal.Pending = &legacyRetirementFile{Index: 0, Protected: []byte("still pending")}
				case "version-one":
					journal.Version, journal.KeysCompleted = 1, 0
				case "sql-pending-mac":
					journal.SQL.Authentication[0]++
				}
				if _, err := writeLegacyRetirementJournal(ctx, owner, doc.VaultID, journal, state.RowVersion); err != nil {
					t.Fatal(err)
				}
				owner.Close()
			case "phase":
				doc, _ := readVaultSlotFile(f.stage)
				doc.Migration.Phase = vault.MigrationCopying
				doc.Migration.Snapshot = nil
				raw, err := vault.EncodeSlotFile(f.key, doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.stage+".slots", raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "stage-path":
				stage = f.source
			case "wrong-key":
				key = bytes.Repeat([]byte{9}, 32)
			case "source-lock", "stage-lock":
				path := f.source + ".vault-migration.lock"
				if mutation == "stage-lock" {
					path = f.stage + ".vault.lock"
				}
				release, err := tryAcquireExclusiveFileLock(path)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			runCtx := ctx
			if mutation == "source-lock" {
				bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
				defer cancel()
				runCtx = bounded
			}
			if err := retireLegacyVaultSQLWith(runCtx, f.source, stage, key, f.store, nil); err == nil {
				t.Fatal("changed or incomplete state accepted")
			}
			db, _ := openLegacyMigrationSource(f.source)
			defer db.Close()
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM CredentialSecrets").Scan(&count); err != nil || count != 2 {
				t.Fatal("failed phase deleted source rows", count, err)
			}
		})
	}
}

func TestVaultMigrationSQLJournalValidation(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx := context.Background()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	doc, _ := readVaultSlotFile(f.stage)
	state, journal, err := readLegacyRetirementJournal(ctx, owner, doc, len(f.files), len(f.rows))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"old-version", "missing-state", "phase", "digest", "files", "keys", "pending"} {
		next := journal
		next.Version, next.SQL = 3, &legacyRetirementSQL{Phase: "pending", Authentication: make([]byte, 32)}
		switch mutation {
		case "old-version":
			next.Version = 2
		case "missing-state":
			next.SQL = nil
		case "phase":
			next.SQL.Phase = "published"
		case "digest":
			next.SQL.Authentication = nil
		case "files":
			next.Completed--
		case "keys":
			next.KeysCompleted--
		case "pending":
			next.PendingKey = new(int)
		}
		state, err = writeLegacyRetirementJournal(ctx, owner, doc.VaultID, next, state.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := readLegacyRetirementJournal(ctx, owner, doc, len(f.files), len(f.rows)); err != vault.ErrFormat {
			t.Fatal(mutation, err)
		}
	}
}

func TestVaultMigrationSQLKeyAbsence(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx := context.Background()
	if err := verifyLegacySQLKeyAbsence(ctx, f.rows, nil); err != vault.ErrPolicy {
		t.Fatal(err)
	}
	for _, mode := range []string{"factory-error", "missing-load", "missing-close", "load-error", "present", "absent-with-value", "absent"} {
		t.Run(mode, func(t *testing.T) {
			closed := 0
			value := []byte("owned plaintext")
			err := verifyLegacySQLKeyAbsence(ctx, f.rows[:1], func(context.Context, legacyInventoryRow, int) (migrationCredentialStore, error) {
				store := migrationCredentialStore{Close: func() { closed++ }, Load: func(context.Context) ([]byte, bool, error) {
					switch mode {
					case "load-error":
						return value, false, errors.New("locked")
					case "present":
						return value, true, nil
					case "absent-with-value":
						return value, false, nil
					default:
						return nil, false, nil
					}
				}}
				switch mode {
				case "factory-error":
					return store, errors.New("unavailable")
				case "missing-load":
					store.Load = nil
				case "missing-close":
					store.Close = nil
				}
				return store, nil
			})
			if (err == nil) != (mode == "absent") || mode != "missing-close" && closed != 1 {
				t.Fatal(mode, closed, err)
			}
			if strings.Contains(mode, "value") || mode == "present" || mode == "load-error" {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("borrowed keychain value retained")
				}
			}
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := verifyLegacySQLKeyAbsence(cancelled, f.rows, f.store); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestVaultMigrationSQLCancellationAfterCommit(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, func(step string) error {
		if step == "commit" {
			cancel()
		}
		return nil
	})
	if err == nil || ctx.Err() != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
	if err := retireLegacyVaultSQLWith(context.Background(), f.source, f.stage, f.key, f.store, nil); err != nil {
		t.Fatal("cancelled commit could not resume", err)
	}
}

func TestVaultMigrationSQLRefusesBusySourceAndUnsafeSidecars(t *testing.T) {
	for _, scenario := range []string{"writer", "-journal", "-wal", "-shm"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRetirementSQLFixture(t)
			if scenario == "writer" {
				db, err := openLegacyMigrationSource(f.source)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				legacyVaultSQL(t, db, "BEGIN IMMEDIATE")
				defer db.Exec("ROLLBACK")
			} else if err := os.Mkdir(f.source+scenario, 0700); err != nil {
				t.Fatal(err)
			}
			if err := retireLegacyVaultSQLWith(context.Background(), f.source, f.stage, f.key, f.store, nil); err == nil {
				t.Fatal("busy or unsafe source accepted")
			}
			if journal := readSQLRetirement(t, f); journal.SQL != nil {
				t.Fatal("failed source admission persisted SQL intent")
			}
		})
	}
}

func TestVaultMigrationSQLCompactedSourceCannotRevert(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx := context.Background()
	if err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, nil); err != nil {
		t.Fatal(err)
	}
	db, err := openLegacyMigrationSource(f.source)
	if err != nil {
		t.Fatal(err)
	}
	legacyVaultSQL(t, db, "INSERT INTO CredentialSecrets VALUES(?,?,?,'original-time')", f.rows[0].ID, f.rows[0].Reference, f.rows[0].Encoding)
	db.Close()
	if err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, nil); err != vault.ErrAuthentication {
		t.Fatal("compacted source rollback accepted", err)
	}
}

// The frozen source digest includes a trigger. A DELETE that copies a retired
// secret elsewhere must be rolled back even though the target table is empty.
func TestVaultMigrationSQLRejectsDeleteSideEffects(t *testing.T) {
	f := newRetirementSQLFixture(t)
	ctx := context.Background()
	db, _ := openLegacyMigrationSource(f.source)
	legacyVaultSQL(t, db, "CREATE TABLE leaked(Secret TEXT)")
	legacyVaultSQL(t, db, "CREATE TRIGGER leak_secret AFTER DELETE ON CredentialSecrets BEGIN INSERT INTO leaked VALUES(old.Secret); END")
	subkey, err := vault.DeriveKey(f.key, []byte(f.document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(subkey)
	digest, err := captureLegacyDatabaseState(resolverCaptureReader{ctx, db}, subkey)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	var inventory legacySourceInventory
	state, err := owner.ReadLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.WithLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, state.RowVersion, func(raw []byte) error { return json.Unmarshal(raw, &inventory) }); err != nil {
		t.Fatal(err)
	}
	inventory.DatabaseMAC = digest
	raw, _ := json.Marshal(inventory)
	if _, err := owner.PutLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, raw, state.RowVersion); err != nil {
		t.Fatal(err)
	}
	owner.Close()
	if err := retireLegacyVaultSQLWith(ctx, f.source, f.stage, f.key, f.store, nil); err != vault.ErrAuthentication {
		t.Fatal("DELETE side effects accepted", err)
	}
	db, _ = openLegacyMigrationSource(f.source)
	defer db.Close()
	var count, leaked int
	if db.QueryRow("SELECT COUNT(*) FROM CredentialSecrets").Scan(&count) != nil || db.QueryRow("SELECT COUNT(*) FROM leaked").Scan(&leaked) != nil || count != 2 || leaked != 0 {
		t.Fatal("failed SQL mutation escaped rollback", count, leaked)
	}
}
