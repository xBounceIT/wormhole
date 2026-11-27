package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type retirementFixture struct {
	db            *sql.DB
	source, stage string
	document      vault.SlotFile
	key           []byte
	files         []legacyLocalStateFile
}

// Portable synthetic protected-file fixture. The production stage copies and
// authenticates real native files in the existing platform-specific tests.
// Here native owner APIs persist both file archives and the matching inventory,
// then seal the closed database exactly as the production staging path does.
func newRetirementFixture(t *testing.T) retirementFixture {
	t.Helper()
	db, source, document, key, plan, _ := migrationStageFixture(t)
	stage, err := stageLegacyVaultDomains(context.Background(), source, "", document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	files := []legacyLocalStateFile{legacyLocalStateFiles(source, document.VaultID)[0]}
	directory := legacyLocalStateDirectories(source, document.VaultID)[0]
	scope := uuid.NewString()
	files = append(files, legacyLocalStateFile{path: filepath.Join(directory.path, strings.ReplaceAll(scope, "-", "")+directory.suffix), kind: directory.kind, scope: scope, maximum: directory.maximum})
	// Sort exactly as the source inventory: azure-refresh precedes bitwarden-cli.
	files[0], files[1] = files[1], files[0]
	for _, file := range files {
		writeLegacyStateFixture(t, file.path, []byte("synthetic-protected-file-"+file.kind))
		if _, err := owner.PutLocalState(context.Background(), file.kind, file.scope, []byte("archived-native-plaintext"), 0); err != nil {
			t.Fatal(err)
		}
	}
	reader := resolverCaptureReader{context.Background(), db}
	raw, err := captureLegacySourceInventory(reader, source, "", document.VaultID, key, migrationSecretReader(reader.ctx, backendMaxTunnelRequestBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.PutLocalState(context.Background(), migrationSourceInventoryKind, document.VaultID, raw, 1); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	document, err = readVaultSlotFile(stage.Path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := vaultMigrationDatabaseDigest(context.Background(), stage.Path, document, key, true)
	if err != nil {
		t.Fatal(err)
	}
	document.Sequence++
	document.Migration.Snapshot = digest
	if err := writeVaultSlotFile(stage.Path, key, document, document.Sequence-1); err != nil {
		t.Fatal(err)
	}
	return retirementFixture{db, source, stage.Path, document, key, files}
}

func (f retirementFixture) run(ctx context.Context, retire func(string, []byte) error) (int, error) {
	return retireLegacyVaultFilesWith(ctx, f.source, "", f.stage, f.key, retire)
}

func TestVaultMigrationRetirementFilesResumeAndQuarantine(t *testing.T) {
	f := newRetirementFixture(t)
	ctx := context.Background()
	called := 0
	stop := errors.New("injected uncertain key deletion")
	_, err := f.run(ctx, func(path string, protected []byte) error {
		called++
		if path != f.files[0].path || !bytes.Equal(protected, []byte("synthetic-protected-file-azure-refresh")) {
			t.Fatal("wrong retirement authority")
		}
		if requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
			t.Fatal("source not quarantined before deletion")
		}
		// Simulate a process interruption after the external operation completed
		// but before its acknowledgement/progress could be persisted.
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		return stop
	})
	if !errors.Is(err, errVaultMigrationSource) || called != 1 {
		t.Fatal(called, err)
	}
	owner := openNativeMigrationStage(t, f.stage, f.key)
	doc, _ := readVaultSlotFile(f.stage)
	state, journal, err := readLegacyRetirementJournal(ctx, owner, doc, len(f.files), 0)
	if err != nil || journal.Completed != 0 || journal.Pending == nil || len(journal.Pending.Protected) == 0 {
		t.Fatal("lost durable intent", err)
	}
	if state.RowVersion != 2 {
		t.Fatal("intent did not advance journal")
	}
	vault.Wipe(journal.Pending.Protected)
	if _, err := owner.PutLocalState(ctx, migrationRetirementKind, uuid.NewString(), []byte("cross-workspace"), 0); err != vault.ErrFormat {
		t.Fatal("wrong scope accepted", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	called = 0
	stored, err := os.ReadFile(f.stage)
	if err != nil || bytes.Contains(stored, []byte("synthetic-protected-file")) || bytes.Contains(stored, []byte("archived-native-plaintext")) {
		t.Fatal("journal/archives persisted without vault encryption", err)
	}
	count, err := f.run(ctx, func(path string, protected []byte) error {
		called++
		if len(protected) == 0 {
			t.Fatal("retry lost protected source")
		}
		return nil
	})
	if err != nil || count != 2 || called != 2 {
		t.Fatal(count, called, err)
	}
	for _, file := range f.files {
		if _, err := os.Lstat(file.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("original survived", err)
		}
	}
	if count, err := f.run(ctx, func(string, []byte) error { t.Fatal("completed deletion repeated"); return nil }); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	// Completed artifacts reappearing after an uncertain filesystem outcome are
	// removed only if they still match the authenticated original ciphertext.
	writeLegacyStateFixture(t, f.files[0].path, []byte("synthetic-protected-file-azure-refresh"))
	if count, err := f.run(ctx, func(string, []byte) error { return nil }); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if _, _, err := canonicalLegacyVaultSource(f.source); err == nil {
		t.Fatal("legacy source re-enabled")
	}
	if _, err := os.Lstat(f.source); err != nil {
		t.Fatal("SQL source prematurely removed", err)
	}
	owner = openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	for _, file := range f.files {
		if err := owner.WithLocalState(ctx, file.kind, file.scope, 1, equalLegacyVaultValue([]byte("archived-native-plaintext"))); err != nil {
			t.Fatal("lost archive", err)
		}
	}
	_, journal, err = readLegacyRetirementJournal(ctx, owner, doc, 2, 0)
	if err != nil || journal.Pending != nil || journal.Completed != 2 {
		t.Fatal("completion not persisted", err)
	}
}

func TestVaultMigrationRetirementReappearingFileWithLaterIntent(t *testing.T) {
	f := newRetirementFixture(t)
	calls := 0
	_, err := f.run(context.Background(), func(string, []byte) error {
		calls++
		if calls == 2 {
			return errors.New("interrupt second file")
		}
		return nil
	})
	if err == nil || calls != 2 {
		t.Fatal("fixture did not reach second intent", err)
	}
	writeLegacyStateFixture(t, f.files[0].path, []byte("synthetic-protected-file-azure-refresh"))
	var paths []string
	count, err := f.run(context.Background(), func(path string, _ []byte) error { paths = append(paths, path); return nil })
	if err != nil || count != 2 || len(paths) != 2 || paths[0] != f.files[1].path || paths[1] != f.files[0].path {
		t.Fatal("pending intent lost or earlier artifact stranded", count, paths, err)
	}
}

func TestVaultMigrationRetirementCancellationAfterIntent(t *testing.T) {
	f := newRetirementFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := f.run(ctx, func(string, []byte) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, file := range f.files {
		if _, err := os.Lstat(file.path); err != nil {
			t.Fatal("cancelled file deleted", err)
		}
	}
	if _, err := f.run(context.Background(), func(string, []byte) error { return nil }); err != nil {
		t.Fatal("could not resume", err)
	}
}

func TestVaultMigrationRetirementRejectsDriftAndMissingGuard(t *testing.T) {
	for _, mutation := range []string{"sql", "file", "extra", "missing", "guard", "stage", "archive"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRetirementFixture(t)
			ctx := context.Background()
			// Persist an intent without modifying an external source.
			if _, err := f.run(ctx, func(string, []byte) error { return errors.New("pause") }); !errors.Is(err, errVaultMigrationSource) {
				t.Fatal(err)
			}
			switch mutation {
			case "sql":
				legacyVaultSQL(t, f.db, `UPDATE Nodes SET Notes='new unarchived notes'`)
			case "file":
				writeLegacyStateFixture(t, f.files[0].path, []byte("replacement"))
			case "extra":
				writeLegacyStateFixture(t, bitwardenBrowserStoragePath(f.source), []byte("new source"))
			case "missing":
				if err := os.Remove(f.files[1].path); err != nil {
					t.Fatal(err)
				}
			case "guard":
				if err := os.Remove(vaultSlotPath(f.source)); err != nil {
					t.Fatal(err)
				}
				if requireLegacyWorkspace(f.source) != errVaultOwnerRequired {
					t.Fatal("lost guard restored legacy access")
				}
			case "stage":
				if err := os.WriteFile(vaultSlotPath(f.stage), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "archive":
				owner := openNativeMigrationStage(t, f.stage, f.key)
				if _, err := owner.DeleteLocalState(ctx, f.files[0].kind, f.files[0].scope, 1); err != nil {
					t.Fatal(err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			_, err := f.run(ctx, func(string, []byte) error { calls++; return nil })
			if err == nil {
				t.Fatal("drift accepted")
			}
			// A missing later source can be discovered after resuming an earlier
			// valid intent; every removed artifact is independently verified.
			if mutation != "missing" && calls != 0 {
				t.Fatal("invalid source reached key retirement")
			}
		})
	}
}

func TestVaultMigrationRetirementAdmissionsAndMarkerRules(t *testing.T) {
	f := newRetirementFixture(t)
	ctx := context.Background()
	for _, input := range []struct {
		source, stage string
		key           []byte
	}{
		{"relative", f.stage, f.key}, {f.source, "missing", f.key}, {f.source, f.stage, make([]byte, 32)},
	} {
		if _, err := retireLegacyVaultFiles(ctx, input.source, "", input.stage, input.key); err == nil {
			t.Fatal("invalid admission")
		}
	}
	if _, err := f.run(ctx, nil); err == nil {
		t.Fatal("nil retire operation")
	}
	release, err := acquireWorkspaceOwnership(f.source, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retireLegacyVaultFiles(ctx, f.source, "", f.stage, f.key); err != errWorkspaceInUse {
		t.Fatal(err)
	}
	release()
	release, err = tryAcquireExclusiveFileLock(f.stage + ".vault.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retireLegacyVaultFiles(ctx, f.source, "", f.stage, f.key); err != errVaultSlotConflict {
		t.Fatal(err)
	}
	release()
	if _, err := f.run(ctx, func(string, []byte) error { return errors.New("stop") }); err == nil {
		t.Fatal("fixture did not stop")
	}
	document, err := readVaultSlotFile(f.stage)
	if err != nil {
		t.Fatal(err)
	}
	missingProof := document
	marker := *document.Migration
	missingProof.Migration = &marker
	missingProof.Migration.Snapshot = nil
	if _, err := vault.EncodeSlotFile(f.key, missingProof); err != vault.ErrFormat {
		t.Fatal("retirement without initial checkpoint proof accepted", err)
	}
	for _, phase := range []string{vault.MigrationCopying, vault.MigrationDomainsCopied} {
		next := document
		migration := *document.Migration
		next.Migration = &migration
		next.Sequence++
		next.Migration.Phase = phase
		if err := writeVaultSlotFile(f.stage, f.key, next, document.Sequence); err != vault.ErrPolicy {
			t.Fatal("retirement regressed", err)
		}
	}
	if _, err := prepareLegacyVaultStage(f.stage, f.key, f.document, document.Migration.Binding); err != vault.ErrPolicy {
		t.Fatal("retirement stage rebuilt", err)
	}
	guard, err := readVaultSlotFile(f.source)
	if err != nil || !matchingRetirementGuard(f.key, guard, document) {
		t.Fatal("guard does not match", err)
	}
	guard.RootKeyVersion++
	if matchingRetirementGuard(f.key, guard, document) {
		t.Fatal("altered guard accepted")
	}
}

func TestVaultMigrationRetirementJournalValidationAndFileMapping(t *testing.T) {
	f := newRetirementFixture(t)
	ctx := context.Background()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	for _, file := range []legacyInventoryFile{
		{}, {Kind: "unknown", ScopeID: uuid.NewString(), Bytes: 1, Authentication: make([]byte, 32)},
		{Kind: "azure-refresh", ScopeID: "../escape", Bytes: 1, Authentication: make([]byte, 32)},
		{Kind: "bitwarden-cli", ScopeID: uuid.NewString(), Bytes: 1, Authentication: make([]byte, 32)},
		{Kind: "azure-refresh", ScopeID: uuid.NewString(), Bytes: 1 << 30, Authentication: make([]byte, 32)},
	} {
		if _, err := legacyRetirementFileSpec(f.source, f.document.VaultID, file); err == nil {
			t.Fatal("invalid file selector")
		}
	}
	var revision uint64
	for _, raw := range [][]byte{nil, []byte("bad"), append([]byte("WMR1"), 0xff, 0xff, 0xff, 0xff), append([]byte("WMR1\x00\x00\x00\x01"), 'x')} {
		state, err := owner.PutLocalState(ctx, migrationRetirementKind, f.document.VaultID, raw, revision)
		if err != nil {
			t.Fatal(err)
		}
		revision = state.RowVersion
		if _, _, err := readLegacyRetirementJournal(ctx, owner, f.document, 2, 0); err != vault.ErrFormat {
			t.Fatal("bad journal accepted", err)
		}
	}
	for _, journal := range []legacyRetirementJournal{
		{Version: 3, Binding: f.document.Migration.Binding},
		{Version: 1, Binding: "wrong"},
		{Version: 1, Binding: f.document.Migration.Binding, Completed: 3},
		{Version: 1, Binding: f.document.Migration.Binding, Pending: &legacyRetirementFile{Index: 1, Protected: []byte("data")}},
		{Version: 1, Binding: f.document.Migration.Binding, Pending: &legacyRetirementFile{Index: 0}},
	} {
		state, err := writeLegacyRetirementJournal(ctx, owner, f.document.VaultID, journal, revision)
		if err != nil {
			t.Fatal(err)
		}
		revision = state.RowVersion
		if _, _, err := readLegacyRetirementJournal(ctx, owner, f.document, 2, 0); err != vault.ErrFormat {
			t.Fatal("invalid journal accepted", err)
		}
	}
	// An extra protected payload without a pending operation is not resumable.
	header, _ := json.Marshal(legacyRetirementJournal{Version: 1, Binding: f.document.Migration.Binding})
	raw := make([]byte, 8+len(header)+1)
	copy(raw, "WMR1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	copy(raw[8:], header)
	if _, err := owner.PutLocalState(ctx, migrationRetirementKind, f.document.VaultID, raw, revision); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLegacyRetirementJournal(ctx, owner, f.document, 2, 0); err != vault.ErrFormat {
		t.Fatal("orphan payload accepted", err)
	}
}

func TestVaultMigrationFileKeyChecked(t *testing.T) {
	missing := errors.New("missing key")
	for _, scenario := range []string{"delete", "absent", "load-error", "wrong-key", "delete-error", "not-deleted", "verification-error"} {
		t.Run(scenario, func(t *testing.T) {
			key := bytes.Repeat([]byte{5}, 32)
			protected, err := encryptAuthDocument([]byte("archived-file-secret"), key)
			if err != nil {
				t.Fatal(err)
			}
			present, deleted := scenario != "absent", false
			var borrowed [][]byte
			load := func() ([]byte, error) {
				if scenario == "load-error" || (deleted && scenario == "verification-error") {
					return nil, errors.New("unavailable")
				}
				if !present {
					return nil, missing
				}
				value := bytes.Clone(key)
				if scenario == "wrong-key" {
					value[0]++
				}
				borrowed = append(borrowed, value)
				return value, nil
			}
			remove := func() error {
				deleted = true
				if scenario == "delete-error" {
					return errors.New("unavailable")
				}
				present = scenario == "not-deleted"
				return nil
			}
			err = retireLegacyFileKeyChecked(protected, load, remove, missing)
			if (err == nil) != (scenario == "delete" || scenario == "absent") {
				t.Fatal(err)
			}
			for _, value := range borrowed {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("key retained")
				}
			}
		})
	}
}

func TestVaultMigrationRetirementNativeProtectedFiles(t *testing.T) {
	_, source, document, key, plan, _ := migrationStageFixture(t)
	ctx := context.Background()
	primary := bitwardenBrowserStoragePath(source)
	if err := protectFile(bitwardenSessionPath(source), []byte("native archived token")); err != nil {
		t.Fatal(err)
	}
	if err := protectBitwardenBrowserStorage(primary, []byte("native archived token")); err != nil {
		t.Fatal(err)
	}
	protected, err := os.ReadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(primary+".bak", protected, 0600); err != nil {
		t.Fatal(err)
	}
	stage, err := stageLegacyVaultDomains(ctx, source, "", document, key, plan)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := retireLegacyVaultFiles(ctx, source, "", stage.Path, key); err != nil || count != 3 {
		t.Fatal(count, err)
	}
	if count, err := retireLegacyVaultFiles(ctx, source, "", stage.Path, key); err != nil || count != 3 {
		t.Fatal("native retry failed", count, err)
	}
	owner := openNativeMigrationStage(t, stage.Path, key)
	defer owner.Close()
	for _, kind := range []string{"bitwarden-cli", "bitwarden-browser", "bitwarden-browser-backup"} {
		if err := owner.WithLocalState(ctx, kind, document.VaultID, 1, equalLegacyVaultValue([]byte("native archived token"))); err != nil {
			t.Fatal(kind, err)
		}
	}
}

func TestVaultMigrationRetirementInitializationCheckpoints(t *testing.T) {
	for _, checkpoint := range []string{"marker", "journal", "corrupt-before-journal"} {
		t.Run(checkpoint, func(t *testing.T) {
			f := newRetirementFixture(t)
			ctx := context.Background()
			doc, err := readVaultSlotFile(f.stage)
			if err != nil {
				t.Fatal(err)
			}
			doc.Migration.Phase = vault.MigrationRetiring
			doc.Sequence++
			if err := writeVaultSlotFile(f.stage, f.key, doc, doc.Sequence-1); err != nil {
				t.Fatal(err)
			}
			if checkpoint != "marker" {
				owner := openNativeMigrationStage(t, f.stage, f.key)
				counts, err := owner.VerifyIntegrity(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if checkpoint == "journal" {
					counts.LocalStates++
					if _, err := writeLegacyRetirementJournal(ctx, owner, doc.VaultID, legacyRetirementJournal{Version: 1, Binding: doc.Migration.Binding, Inventory: counts}, 0); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := owner.DeleteLocalState(ctx, f.files[0].kind, f.files[0].scope, 1); err != nil {
						t.Fatal(err)
					}
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			count, err := f.run(ctx, func(string, []byte) error { calls++; return nil })
			if checkpoint == "corrupt-before-journal" {
				if err == nil || calls != 0 {
					t.Fatal("unverified initial journal adopted")
				}
			} else if err != nil || count != 2 || calls != 2 {
				t.Fatal("checkpoint did not resume", count, calls, err)
			}
		})
	}
}
