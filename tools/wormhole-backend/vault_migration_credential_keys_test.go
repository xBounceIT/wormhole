package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultLoadMigrationCredential(t *testing.T) {
	for _, mode := range []string{"value", "empty", "missing", "load-error", "oversize", "cancel", "open-error", "missing-operations", "bad-limit", "already-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			row := legacyInventoryRow{ID: "credential", Reference: "original", Encoding: linuxLegacySecretServiceEncoding}
			maximum := 3
			raw := []byte("key")
			if mode == "empty" {
				raw = nil
			}
			want := bytes.Clone(raw)
			if mode == "bad-limit" {
				maximum = 0
			}
			if mode == "already-cancelled" {
				cancel()
			}
			opens, closes := 0, 0
			got, err := loadMigrationCredential(ctx, row, maximum, func(c context.Context, selected legacyInventoryRow, limit int) (migrationCredentialStore, error) {
				opens++
				if c != ctx || selected.ID != row.ID || selected.Reference != row.Reference || selected.Encoding != row.Encoding || limit != maximum {
					t.Fatal("changed store selection")
				}
				store := migrationCredentialStore{Close: func() { closes++ }}
				switch mode {
				case "open-error":
					return store, errors.New("open failed")
				case "missing-operations":
					return store, nil
				}
				store.Load = func(context.Context) ([]byte, bool, error) {
					switch mode {
					case "missing":
						return raw, false, nil
					case "load-error":
						return raw, true, errors.New("read failed")
					case "oversize":
						raw = append(raw, '!')
					case "cancel":
						cancel()
					}
					return raw, true, nil
				}
				return store, nil
			})
			if closes != opens {
				t.Fatal("store was left open")
			}
			switch mode {
			case "value", "empty":
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("credential changed", err)
				}
				clearBytes(got)
			default:
				if got != nil || !errors.Is(err, errVaultMigrationSource) {
					t.Fatal("failed read returned data or an unexpected error", err)
				}
				switch mode {
				case "bad-limit", "already-cancelled":
					if opens != 0 {
						t.Fatal("invalid request opened an OS service")
					}
				case "missing", "load-error", "oversize", "cancel":
					if !bytes.Equal(raw, make([]byte, len(raw))) {
						t.Fatal("failed read retained borrowed data")
					}
				}
			}
		})
	}
}

type retirementKeysFixture struct {
	retirementFixture
	rows            []legacyInventoryRow
	values          map[string][]byte
	borrowed        [][]byte
	closed, deleted int
}

// This represents a native stage whose file phase completed on the source OS.
// Fake OS values let Windows exercise keychain recovery without touching any real
// credential store. All archive, journal and inventory writes use the real owner.
func newRetirementKeysFixture(t *testing.T) *retirementKeysFixture {
	t.Helper()
	f := &retirementKeysFixture{retirementFixture: newRetirementFixture(t), values: map[string][]byte{}}
	ctx := context.Background()
	if _, err := f.run(ctx, func(string, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	legacyVaultSecrets(t, f.db)
	for i, id := range []string{"11111111-1111-4111-8111-111111111111", "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF"} {
		reference := id + ":" + uuid.NewString()
		value := []byte("native credential original")
		if i == 1 {
			value = []byte{}
		}
		f.values[reference] = value
		legacyVaultSQL(t, f.db, `INSERT INTO CredentialSecrets VALUES(?,?,?,'original-time')`, id, reference, linuxSecretServiceEncoding)
	}
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	var inventory legacySourceInventory
	manifest, err := owner.ReadLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.WithLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, manifest.RowVersion, func(raw []byte) error { return json.Unmarshal(raw, &inventory) }); err != nil {
		t.Fatal(err)
	}
	current, err := captureLegacySourceInventory(resolverCaptureReader{ctx, f.db}, f.source, "", f.document.VaultID, f.key, func(_, encoded, _ string, _ ...string) ([]byte, error) { return bytes.Clone(f.values[encoded]), nil })
	if err != nil {
		t.Fatal(err)
	}
	var next legacySourceInventory
	if json.Unmarshal(current, &next) != nil {
		t.Fatal("bad fixture inventory")
	}
	next.Files = inventory.Files
	f.rows = next.Secrets
	for _, row := range f.rows {
		archive, _ := json.Marshal(legacyVaultOrphan{Version: 1, Source: row.ID, Encoded: row.Reference, Encoding: row.Encoding, UpdatedAt: row.UpdatedAt, Value: f.values[row.Reference]})
		if _, err := owner.PutLocalState(ctx, "legacy-secret", strings.ToLower(row.ID), archive, 0); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(next)
	if _, err := owner.PutLocalState(ctx, migrationSourceInventoryKind, f.document.VaultID, raw, manifest.RowVersion); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(f.stage)
	if err != nil {
		t.Fatal(err)
	}
	state, journal, err := readLegacyRetirementJournal(ctx, owner, doc, len(f.files), len(f.rows))
	if err != nil {
		t.Fatal(err)
	}
	journal.Inventory, err = owner.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeLegacyRetirementJournal(ctx, owner, doc.VaultID, journal, state.RowVersion); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *retirementKeysFixture) store(_ context.Context, row legacyInventoryRow, _ int) (migrationCredentialStore, error) {
	return migrationCredentialStore{
		Load: func(context.Context) ([]byte, bool, error) {
			value, present := f.values[row.Reference]
			copy := bytes.Clone(value)
			f.borrowed = append(f.borrowed, copy)
			return copy, present, nil
		},
		Delete: func(context.Context) error { f.deleted++; delete(f.values, row.Reference); return nil },
		Close:  func() { f.closed++ },
	}, nil
}

func (f *retirementKeysFixture) retire(ctx context.Context, open migrationCredentialStoreFactory) (legacyRetirementProgress, error) {
	return retireLegacyVaultSourcesWith(ctx, f.source, "", f.stage, f.key, func(string, []byte) error { return nil }, open)
}

func TestVaultMigrationCredentialKeysResumeAndEmptyValues(t *testing.T) {
	f := newRetirementKeysFixture(t)
	ctx := context.Background()
	_, err := f.retire(ctx, func(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
		store, _ := f.store(ctx, row, maximum)
		remove := store.Delete
		store.Delete = func(ctx context.Context) error { remove(ctx); return errors.New("uncertain deletion") }
		return store, nil
	})
	if err == nil || f.deleted != 1 || f.closed != 1 {
		t.Fatal("did not preserve uncertain outcome", err)
	}
	if _, err := f.run(ctx, func(string, []byte) error { return nil }); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("file-only resume ignored key intent", err)
	}
	progress, err := f.retire(ctx, f.store)
	if err != nil || progress.Files != 2 || progress.KeyReferences != 2 || len(f.values) != 0 {
		t.Fatal(progress, err)
	}
	if _, err := f.retire(ctx, f.store); err != nil {
		t.Fatal("idempotent retry failed", err)
	}
	if f.deleted != 2 {
		t.Fatal("unexpected deletion count", f.deleted)
	}
	for _, value := range f.borrowed {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("credential plaintext retained")
		}
	}
	var count int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM CredentialSecrets").Scan(&count); err != nil || count != 2 {
		t.Fatal("SQL source altered", count, err)
	}
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	for i, row := range f.rows {
		if err := owner.WithLocalState(ctx, "legacy-secret", strings.ToLower(row.ID), 1, func(raw []byte) error {
			var archive legacyVaultOrphan
			if err := json.Unmarshal(raw, &archive); err != nil {
				return err
			}
			defer vault.Wipe(archive.Value)
			expected := []byte("native credential original")
			if i == 1 {
				expected = []byte{}
			}
			if archive.Source != row.ID || archive.Encoded != row.Reference || archive.Encoding != row.Encoding || !bytes.Equal(archive.Value, expected) {
				return errors.New("archive changed")
			}
			return nil
		}); err != nil {
			t.Fatal("native archive lost", err)
		}
	}
	doc, _ := readVaultSlotFile(f.stage)
	_, journal, err := readLegacyRetirementJournal(ctx, owner, doc, 2, 2)
	if err != nil || journal.Version != 2 || journal.KeysCompleted != 2 || journal.PendingKey != nil {
		t.Fatal("invalid completed key journal", err)
	}
}

func TestVaultMigrationCredentialKeysRecheckAfterIntent(t *testing.T) {
	for _, mutation := range []string{"changed", "missing", "locked", "cancel", "absent-with-value"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRetirementKeysFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err := f.retire(ctx, func(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
				store, _ := f.store(ctx, row, maximum)
				if row.ID != f.rows[0].ID {
					return store, nil
				}
				load, calls := store.Load, 0
				store.Load = func(ctx context.Context) ([]byte, bool, error) {
					calls++
					if calls == 2 {
						switch mutation {
						case "changed":
							f.values[row.Reference] = []byte("unarchived replacement")
						case "missing":
							delete(f.values, row.Reference)
						case "locked":
							return nil, false, errors.New("locked")
						case "cancel":
							cancel()
						case "absent-with-value":
							return []byte("contradictory"), false, nil
						}
					}
					return load(ctx)
				}
				return store, nil
			})
			if mutation == "missing" {
				if err != nil || f.deleted != 1 {
					t.Fatal("absence after persisted intent not recovered", err)
				}
				return
			}
			if err == nil || f.deleted != 0 {
				t.Fatal("unverified value removed after intent", err)
			}
		})
	}
}

func TestVaultMigrationCredentialKeyJournalValidation(t *testing.T) {
	f := newRetirementKeysFixture(t)
	ctx := context.Background()
	owner := openNativeMigrationStage(t, f.stage, f.key)
	defer owner.Close()
	doc, err := readVaultSlotFile(f.stage)
	if err != nil {
		t.Fatal(err)
	}
	state, base, err := readLegacyRetirementJournal(ctx, owner, doc, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	negative, first, beyond := -1, 0, 2
	for _, mutate := range []func(*legacyRetirementJournal){
		func(j *legacyRetirementJournal) { j.Version = 1; j.KeysCompleted = 1 },
		func(j *legacyRetirementJournal) { j.Version = 1; j.PendingKey = &first },
		func(j *legacyRetirementJournal) { j.KeysCompleted = -1 },
		func(j *legacyRetirementJournal) { j.KeysCompleted = 3 },
		func(j *legacyRetirementJournal) { j.PendingKey = &negative },
		func(j *legacyRetirementJournal) { j.PendingKey = &beyond },
		func(j *legacyRetirementJournal) { j.KeysCompleted = 2; j.PendingKey = &beyond },
		func(j *legacyRetirementJournal) {
			j.PendingKey = &first
			j.Pending = &legacyRetirementFile{Index: 0, Protected: []byte("protected")}
		},
	} {
		journal := base
		journal.Version = 2
		mutate(&journal)
		state, err = writeLegacyRetirementJournal(ctx, owner, doc.VaultID, journal, state.RowVersion)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := readLegacyRetirementJournal(ctx, owner, doc, 2, 2); !errors.Is(err, vault.ErrFormat) {
			t.Fatal("invalid key journal accepted", err)
		}
	}
}

func TestVaultMigrationCredentialKeysRejectMissingChangedAndUnavailable(t *testing.T) {
	for _, failure := range []string{"missing", "changed", "unavailable", "not-deleted", "replacement", "malformed-store", "factory", "oversize", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			f := newRetirementKeysFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "missing" {
				delete(f.values, f.rows[0].Reference)
			}
			if failure == "changed" {
				f.values[f.rows[0].Reference] = []byte("new external value")
			}
			_, err := f.retire(ctx, func(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
				store, _ := f.store(ctx, row, maximum)
				switch failure {
				case "factory":
					return store, errors.New("unavailable")
				case "malformed-store":
					store.Load = nil
				case "unavailable":
					store.Load = func(context.Context) ([]byte, bool, error) { return nil, false, errors.New("locked") }
				case "oversize":
					store.Load = func(context.Context) ([]byte, bool, error) { return make([]byte, maximum+1), true, nil }
				case "not-deleted":
					store.Delete = func(context.Context) error { return nil }
				case "replacement":
					store.Delete = func(context.Context) error { f.values[row.Reference] = []byte("new value during deletion"); return nil }
				case "cancel":
					store.Delete = func(context.Context) error { cancel(); return nil }
				}
				return store, nil
			})
			if err == nil {
				t.Fatal("invalid external store outcome accepted")
			}
			if f.closed != 1 {
				t.Fatal("store leaked", f.closed)
			}
			if failure == "replacement" {
				if _, err := f.retire(context.Background(), f.store); !errors.Is(err, vault.ErrAuthentication) {
					t.Fatal("replacement value deleted on retry", err)
				}
			}
		})
	}
}

func TestVaultMigrationCredentialKeysReappearDuringLaterIntent(t *testing.T) {
	f := newRetirementKeysFixture(t)
	_, err := f.retire(context.Background(), func(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
		store, _ := f.store(ctx, row, maximum)
		if row.ID == f.rows[1].ID {
			store.Delete = func(context.Context) error { return errors.New("stop") }
		}
		return store, nil
	})
	if err == nil {
		t.Fatal("fixture did not stop")
	}
	f.values[f.rows[0].Reference] = []byte("native credential original")
	if p, err := f.retire(context.Background(), f.store); err != nil || p.KeyReferences != 2 || len(f.values) != 0 {
		t.Fatal("reappearance stranded pending key", p, err)
	}
}

func TestVaultMigrationCredentialKeyInventoryValidation(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	valid := legacyInventoryRow{ID: id, Reference: id, Encoding: linuxSecretServiceEncoding, Authentication: make([]byte, 32)}
	for _, change := range []func(*legacyInventoryRow){
		func(r *legacyInventoryRow) { r.ID = "bad" }, func(r *legacyInventoryRow) { r.Reference = "bad" }, func(r *legacyInventoryRow) { r.Reference = "" }, func(r *legacyInventoryRow) { r.Authentication = nil }, func(r *legacyInventoryRow) { r.Encoding = "unknown" }, func(r *legacyInventoryRow) { r.Encoding = protectedSecretEncoding }, func(r *legacyInventoryRow) { bad := "bad\x00time"; r.UpdatedAt = &bad },
	} {
		row := valid
		change(&row)
		if _, err := legacyRetirementKeyRows([]legacyInventoryRow{row}); err == nil {
			t.Fatal("bad inventory accepted")
		}
	}
	if _, err := legacyRetirementKeyRows([]legacyInventoryRow{valid, valid}); err == nil {
		t.Fatal("duplicate identity")
	}
	for _, encoding := range []string{protectedSecretEncoding, electronSafeStorageSecretEncoding} {
		row := valid
		row.Reference = ""
		row.Encoding = encoding
		if got, err := legacyRetirementKeyRows([]legacyInventoryRow{row}); err != nil || len(got) != 0 {
			t.Fatal("local wrapper treated as keychain entry", err)
		}
	}
}
