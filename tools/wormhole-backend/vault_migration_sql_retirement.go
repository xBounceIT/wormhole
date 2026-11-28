package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Native-only continuation. Files and credential-store references must already
// be retired. This never publishes either database or enables ordinary access.
// The caller retains fresh-authentication and browser-quiescence ownership.
func retireLegacyVaultSQL(ctx context.Context, source, stage string, key []byte) error {
	return retireLegacyVaultSQLWith(ctx, source, stage, key, openMigrationCredentialStore, nil)
}

// checkpoint models uncertain process termination, including a committed SQL
// deletion whose acknowledgement has not yet reached the encrypted journal.
func retireLegacyVaultSQLWith(ctx context.Context, source, stage string, key []byte, stores migrationCredentialStoreFactory, checkpoint func(string) error) error {
	return retireLegacyVaultSQLOwned(ctx, source, stage, key, stores, checkpoint, nil)
}

func retireLegacyVaultSQLOwned(ctx context.Context, source, stage string, key []byte, stores migrationCredentialStoreFactory, checkpoint func(string) error, ownership *legacyVaultMigrationOwnership) error {
	logical := filepath.Clean(source)
	canonical, info, err := legacyVaultSourceIdentity(source)
	if err != nil {
		return errVaultMigrationSource
	}
	release, err := lockLegacyMigrationSourceOwned(ctx, canonical, ownership)
	if err != nil {
		return err
	}
	defer release()
	document, err := readVaultSlotFile(stage)
	if err != nil {
		return err
	}
	if err := vault.VerifySlotFile(key, document, document.VaultID, document.FileID, 1); err != nil {
		return err
	}
	if stage != canonical+".migrating-"+document.FileID || document.Migration == nil || document.Migration.Phase != vault.MigrationRetiring {
		return vault.ErrPolicy
	}
	guard, err := readVaultSlotFile(canonical)
	if err != nil || !matchingRetirementGuard(key, guard, document) {
		return vault.ErrAuthentication
	}
	releaseStage, err := lockLegacyMigrationStageOwned(ctx, stage, ownership)
	if err != nil {
		return errVaultSlotConflict
	}
	defer releaseStage()
	options := localVaultOptions(document)
	options.AllowImport = true
	owner, err := localvault.Open(ctx, stage, options, bytes.Clone(key))
	if err != nil {
		return err
	}
	defer owner.Close()
	inventory, files, keys, err := readLegacyRetirementInventory(ctx, owner, document, logical)
	if err != nil {
		return err
	}
	state, journal, err := readLegacyRetirementJournal(ctx, owner, document, len(files), len(keys))
	if err != nil {
		return err
	}
	if journal.Pending != nil {
		vault.Wipe(journal.Pending.Protected)
	}
	if journal.Version < 2 || journal.Completed != len(files) || journal.KeysCompleted != len(keys) || journal.Pending != nil || journal.PendingKey != nil {
		return vault.ErrPolicy
	}
	if inventory.Browser != nil {
		if journal.Browser == nil || journal.Browser.Pending != nil || journal.Browser.Completed != len(inventory.Browser.Profiles) {
			return vault.ErrPolicy
		}
		if err := verifyLegacyBrowserSourcesAbsent(ctx, inventory.Browser, key); err != nil {
			return err
		}
	} else if journal.Browser != nil {
		return vault.ErrAuthentication
	}
	counts, err := owner.VerifyIntegrity(ctx)
	if err != nil {
		return err
	}
	if counts != journal.Inventory {
		return vault.ErrAuthentication
	}
	for _, file := range files {
		if _, err := os.Lstat(file.path); !errors.Is(err, os.ErrNotExist) {
			return vault.ErrAuthentication
		}
	}
	if err := verifyLegacySQLKeyAbsence(ctx, keys, stores); err != nil {
		return err
	}
	// SQLite must never follow an attacker-provided sidecar symlink. Nothing
	// removes an unexpected sidecar; recovery stays quarantined for inspection.
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		file, err := os.Lstat(canonical + suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && !file.Mode().IsRegular() {
			return errVaultMigrationSource
		}
	}
	database, err := openLegacyMigrationSource(canonical)
	if err != nil {
		return err
	}
	defer database.Close()
	connection, err := database.Conn(ctx)
	if err != nil {
		return errVaultMigrationSource
	}
	defer connection.Close()
	// DELETE mode gives compaction a single file and no surviving WAL frames.
	// EXCLUSIVE ownership stays held between the SQL commit and VACUUM.
	for _, pragma := range []string{"PRAGMA locking_mode=EXCLUSIVE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON"} {
		if _, err := connection.ExecContext(ctx, pragma); err != nil {
			return errVaultMigrationSource
		}
	}
	var mode string
	if connection.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode) != nil || mode != "delete" {
		return errVaultMigrationSource
	}
	if _, err := connection.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
		return errVaultMigrationSource
	}
	defer connection.ExecContext(context.Background(), "ROLLBACK")
	reader := resolverCaptureReader{ctx, connection}
	if err := verifyLegacyMigrationIdentity(reader, logical, info); err != nil {
		return err
	}
	if err := rejectNewLegacyRetirementFiles(reader, logical, document.VaultID, files); err != nil {
		return err
	}
	subkey, err := vault.DeriveKey(key, []byte(document.VaultID), vault.PurposeLocalSeal)
	if err != nil {
		return err
	}
	defer vault.Wipe(subkey)
	current, err := captureLegacyDatabaseState(reader, subkey)
	if err != nil {
		return err
	}
	if journal.SQL == nil {
		if !hmac.Equal(current, inventory.DatabaseMAC) {
			return vault.ErrAuthentication
		}
		expected, err := captureLegacyDatabaseRetirementState(reader, subkey, true)
		if err != nil {
			return err
		}
		if journal.Browser == nil {
			journal.Version = 3
		}
		journal.SQL = &legacyRetirementSQL{Phase: "pending", Authentication: expected}
		state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
		if err != nil {
			return err
		}
	}
	if journal.SQL.Phase == "compacted" {
		if !hmac.Equal(current, journal.SQL.Authentication) {
			return vault.ErrAuthentication
		}
		return owner.Close()
	}
	step := func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if checkpoint != nil {
			return checkpoint(name)
		}
		return nil
	}
	if err := step("intent"); err != nil {
		return err
	}
	if !hmac.Equal(current, journal.SQL.Authentication) {
		if journal.SQL.Phase != "pending" || !hmac.Equal(current, inventory.DatabaseMAC) {
			return vault.ErrAuthentication
		}
		exists, err := validateLegacyVaultSecretSource(reader)
		if err != nil {
			return err
		}
		if exists {
			if _, err := connection.ExecContext(ctx, "DELETE FROM main.CredentialSecrets"); err != nil {
				return errVaultMigrationSource
			}
		}
	}
	// Trigger/cascade effects, retained rows or any metadata change must roll
	// back. Only the authenticated, predicted empty-secret state may commit.
	after, err := captureLegacyDatabaseState(reader, subkey)
	if err != nil || !hmac.Equal(after, journal.SQL.Authentication) {
		return vault.ErrAuthentication
	}
	if err := verifyLegacyMigrationIdentity(reader, logical, info); err != nil {
		return err
	}
	if err := step("deleted"); err != nil {
		return err
	}
	if _, err := connection.ExecContext(ctx, "COMMIT"); err != nil {
		return errVaultMigrationSource
	}
	if err := step("commit"); err != nil {
		return err
	}
	journal.SQL.Phase = "committed"
	state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
	if err != nil {
		return err
	}
	if err := step("committed"); err != nil {
		return err
	}
	if _, err := connection.ExecContext(ctx, "VACUUM main"); err != nil {
		return errVaultMigrationSource
	}
	if err := step("vacuumed"); err != nil {
		return err
	}
	after, err = captureLegacyDatabaseState(reader, subkey)
	if err != nil || !hmac.Equal(after, journal.SQL.Authentication) {
		return vault.ErrAuthentication
	}
	if err := verifyLegacyMigrationIdentity(reader, logical, info); err != nil {
		return err
	}
	journal.SQL.Phase = "compacted"
	_, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
	return errors.Join(err, owner.Close())
}

func verifyLegacySQLKeyAbsence(ctx context.Context, rows []legacyInventoryRow, open migrationCredentialStoreFactory) error {
	if open == nil {
		return vault.ErrPolicy
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		maximum := maxStoredCredentialBytes
		if kind, _ := legacyOrphanRowIdentity(row.ID); kind == "legacy-tunnel-row" {
			maximum = backendMaxTunnelRequestBytes
		}
		store, err := open(ctx, row, maximum)
		if err != nil || store.Load == nil || store.Close == nil {
			if store.Close != nil {
				store.Close()
			}
			return errVaultMigrationSource
		}
		value, present, err := store.Load(ctx)
		vault.Wipe(value)
		store.Close()
		if err != nil || present || len(value) != 0 {
			return errVaultMigrationSource
		}
	}
	return ctx.Err()
}
