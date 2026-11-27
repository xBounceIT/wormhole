package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Native continuation after fresh authentication, confirmed recovery setup and
// Chromium shutdown. Source/userData are fixed native selections. The key is
// borrowed only for this call. No ordinary owner is published, even on success:
// a later cutover must renew the closed snapshot and persist rollback floors.
func continueLegacyVaultMigration(ctx context.Context, source, userData string, document vault.SlotFile, key []byte, plan resolver.MigrationPlan) (string, error) {
	return continueLegacyVaultMigrationWith(ctx, source, userData, document, key, plan, nil)
}

// checkpoint interrupts only between completed durable phases. Each individual
// phase retains its existing encrypted intent and uncertain-outcome recovery.
func continueLegacyVaultMigrationWith(ctx context.Context, source, userData string, document vault.SlotFile, key []byte, plan resolver.MigrationPlan, checkpoint func(string) error) (string, error) {
	if plan.Validate() != nil || plan.WorkspaceID != document.VaultID || document.Sequence != 1 || document.Initializing || document.Encrypted || document.Migration != nil || len(document.Nodes) != 0 || !filepath.IsAbs(source) || filepath.Clean(source) != source || !legacyPublicationFilename(filepath.Base(source)) || !filepath.IsAbs(userData) || filepath.Clean(userData) != userData {
		return "", vault.ErrFormat
	}
	raw, err := vault.EncodeSlotFile(key, document)
	if err != nil {
		return "", err
	}
	document, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return "", err
	}
	var path string
	err = withLegacyVaultMigrationOwnership(ctx, source, document.FileID, func(ownership *legacyVaultMigrationOwnership) error {
		binding, err := legacyVaultStageBinding(key, document.VaultID, ownership.source, filepath.Clean(source), plan)
		if err != nil {
			return err
		}
		current, err := readVaultSlotFile(ownership.stage)
		missing := errors.Is(err, errVaultSlotMissing)
		if err != nil && !missing {
			return err
		}
		if !missing && !matchingLegacyMigrationSetup(key, document, current, binding) {
			return vault.ErrAuthentication
		}
		if missing || current.Migration.Phase == vault.MigrationCopying {
			if _, err := stageLegacyVaultDomainsOwned(ctx, source, userData, document, key, plan, ownership); err != nil {
				return err
			}
			current, err = readVaultSlotFile(ownership.stage)
			if err != nil {
				return err
			}
		}
		if current.Migration.Phase == vault.MigrationDomainsCopied {
			if err := verifyVaultMigrationSnapshot(ctx, ownership.stage, current, key); err != nil {
				return err
			}
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
		if err := step("copied"); err != nil {
			return err
		}
		sqlStarted, err := legacyMigrationSQLStarted(ctx, source, userData, ownership.stage, current, key)
		if err != nil {
			return err
		}
		if !sqlStarted {
			if _, err := retireLegacyVaultSourcesOwned(ctx, source, userData, ownership.stage, key, retireLegacyFileProtectionKey, openMigrationCredentialStore, ownership); err != nil {
				return err
			}
		}
		if err := step("sources-retired"); err != nil {
			return err
		}
		if err := retireLegacyVaultSQLOwned(ctx, source, ownership.stage, key, openMigrationCredentialStore, nil, ownership); err != nil {
			return err
		}
		if err := step("sql-retired"); err != nil {
			return err
		}
		path = ownership.stage
		return nil
	})
	return path, err
}

// Resumption cannot change slots, root identity, profile floors or choices.
// Only the migration phase and its slot-file sequence may have advanced.
func matchingLegacyMigrationSetup(key []byte, expected, current vault.SlotFile, binding string) bool {
	if vault.VerifySlotFile(key, current, expected.VaultID, expected.FileID, 1) != nil || current.Migration == nil || current.Migration.Binding != binding {
		return false
	}
	current = vault.MigrationSlotFile(current, nil)
	current.Sequence, current.Authentication = 1, nil
	expected.Authentication = nil
	a, aErr := json.Marshal(expected)
	b, bErr := json.Marshal(current)
	return aErr == nil && bErr == nil && bytes.Equal(a, b)
}

func legacyMigrationSQLStarted(ctx context.Context, source, userData, stage string, document vault.SlotFile, key []byte) (bool, error) {
	options := localVaultOptions(document)
	options.AllowImport = true
	owner, err := localvault.Open(ctx, stage, options, bytes.Clone(key))
	if err != nil {
		return false, err
	}
	defer owner.Close()
	inventory, files, keys, err := readLegacyRetirementInventory(ctx, owner, document, filepath.Clean(source))
	if err != nil {
		return false, err
	}
	if inventory.Browser == nil || inventory.Browser.UserData != userData {
		return false, vault.ErrAuthentication
	}
	_, journal, err := readLegacyRetirementJournal(ctx, owner, document, len(files), len(keys))
	if journal.Pending != nil {
		vault.Wipe(journal.Pending.Protected)
	}
	if errors.Is(err, vaultstore.ErrMissing) {
		err = nil // The retirement phase itself authenticates its missing-intent path.
	}
	return journal.SQL != nil, errors.Join(err, owner.Close())
}
