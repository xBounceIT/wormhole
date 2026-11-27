package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const migrationRetirementKind = vaultstore.LocalStateMigrationRetirement

type legacyRetirementJournal struct {
	Version       int                           `json:"version"`
	Binding       string                        `json:"binding"`
	Inventory     localvault.IntegrityInventory `json:"inventory"`
	Completed     int                           `json:"completed"`
	Pending       *legacyRetirementFile         `json:"pending"`
	KeysCompleted int                           `json:"keysCompleted,omitempty"`
	PendingKey    *int                          `json:"pendingKey,omitempty"`
	SQL           *legacyRetirementSQL          `json:"sql,omitempty"`
	Browser       *legacyRetirementBrowser      `json:"browser,omitempty"`
}

type legacyRetirementBrowser struct {
	Completed int  `json:"completed"`
	Pending   *int `json:"pending,omitempty"`
}

type legacyRetirementSQL struct {
	Phase          string `json:"phase"`
	Authentication []byte `json:"authentication"`
}

type legacyRetirementFile struct {
	Index     int    `json:"index"`
	Protected []byte `json:"-"`
}

func lockLegacyVaultSource(ctx context.Context, source string) (func(), error) {
	release, err := acquireWorkspaceOwnership(source, true)
	if err != nil {
		return nil, err
	}
	releaseStores, err := lockLegacyVaultSourceStores(ctx, source)
	if err != nil {
		release()
		return nil, err
	}
	return func() { releaseStores(); release() }, nil
}

// Publication transfers workspace exclusion to the active owner, while these
// shorter-lived source locks are always released when cutover returns.
func lockLegacyVaultSourceStores(ctx context.Context, source string) (func(), error) {
	releases := []func(){}
	cleanup := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, acquire := range []func() (func(), error){
		func() (func(), error) { return acquireExclusiveFileLockContext(ctx, source+".vault-migration.lock") },
		func() (func(), error) { return acquireTunnelConfigurationLock(ctx, source) },
		func() (func(), error) {
			return acquireExclusiveFileLockContext(ctx, credentialPrivateKeyLockPath(source))
		},
	} {
		release, err := acquire()
		if err != nil {
			cleanup()
			return nil, errVaultMigrationSource
		}
		releases = append(releases, release)
	}
	return cleanup, nil
}

// Native-only continuation after fresh authentication and source quiescence.
// Retires only inventoried protected files and their per-path keychain keys.
// SQL secrets, browser partitions and final publication are later journal phases.
// Both source and stage remain quarantined against ordinary use throughout.
func retireLegacyVaultFiles(ctx context.Context, source, userData, stage string, key []byte) (int, error) {
	return retireLegacyVaultFilesWith(ctx, source, userData, stage, key, retireLegacyFileProtectionKey)
}

func retireLegacyVaultFilesWith(ctx context.Context, source, userData, stage string, key []byte, retireKey func(string, []byte) error) (int, error) {
	progress, err := retireLegacyVaultSourcesWith(ctx, source, userData, stage, key, retireKey, nil)
	return progress.Files, err
}

type legacyRetirementProgress struct{ Files, KeyReferences, BrowserProfiles int }

func retireLegacyVaultSources(ctx context.Context, source, userData, stage string, key []byte) (legacyRetirementProgress, error) {
	return retireLegacyVaultSourcesWith(ctx, source, userData, stage, key, retireLegacyFileProtectionKey, openMigrationCredentialStore)
}

func retireLegacyVaultSourcesWith(ctx context.Context, source, userData, stage string, key []byte, retireKey func(string, []byte) error, credentialStores migrationCredentialStoreFactory, browserRemoval ...func(*os.Root, string) error) (legacyRetirementProgress, error) {
	return retireLegacyVaultSourcesOwned(ctx, source, userData, stage, key, retireKey, credentialStores, nil, browserRemoval...)
}

func retireLegacyVaultSourcesOwned(ctx context.Context, source, userData, stage string, key []byte, retireKey func(string, []byte) error, credentialStores migrationCredentialStoreFactory, ownership *legacyVaultMigrationOwnership, browserRemoval ...func(*os.Root, string) error) (legacyRetirementProgress, error) {
	logical := filepath.Clean(source)
	canonical, info, err := legacyVaultSourceIdentity(source)
	if err != nil || retireKey == nil || len(browserRemoval) > 1 || len(browserRemoval) == 1 && browserRemoval[0] == nil {
		return legacyRetirementProgress{}, errVaultMigrationSource
	}
	removeBrowser := func(root *os.Root, name string) error { return root.RemoveAll(name) }
	if len(browserRemoval) == 1 {
		removeBrowser = browserRemoval[0]
	}
	release, err := lockLegacyMigrationSourceOwned(ctx, canonical, ownership)
	if err != nil {
		return legacyRetirementProgress{}, err
	}
	defer release()
	document, err := readVaultSlotFile(stage)
	if err != nil {
		return legacyRetirementProgress{}, err
	}
	if err := vault.VerifySlotFile(key, document, document.VaultID, document.FileID, 1); err != nil {
		return legacyRetirementProgress{}, err
	}
	if stage != canonical+".migrating-"+document.FileID || document.Migration == nil || (document.Migration.Phase != vault.MigrationDomainsCopied && document.Migration.Phase != vault.MigrationRetiring) {
		return legacyRetirementProgress{}, vault.ErrPolicy
	}
	releaseStage, err := lockLegacyMigrationStageOwned(ctx, stage, ownership)
	if err != nil {
		return legacyRetirementProgress{}, errVaultSlotConflict
	}
	defer releaseStage()
	snapshotErr := verifyVaultMigrationSnapshot(ctx, stage, document, key)
	if document.Migration.Phase == vault.MigrationDomainsCopied && snapshotErr != nil {
		return legacyRetirementProgress{}, snapshotErr
	}
	options := localVaultOptions(document)
	options.AllowImport = true
	owner, err := localvault.Open(ctx, stage, options, bytes.Clone(key))
	if err != nil {
		return legacyRetirementProgress{}, err
	}
	defer owner.Close()
	database, err := openLegacyMigrationSource(canonical)
	if err != nil {
		return legacyRetirementProgress{}, err
	}
	defer database.Close()
	var progress legacyRetirementProgress
	err = withReservedLegacySource(ctx, database, func(reader resolverCaptureReader) error {
		if err := verifyLegacyMigrationIdentity(reader, logical, info); err != nil {
			return err
		}
		inventory, specs, keyRows, err := readLegacyRetirementInventory(ctx, owner, document, logical)
		if err != nil {
			return err
		}
		state, journal, err := readLegacyRetirementJournal(ctx, owner, document, len(specs), len(keyRows))
		missing := errors.Is(err, vaultstore.ErrMissing)
		if err != nil && !missing {
			return err
		}
		if journal.SQL != nil || journal.Browser != nil && credentialStores == nil {
			return vault.ErrPolicy
		}
		defer func() {
			if journal.Pending != nil {
				vault.Wipe(journal.Pending.Protected)
			}
		}()
		guard, guardErr := readVaultSlotFile(canonical)
		guardMissing := errors.Is(guardErr, errVaultSlotMissing)
		if !guardMissing && (guardErr != nil || !matchingRetirementGuard(key, guard, document)) {
			return vault.ErrAuthentication
		}
		if missing {
			if !guardMissing || snapshotErr != nil {
				return vault.ErrAuthentication
			}
			if err := verifyLegacySourceInventory(reader, logical, userData, document.VaultID, key, owner); err != nil {
				return err
			}
			counts, err := owner.VerifyIntegrity(ctx)
			if err != nil {
				return err
			}
			if document.Migration.Phase != vault.MigrationRetiring {
				document.Sequence++
				document.Migration.Phase = vault.MigrationRetiring
				if err := writeVaultSlotFile(stage, key, document, document.Sequence-1); err != nil {
					return err
				}
			}
			counts.LocalStates++
			journal = legacyRetirementJournal{Version: 1, Binding: document.Migration.Binding, Inventory: counts}
			state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, 0)
			if err != nil {
				return err
			}
		} else if document.Migration.Phase != vault.MigrationRetiring {
			return vault.ErrPolicy
		}
		counts, err := owner.VerifyIntegrity(ctx)
		if err != nil {
			return err
		}
		if counts != journal.Inventory {
			return vault.ErrAuthentication
		}
		if guardMissing {
			if journal.Completed != 0 || journal.Pending != nil || journal.KeysCompleted != 0 || journal.PendingKey != nil || journal.Browser != nil {
				return vault.ErrAuthentication
			}
			if err := verifyLegacySourceInventory(reader, logical, userData, document.VaultID, key, owner); err != nil {
				return err
			}
			guard = document
			guard.Sequence = 1
			if err := writeVaultSlotFile(canonical, key, guard, 0); err != nil {
				return err
			}
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
		if !hmac.Equal(current, inventory.DatabaseMAC) {
			return vault.ErrAuthentication
		}
		if err := rejectNewLegacyRetirementFiles(reader, logical, document.VaultID, specs); err != nil {
			return err
		}
		if journal.Browser != nil {
			for _, file := range specs {
				if _, err := os.Lstat(file.path); !errors.Is(err, os.ErrNotExist) {
					return vault.ErrAuthentication
				}
			}
			if err := verifyLegacySQLKeyAbsence(ctx, keyRows, credentialStores); err != nil {
				return err
			}
			if inventory.Browser == nil || filepath.Clean(userData) != inventory.Browser.UserData {
				return vault.ErrAuthentication
			}
			if err := retireLegacyBrowserProfiles(ctx, inventory.Browser, subkey, owner, &state, &journal, removeBrowser); err != nil {
				return err
			}
			progress = legacyRetirementProgress{Files: journal.Completed, KeyReferences: journal.KeysCompleted, BrowserProfiles: journal.Browser.Completed}
			return verifyLegacyMigrationIdentity(reader, logical, info)
		}
		if journal.PendingKey != nil {
			if credentialStores == nil {
				return vault.ErrPolicy
			}
			if err := retireLegacyCredentialKey(reader, logical, document.VaultID, subkey, keyRows, *journal.PendingKey, owner, &state, &journal, credentialStores); err != nil {
				return err
			}
		}
		// Finish the persisted intent first. A previously completed file may
		// reappear after an uncertain filesystem outcome while another file's
		// intent is pending; never overwrite that pending recovery payload.
		order := make([]int, 0, len(specs))
		if journal.Pending != nil {
			order = append(order, journal.Pending.Index)
		}
		for i := range specs {
			if journal.Pending == nil || i != journal.Pending.Index {
				order = append(order, i)
			}
		}
		for _, i := range order {
			spec := specs[i]
			if err := ctx.Err(); err != nil {
				return err
			}
			protected, err := readLegacyInventoryFile(spec.path, spec.maximum)
			absent := errors.Is(err, os.ErrNotExist)
			if err != nil && !absent {
				return errVaultMigrationSource
			}
			if absent && (i < journal.Completed || (journal.Pending != nil && journal.Pending.Index == i)) {
				if journal.Pending == nil || journal.Pending.Index != i {
					continue
				}
			} else if absent {
				return vault.ErrAuthentication
			}
			if !absent && !matchesLegacyRetirementFile(subkey, logical, inventory.Files[i], protected) {
				vault.Wipe(protected)
				return vault.ErrAuthentication
			}
			if journal.Pending != nil && journal.Pending.Index != i {
				vault.Wipe(protected)
				return vault.ErrAuthentication
			}
			if journal.Pending == nil {
				journal.Pending = &legacyRetirementFile{Index: i, Protected: protected}
				state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
				if err != nil {
					return err
				}
			} else {
				vault.Wipe(protected)
			}
			if !matchesLegacyRetirementFile(subkey, logical, inventory.Files[i], journal.Pending.Protected) {
				return vault.ErrAuthentication
			}
			keyPath := spec.path
			if spec.browser {
				keyPath = strings.TrimSuffix(keyPath, ".bak")
			}
			if err := retireKey(keyPath, journal.Pending.Protected); err != nil {
				return errVaultMigrationSource
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			// Recheck immediately before deletion; an uncertain outcome leaves the
			// durable intent and encrypted protected bytes available for retry.
			if !absent {
				again, err := readLegacyInventoryFile(spec.path, spec.maximum)
				match := err == nil && matchesLegacyRetirementFile(subkey, logical, inventory.Files[i], again)
				vault.Wipe(again)
				if !match {
					return vault.ErrAuthentication
				}
				if os.Remove(spec.path) != nil {
					return errVaultMigrationSource
				}
			}
			if syncPrivateFileDirectory(filepath.Dir(spec.path)) != nil {
				return errVaultMigrationSource
			}
			vault.Wipe(journal.Pending.Protected)
			journal.Pending = nil
			journal.Completed = max(journal.Completed, i+1)
			state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
			if err != nil {
				return err
			}
		}
		if credentialStores != nil {
			if journal.Version == 1 {
				journal.Version = 2
				state, err = writeLegacyRetirementJournal(ctx, owner, document.VaultID, journal, state.RowVersion)
				if err != nil {
					return err
				}
			}
			for i := range keyRows {
				if err := retireLegacyCredentialKey(reader, logical, document.VaultID, subkey, keyRows, i, owner, &state, &journal, credentialStores); err != nil {
					return err
				}
			}
		}
		if credentialStores != nil && inventory.Browser != nil {
			if filepath.Clean(userData) != inventory.Browser.UserData {
				return vault.ErrAuthentication
			}
			if err := retireLegacyBrowserProfiles(ctx, inventory.Browser, subkey, owner, &state, &journal, removeBrowser); err != nil {
				return err
			}
		}
		progress = legacyRetirementProgress{Files: journal.Completed, KeyReferences: journal.KeysCompleted}
		if journal.Browser != nil {
			progress.BrowserProfiles = journal.Browser.Completed
		}
		return verifyLegacyMigrationIdentity(reader, logical, info)
	})
	return progress, errors.Join(err, owner.Close())
}

func matchingRetirementGuard(key []byte, guard, stage vault.SlotFile) bool {
	if guard.Sequence != 1 || vault.VerifySlotFile(key, guard, stage.VaultID, stage.FileID, 1) != nil || guard.Migration == nil || guard.Migration.Phase != vault.MigrationRetiring {
		return false
	}
	guard.Sequence, guard.Authentication = stage.Sequence, nil
	stage.Authentication = nil
	a, _ := json.Marshal(guard)
	b, _ := json.Marshal(stage)
	return bytes.Equal(a, b)
}

func readLegacyRetirementJournal(ctx context.Context, owner *localvault.Owner, document vault.SlotFile, fileCount, keyCount int) (vaultstore.LocalState, legacyRetirementJournal, error) {
	state, err := owner.ReadLocalState(ctx, migrationRetirementKind, document.VaultID, 1)
	if err != nil {
		return state, legacyRetirementJournal{}, err
	}
	var result legacyRetirementJournal
	err = owner.WithLocalState(ctx, migrationRetirementKind, document.VaultID, state.RowVersion, func(raw []byte) error {
		if len(raw) < 8 || string(raw[:4]) != "WMR1" {
			return vault.ErrFormat
		}
		headerSize := int(binary.BigEndian.Uint32(raw[4:8]))
		if headerSize < 1 || headerSize > 4096 || headerSize > len(raw)-8 {
			return vault.ErrFormat
		}
		header := raw[8 : 8+headerSize]
		if json.Unmarshal(header, &result) != nil {
			return vault.ErrFormat
		}
		canonical, err := json.Marshal(result)
		defer vault.Wipe(canonical)
		payload := raw[8+headerSize:]
		if err != nil || !bytes.Equal(canonical, header) || (result.Version != 1 && result.Version != 2 && result.Version != 3 && result.Version != 4) || result.Binding != document.Migration.Binding || result.Completed < 0 || result.Completed > fileCount || (result.Pending == nil && len(payload) != 0) || (result.Pending != nil && (result.Pending.Index < 0 || result.Pending.Index > result.Completed || result.Pending.Index >= fileCount || len(payload) == 0)) {
			return vault.ErrFormat
		}
		if result.KeysCompleted < 0 || result.KeysCompleted > keyCount || (result.Version == 1 && (result.KeysCompleted != 0 || result.PendingKey != nil)) || (result.PendingKey != nil && (result.Pending != nil || *result.PendingKey < 0 || *result.PendingKey > result.KeysCompleted || *result.PendingKey >= keyCount)) {
			return vault.ErrFormat
		}
		if result.Version == 3 && result.SQL == nil || result.Version < 3 && result.SQL != nil || (result.Version == 4) != (result.Browser != nil) {
			return vault.ErrFormat
		}
		if result.Browser != nil && (result.Browser.Completed < 0 || result.Browser.Completed > maxMigrationBrowserProfiles || result.Browser.Pending != nil && (*result.Browser.Pending < 0 || *result.Browser.Pending > result.Browser.Completed || *result.Browser.Pending >= maxMigrationBrowserProfiles) || result.Completed != fileCount || result.KeysCompleted != keyCount || result.Pending != nil || result.PendingKey != nil || result.SQL != nil && result.Browser.Pending != nil) {
			return vault.ErrFormat
		}
		if result.SQL != nil && (len(result.SQL.Authentication) != 32 || (result.SQL.Phase != "pending" && result.SQL.Phase != "committed" && result.SQL.Phase != "compacted") || result.Completed != fileCount || result.KeysCompleted != keyCount || result.Pending != nil || result.PendingKey != nil) {
			return vault.ErrFormat
		}
		if result.Pending != nil {
			result.Pending.Protected = bytes.Clone(payload)
		}
		return nil
	})
	if err != nil && result.Pending != nil {
		vault.Wipe(result.Pending.Protected)
	}
	return state, result, err
}

func writeLegacyRetirementJournal(ctx context.Context, owner *localvault.Owner, workspace string, journal legacyRetirementJournal, expected uint64) (vaultstore.LocalState, error) {
	header, err := json.Marshal(journal)
	defer vault.Wipe(header)
	if err != nil || len(header) > 4096 {
		return vaultstore.LocalState{}, vault.ErrFormat
	}
	var payload []byte
	if journal.Pending != nil {
		payload = journal.Pending.Protected
	}
	if len(payload) > vaultstore.MaxLocalStateBytes-len(header)-8 {
		return vaultstore.LocalState{}, vault.ErrFormat
	}
	raw := make([]byte, 8+len(header)+len(payload))
	defer vault.Wipe(raw)
	copy(raw, "WMR1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	copy(raw[8:], header)
	copy(raw[8+len(header):], payload)
	return owner.PutLocalState(ctx, migrationRetirementKind, workspace, raw, expected)
}

func readLegacyRetirementInventory(ctx context.Context, owner *localvault.Owner, document vault.SlotFile, source string) (legacySourceInventory, []legacyLocalStateFile, []legacyInventoryRow, error) {
	var inventory legacySourceInventory
	err := owner.WithLocalState(ctx, migrationSourceInventoryKind, document.VaultID, 1, func(raw []byte) error {
		if json.Unmarshal(raw, &inventory) != nil {
			return vault.ErrFormat
		}
		canonical, err := json.Marshal(inventory)
		defer vault.Wipe(canonical)
		if err != nil || !bytes.Equal(canonical, raw) || inventory.Version != 2 || inventory.WorkspaceID != document.VaultID || inventory.Source != source || len(inventory.DatabaseMAC) != 32 || inventory.Files == nil || inventory.Secrets == nil {
			return vault.ErrFormat
		}
		return nil
	})
	if err != nil {
		return inventory, nil, nil, err
	}
	if inventory.Browser != nil && validateLegacyBrowserInventory(inventory.Browser, document.VaultID) != nil {
		return inventory, nil, nil, vault.ErrFormat
	}
	specs := make([]legacyLocalStateFile, len(inventory.Files))
	for i, file := range inventory.Files {
		spec, err := legacyRetirementFileSpec(source, document.VaultID, file)
		if err != nil || (i > 0 && (inventory.Files[i-1].Kind > file.Kind || (inventory.Files[i-1].Kind == file.Kind && inventory.Files[i-1].ScopeID >= file.ScopeID))) {
			return inventory, nil, nil, vault.ErrFormat
		}
		specs[i] = spec
	}
	keys, err := legacyRetirementKeyRows(inventory.Secrets)
	return inventory, specs, keys, err
}

func legacyRetirementFileSpec(source, workspace string, file legacyInventoryFile) (legacyLocalStateFile, error) {
	if len(file.Authentication) != 32 || file.Bytes <= 0 {
		return legacyLocalStateFile{}, vault.ErrFormat
	}
	for _, spec := range legacyLocalStateFiles(source, workspace) {
		if file.Kind == spec.kind && file.ScopeID == spec.scope && int64(file.Bytes) <= spec.maximum {
			return spec, nil
		}
	}
	id, err := uuid.Parse(file.ScopeID)
	if err != nil || id == uuid.Nil || id.String() != file.ScopeID {
		return legacyLocalStateFile{}, vault.ErrFormat
	}
	for _, directory := range legacyInventoryDirectories(source, workspace) {
		if file.Kind == directory.kind && int64(file.Bytes) <= directory.maximum {
			return legacyLocalStateFile{path: filepath.Join(directory.path, strings.ReplaceAll(file.ScopeID, "-", "")+directory.suffix), kind: file.Kind, scope: file.ScopeID, maximum: directory.maximum, required: true}, nil
		}
	}
	return legacyLocalStateFile{}, vault.ErrFormat
}

func matchesLegacyRetirementFile(key []byte, source string, file legacyInventoryFile, protected []byte) bool {
	expected := file.Authentication
	file.Authentication = nil
	actual, err := legacyInventoryMAC(key, source, file, protected)
	return err == nil && len(protected) == file.Bytes && hmac.Equal(expected, actual)
}

func rejectNewLegacyRetirementFiles(reader resolverCaptureReader, source, workspace string, specs []legacyLocalStateFile) error {
	allowed := map[string]bool{}
	for _, spec := range specs {
		allowed[spec.path] = true
	}
	check := func(path string) error {
		if !allowed[path] {
			return vault.ErrAuthentication
		}
		return nil
	}
	for _, spec := range legacyLocalStateFiles(source, workspace) {
		if _, err := os.Lstat(spec.path); err == nil {
			if err := check(spec.path); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errVaultMigrationSource
		}
	}
	for _, directory := range legacyInventoryDirectories(source, workspace) {
		if err := visitLegacyLocalDirectory(reader, directory.path, directory.suffix, func(path, _ string) error { return check(path) }); err != nil {
			return err
		}
	}
	return nil
}
