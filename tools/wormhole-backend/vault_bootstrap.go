package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

var errVaultOwnerRequired = errors.New("vault_owner_required")

// Presence, not successful parsing, disables legacy access. A damaged slot file
// must never restore DPAPI/keychain readers or trigger legacy startup migrations.
func requireLegacyWorkspace(databasePath string) error {
	if err := requireLegacySlotAbsent(databasePath); err != nil {
		return err
	}
	return requireNoLegacyMigrationSetup(databasePath)
}

func requireNoLegacyMigrationSetup(databasePath string) error {
	// An interrupted migration remains quarantined even if its source marker
	// is lost or removed. Never trust an unauthenticated stage phase to re-enable
	// legacy secrets. The authenticated migration coordinator uses its separate
	// admission below so it can resume/rebuild copy phases under ownership.
	directory, err := os.Open(filepath.Dir(databasePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errVaultOwnerRequired
	}
	defer directory.Close()
	prefix := filepath.Base(databasePath) + ".migrating-"
	for count := 0; ; {
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return errVaultOwnerRequired
		}
		for _, entry := range entries {
			count++
			if count > 32768 {
				return errVaultOwnerRequired
			}
			name := entry.Name()
			matches := strings.HasPrefix(name, prefix) && (strings.HasSuffix(name, ".slots") || strings.HasSuffix(name, ".setup"))
			if runtime.GOOS == "windows" {
				p, n := []rune(prefix), []rune(name)
				matches = len(n) >= len(p)+6 && strings.EqualFold(string(n[:len(p)]), prefix) && (strings.EqualFold(string(n[len(n)-6:]), ".slots") || strings.EqualFold(string(n[len(n)-6:]), ".setup"))
			}
			if matches {
				return errVaultOwnerRequired
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// Only migration code with authenticated stage authority may bypass stage-file
// quarantine. A source slot marker still forbids rebuilding after retirement.
func requireLegacySlotAbsent(databasePath string) error {
	if requireNoLocalBackupInstall(databasePath) != nil {
		return errVaultOwnerRequired
	}
	if requireNoRootRotation(databasePath) != nil {
		return errVaultOwnerRequired
	}
	if err := requireNoSharedWorkspace(databasePath); err != nil {
		return err
	}
	_, err := os.Lstat(vaultSlotPath(databasePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errVaultOwnerRequired
}

func localVaultOptions(document vault.SlotFile) localvault.OpenOptions {
	return localvault.OpenOptions{
		Identity: vaultstore.Identity{WorkspaceID: document.VaultID, FileID: document.FileID, Root: vaultstore.KeyRef{ID: document.RootKeyID, Version: document.RootKeyVersion}},
		Slots:    document, MinimumSequence: document.Sequence, RequireLocked: true,
	}
}

func requireNewVaultWorkspace(databasePath string) error {
	if err := requireNoLocalBackupInstall(databasePath); err != nil {
		return err
	}
	if err := requireNoRootRotation(databasePath); err != nil {
		return err
	}
	if err := requireNoSharedWorkspace(databasePath); err != nil {
		return err
	}
	if err := requireNoLegacyMigrationSetup(databasePath); err != nil {
		return err
	}
	if _, err := os.Lstat(databasePath); !errors.Is(err, os.ErrNotExist) {
		return vaultstore.ErrConflict
	}
	if _, err := os.Lstat(vaultSlotPath(databasePath)); !errors.Is(err, os.ErrNotExist) {
		return errVaultSlotConflict
	}
	return nil
}

// The vault process holds the workspace ownership lock around these operations.
// This creates only a new empty workspace. Migrating an existing app database is
// a separate journaled operation and must not overwrite it through this path.
func initializeVaultFiles(ctx context.Context, databasePath string, document vault.SlotFile, key []byte) (*localvault.Owner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !document.Initializing || document.Sequence != 1 {
		return nil, vault.ErrFormat
	}
	if err := requireNewVaultWorkspace(databasePath); err != nil {
		return nil, err
	}
	if err := writeVaultSlotFile(databasePath, key, document, 0); err != nil {
		return nil, err
	}
	stored, err := readVaultSlotFile(databasePath)
	if err != nil {
		return nil, err
	}
	return openVaultFiles(ctx, databasePath, stored, key)
}

func vaultStagingPath(databasePath string, document vault.SlotFile) string {
	return databasePath + ".creating-" + document.FileID
}

// Only called after authenticating the initializing marker. The UUID-bound
// staging name cannot escape the workspace directory; no recursive cleanup.
func removeVaultStaging(path string) error {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		file := path + suffix
		info, err := os.Lstat(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errVaultSlotStorage
		}
		if err := os.Remove(file); err != nil {
			return errVaultSlotStorage
		}
	}
	return nil
}

func openVaultFiles(ctx context.Context, databasePath string, document vault.SlotFile, key []byte) (*localvault.Owner, error) {
	if err := requireNoRootRotation(databasePath); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := vault.VerifySlotFile(key, document, document.VaultID, document.FileID, document.Sequence); err != nil {
		return nil, err
	}
	options := localVaultOptions(document)
	// A normal local owner can report optional page-lock failure. The owner still
	// requires locked memory for encrypted SQLite and rejects stricter policies.
	// Migration and rotation staging use the required-lock options directly.
	options.RequireLocked = false
	if !document.Initializing {
		return localvault.Open(ctx, databasePath, options, bytes.Clone(key))
	}
	if document.Sequence != 1 {
		return nil, vault.ErrPolicy
	}
	absolute, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, errVaultSlotStorage
	}
	stage := vaultStagingPath(absolute, document)
	if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		// No domain write is possible before initialization completes. A torn
		// staging file can therefore be rebuilt after authenticating this marker.
		if err := removeVaultStaging(stage); err != nil {
			return nil, err
		}
		// Authentication above is sufficient to create this empty schema. No
		// native key owner is needed until publication and final identity check.
		var staged *vaultstore.SQLite
		if document.Encrypted {
			staged, err = vaultstore.OpenSQLiteEncrypted(ctx, stage, options.Identity, true, key)
		} else {
			staged, err = vaultstore.OpenSQLite(ctx, stage, options.Identity, true)
		}
		if err != nil {
			return nil, err
		}
		if err := staged.Close(); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(stage, os.O_RDWR, 0)
		if err != nil {
			return nil, errVaultSlotStorage
		}
		flushErr := file.Sync()
		closeErr := file.Close()
		if flushErr != nil || closeErr != nil {
			return nil, errVaultSlotStorage
		}
		// Atomic no-replace publication: a late-created legacy file is preserved.
		if err := publishVaultFile(stage, absolute); err != nil {
			return nil, errVaultSlotCommitUncertain
		}
		if err := privateFileDirectorySync(filepath.Dir(absolute)); err != nil {
			return nil, errVaultSlotCommitUncertain
		}
	} else if err != nil {
		return nil, errVaultSlotStorage
	}
	options.Create = false
	owner, err := localvault.Open(ctx, absolute, options, bytes.Clone(key))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*localvault.Owner, error) { return nil, errors.Join(err, owner.Close()) }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	// Check the published DB identity before finalizing the authenticated marker.
	// A crash here resumes this same branch; an unrelated DB is never repaired.
	if err := removeVaultStaging(stage); err != nil {
		return fail(err)
	}
	document.Initializing = false
	policy, err := owner.ReadLocalPolicy(ctx)
	if err != nil {
		return fail(err)
	}
	document.ProfileSequence = policy.Policy.Sequence
	document.Sequence++
	if err := writeVaultSlotFile(absolute, key, document, 1); err != nil {
		return fail(err)
	}
	return owner, nil
}
