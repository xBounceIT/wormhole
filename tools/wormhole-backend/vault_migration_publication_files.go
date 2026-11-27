package main

import (
	"context"
	"crypto/hmac"
	"errors"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func finishLegacyPublicationFiles(ctx context.Context, logical, userData, source, stage string, initial, guard vault.SlotFile, key []byte, binding string, step func(string) error, f *legacyPublicationFS) error {
	if err := f.verify(); err != nil {
		return err
	}
	if guard.Migration == nil || guard.Migration.Phase != vault.MigrationPublishing {
		return vault.ErrPolicy
	}
	backup := source + ".retired-" + guard.FileID
	stagePresent, err := legacyPublicationPresent(stage, f)
	if err != nil {
		return err
	}
	backupPresent, err := legacyPublicationPresent(backup, f)
	if err != nil {
		return err
	}
	sourcePresent, err := legacyPublicationPresent(source, f)
	if err != nil {
		return err
	}
	markerPresent, err := legacyPublicationPresent(vaultSlotPath(stage), f)
	if err != nil {
		return err
	}
	if markerPresent {
		marker, err := f.readSlots(stage)
		if err != nil || !matchingLegacyMigrationSetup(key, initial, marker, binding) {
			return vault.ErrAuthentication
		}
	}
	if stagePresent {
		if err := verifyLegacyPublicationFile(ctx, stage, guard, key, guard.Migration.Snapshot, f); err != nil {
			return err
		}
	}
	if backupPresent {
		if err := verifyLegacyPublicationFile(ctx, backup, guard, key, guard.Migration.SourceSnapshot, f); err != nil {
			return err
		}
	}
	sourceFinal := sourcePresent && verifyLegacyPublicationFile(ctx, source, guard, key, guard.Migration.Snapshot) == nil
	if sourcePresent && !sourceFinal {
		if err := verifyLegacyPublicationFile(ctx, source, guard, key, guard.Migration.SourceSnapshot, f); err != nil {
			return err
		}
	}
	if !sourceFinal {
		if !stagePresent || !markerPresent || !sourcePresent && !backupPresent {
			return vault.ErrAuthentication
		}
		ready, err := readLegacyPublicationCheckpoint(ctx, stage, logical, userData, binding, guard, key, f)
		if err != nil {
			return err
		}
		if !sameLegacyPublicationFloors(ready, guard) {
			return vault.ErrRollback
		}
		if err := verifyLegacyPublicationFile(ctx, stage, guard, key, guard.Migration.Snapshot, f); err != nil {
			return err
		}
		if sourcePresent {
			if backupPresent {
				from, aErr := f.lstat(source)
				to, bErr := f.lstat(backup)
				if aErr != nil || bErr != nil || !os.SameFile(from, to) {
					return vault.ErrAuthentication
				}
				if err := removeLegacyPublicationFile(ctx, source, guard, key, guard.Migration.SourceSnapshot, f); err != nil {
					return err
				}
			} else if err := moveLegacyPublicationFile(ctx, source, backup, f); err != nil {
				return err
			}
		}
		if err := step("source-retired"); err != nil {
			return err
		}
		if err := moveLegacyPublicationFile(ctx, stage, source, f); err != nil {
			return err
		}
		if err := step("database-published"); err != nil {
			return err
		}
	}
	ready, err := readLegacyPublicationCheckpoint(ctx, source, logical, userData, binding, guard, key, f)
	if err != nil {
		return err
	}
	if !sameLegacyPublicationFloors(ready, guard) {
		return vault.ErrRollback
	}
	if err := verifyLegacyPublicationFile(ctx, source, guard, key, guard.Migration.Snapshot, f); err != nil {
		return err
	}
	for _, file := range []struct {
		path     string
		snapshot *vault.MigrationSnapshot
	}{{stage, guard.Migration.Snapshot}, {backup, guard.Migration.SourceSnapshot}} {
		if err := removeLegacyPublicationFile(ctx, file.path, guard, key, file.snapshot, f); err != nil {
			return err
		}
	}
	if err := step("source-removed"); err != nil {
		return err
	}
	if markerPresent {
		release, err := tryAcquireExclusiveFileLock(vaultSlotPath(stage) + ".lock")
		if err != nil {
			return errVaultSlotConflict
		}
		defer release()
		before, statErr := f.lstat(vaultSlotPath(stage))
		marker, err := f.readSlots(stage)
		current, currentErr := f.lstat(vaultSlotPath(stage))
		if statErr != nil || currentErr != nil || err != nil || !os.SameFile(before, current) || !matchingLegacyMigrationSetup(key, initial, marker, binding) {
			return vault.ErrAuthentication
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := f.relative(vaultSlotPath(stage))
		if err != nil {
			return err
		}
		if f.root.Remove(name) != nil || syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
			return errVaultSlotCommitUncertain
		}
	}
	if err := verifyLegacyPublicationFile(ctx, source, guard, key, guard.Migration.Snapshot, f); err != nil {
		return err
	}
	return step("stage-removed")
}

func verifyLegacyPublicationFile(ctx context.Context, path string, document vault.SlotFile, key []byte, expected *vault.MigrationSnapshot, supplied ...*legacyPublicationFS) error {
	f, release, err := borrowLegacyPublicationFS(path, supplied)
	if err != nil {
		return err
	}
	defer release()
	if expected == nil {
		return vault.ErrPolicy
	}
	actual, err := vaultMigrationDatabaseDigestExpected(ctx, path, document, key, false, expected, f.root)
	if err != nil {
		return err
	}
	if actual.Bytes != expected.Bytes || !hmac.Equal(actual.Authentication, expected.Authentication) {
		return vault.ErrAuthentication
	}
	return nil
}

// No overwrite or recursive deletion: a crash between POSIX link/unlink leaves
// authenticated duplicates, which the next invocation can distinguish from an
// unrelated late-created file. Windows uses the root-relative no-replace adapter.
func moveLegacyPublicationFile(ctx context.Context, from, to string, supplied ...*legacyPublicationFS) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, release, err := borrowLegacyPublicationFS(from, supplied)
	if err != nil {
		return err
	}
	defer release()
	oldname, err := f.relative(from)
	if err != nil {
		return err
	}
	newname, err := f.relative(to)
	if err != nil {
		return err
	}
	if err := renameLegacyPublicationRootFile(f.root, oldname, newname, false); err != nil {
		return errVaultSlotCommitUncertain
	}
	if syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
		return errVaultSlotCommitUncertain
	}
	return nil
}

func removeLegacyPublicationFile(ctx context.Context, path string, document vault.SlotFile, key []byte, expected *vault.MigrationSnapshot, supplied ...*legacyPublicationFS) error {
	f, release, err := borrowLegacyPublicationFS(path, supplied)
	if err != nil {
		return err
	}
	defer release()
	before, err := f.lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !before.Mode().IsRegular() {
		return errVaultSlotStorage
	}
	if err := verifyLegacyPublicationFile(ctx, path, document, key, expected, f); err != nil {
		return err
	}
	current, err := f.lstat(path)
	if err != nil || !os.SameFile(before, current) || !current.Mode().IsRegular() {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := f.relative(path)
	if err != nil {
		return err
	}
	if f.root.Remove(name) != nil || syncLegacyPublicationRoot(f.root) != nil || f.verify() != nil {
		return errVaultSlotCommitUncertain
	}
	return nil
}
