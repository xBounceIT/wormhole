package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type legacyVaultPublication struct {
	owner            *localvault.Owner
	releaseWorkspace func()
	canonicalSource  string
}

func (p *legacyVaultPublication) close() error {
	if err := p.owner.Close(); err != nil {
		return err // Do not release exclusion after an uncertain native close.
	}
	p.releaseWorkspace()
	return nil
}

// Fresh-authenticated, native-only cutover. A successful continuation adopts
// the owner, its canonical path and its workspace
// exclusion. The original logical path remains only historical migration data.
func publishLegacyVaultMigration(ctx context.Context, source, userData string, initial vault.SlotFile, key []byte, plan resolver.MigrationPlan) (*legacyVaultPublication, error) {
	return publishLegacyVaultMigrationWith(ctx, source, userData, initial, key, plan, nil)
}

func publishLegacyVaultMigrationWith(ctx context.Context, source, userData string, initial vault.SlotFile, key []byte, plan resolver.MigrationPlan, checkpoint func(string) error) (result *legacyVaultPublication, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plan.Validate() != nil || plan.WorkspaceID != initial.VaultID || initial.Sequence != 1 || initial.Initializing || initial.Encrypted || initial.Migration != nil || len(initial.Nodes) != 0 || !filepath.IsAbs(source) || filepath.Clean(source) != source || !legacyPublicationFilename(filepath.Base(source)) || !filepath.IsAbs(userData) || filepath.Clean(userData) != userData {
		return nil, vault.ErrFormat
	}
	raw, err := vault.EncodeSlotFile(key, initial)
	if err != nil {
		return nil, err
	}
	initial, err = vault.DecodeSlotFile(raw)
	if err != nil {
		return nil, err
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		return nil, errVaultMigrationSource
	}
	canonical := filepath.Join(directory, filepath.Base(source))
	f, err := openLegacyPublicationFS(directory)
	if err != nil {
		return nil, err
	}
	defer f.root.Close()
	canonical, err = f.canonicalSource(source)
	if err != nil {
		return nil, err
	}
	releaseWorkspace, err := acquireWorkspaceOwnership(canonical, true)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			releaseWorkspace()
		}
	}()
	releaseStores, err := lockLegacyVaultSourceStores(ctx, canonical)
	if err != nil {
		return nil, err
	}
	defer releaseStores()
	stage := canonical + ".migrating-" + initial.FileID
	releaseStage, err := tryAcquireExclusiveFileLock(stage + ".vault.lock")
	if err != nil {
		return nil, errVaultSlotConflict
	}
	defer releaseStage()
	ownership := &legacyVaultMigrationOwnership{source: canonical, stage: stage}
	ownership.active.Store(true)
	defer ownership.active.Store(false)
	binding, err := legacyVaultStageBinding(key, initial.VaultID, canonical, source, plan)
	if err != nil {
		return nil, err
	}
	guard, err := f.readSlots(canonical)
	if err != nil {
		return nil, err
	}
	if !matchingLegacyPublicationSetup(key, initial, guard, binding) {
		return nil, vault.ErrAuthentication
	}
	if guard.Migration != nil && guard.Migration.Phase == vault.MigrationRetiring {
		document, err := f.readSlots(stage)
		if err != nil {
			return nil, err
		}
		if !matchingLegacyMigrationSetup(key, initial, document, binding) || !matchingRetirementGuard(key, guard, document) {
			return nil, vault.ErrAuthentication
		}
		// Renew logical SQL/source checks before preparing a new closed snapshot.
		if err := f.verify(); err != nil {
			return nil, err
		}
		if err := retireLegacyVaultSQLOwned(ctx, source, stage, key, openMigrationCredentialStore, nil, ownership); err != nil {
			return nil, err
		}
		next, err := readLegacyPublicationCheckpoint(ctx, stage, source, userData, binding, document, key, f)
		if err != nil {
			return nil, err
		}
		finalSnapshot, err := vaultMigrationDatabaseDigestExpected(ctx, stage, document, key, true, nil, f.root)
		if err != nil {
			return nil, err
		}
		finalSnapshot.ContentAuthentication = bytes.Clone(document.Migration.Snapshot.ContentAuthentication)
		oldSnapshot, err := vaultMigrationDatabaseDigestExpected(ctx, canonical, guard, key, true, nil, f.root)
		if err != nil {
			return nil, err
		}
		next.Sequence = guard.Sequence + 1
		next.Migration = &vault.LocalMigration{Binding: binding, Phase: vault.MigrationPublishing, Snapshot: finalSnapshot, SourceSnapshot: oldSnapshot}
		if err := writeLegacyPublicationSlots(canonical, key, guard, next, f); err != nil {
			return nil, err
		}
		guard, err = f.readSlots(canonical)
		if err != nil {
			return nil, err
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
	if guard.Migration != nil {
		if err := step("intent"); err != nil {
			return nil, err
		}
		if err := finishLegacyPublicationFiles(ctx, source, userData, canonical, stage, initial, guard, key, binding, step, f); err != nil {
			return nil, err
		}
		next := guard
		next.Sequence++
		next = vault.MigrationSlotFile(next, nil)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writeLegacyPublicationSlots(canonical, key, guard, next, f); err != nil {
			return nil, err
		}
		guard, err = f.readSlots(canonical)
		if err != nil {
			return nil, err
		}
		if err := step("slots-published"); err != nil {
			return nil, err
		}
	} else {
		for _, path := range []string{stage, vaultSlotPath(stage), canonical + ".retired-" + initial.FileID} {
			present, err := legacyPublicationPresent(path, f)
			if err != nil || present {
				return nil, vault.ErrPolicy
			}
		}
	}
	// Also authenticate an already-finished crash retry against its sealed journal.
	ready, err := readLegacyPublicationCheckpoint(ctx, canonical, source, userData, binding, guard, key, f)
	if err != nil {
		return nil, err
	}
	if !sameLegacyPublicationFloors(ready, guard) {
		return nil, vault.ErrRollback
	}
	owner, err := openVaultFiles(ctx, canonical, guard, key)
	if err != nil {
		return nil, err
	}
	if err := f.verify(); err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	retained = true
	return &legacyVaultPublication{owner: owner, releaseWorkspace: sync.OnceFunc(releaseWorkspace), canonicalSource: canonical}, nil
}

func matchingLegacyPublicationSetup(key []byte, initial, current vault.SlotFile, binding string) bool {
	if vault.VerifySlotFile(key, current, initial.VaultID, initial.FileID, 1) != nil || current.ProfileSequence < initial.ProfileSequence {
		return false
	}
	if current.Migration != nil && (current.Migration.Binding != binding || current.Migration.Phase != vault.MigrationRetiring && current.Migration.Phase != vault.MigrationPublishing) {
		return false
	}
	current = vault.MigrationSlotFile(current, nil)
	current.Sequence, current.Authentication = 1, nil
	current.ProfileSequence, current.Nodes = initial.ProfileSequence, initial.Nodes
	initial.Authentication = nil
	a, _ := json.Marshal(initial)
	b, _ := json.Marshal(current)
	return bytes.Equal(a, b)
}

func sameLegacyPublicationFloors(a, b vault.SlotFile) bool {
	left, _ := json.Marshal(a.Nodes)
	right, _ := json.Marshal(b.Nodes)
	return a.ProfileSequence == b.ProfileSequence && bytes.Equal(left, right)
}

func legacyPublicationPresent(path string, supplied ...*legacyPublicationFS) (bool, error) {
	f, release, err := borrowLegacyPublicationFS(path, supplied)
	if err != nil {
		return false, err
	}
	defer release()
	info, err := f.lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return false, errVaultSlotStorage
	}
	return true, nil
}
