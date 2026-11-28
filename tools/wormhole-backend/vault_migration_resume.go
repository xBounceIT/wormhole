package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Only a main-owned restart with isolated Chromium storage may grant quiescence.
// An ordinary unlock, a renderer-supplied field or a pending enrollment cannot.
// No ordinary owner exists before all migration phases and cleanup succeed.
func (h *vaultFoundationHandler) resumeMigration(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if !h.migrationQuiesced || h.owner != nil || h.shared != nil || h.enrollment != nil || h.databasePath == "" {
		return nil, vaultwire.ErrProtocol
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	input, err := decodeVaultUnlock(payload)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil || floor != vault.Default && floor != vault.Standard {
		return nil, vault.ErrPolicy
	}
	hint, err := discoverLegacyMigrationSetup(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	if hint == nil {
		return nil, vault.ErrAuthentication
	}
	key, err := openVaultUnlockFactor(ctx, hint.Document, &input)
	defer vault.Wipe(key)
	if err != nil {
		return nil, err
	}
	locked, err := securemem.New(len(key), true)
	if err != nil {
		return nil, err
	}
	err = locked.With(func(storage []byte) error {
		copy(storage, key)
		vault.Wipe(key)
		return h.resumeMigrationKey(ctx, hint, storage)
	})
	if closeErr := locked.Close(); closeErr != nil {
		return nil, h.retire(errors.Join(err, closeErr))
	}
	if err != nil {
		return nil, err
	}
	return marshalLocalVaultUnlock(h.owner)
}

func (h *vaultFoundationHandler) resumeMigrationKey(ctx context.Context, hint *legacyMigrationSetupHint, key []byte) error {
	return h.resumeMigrationKeyGuarded(ctx, hint, key, nil)
}

// A native OS-target guard revalidates its sole durable root custody before
// crossing destructive boundaries. No caller-supplied policy or path is used.
func (h *vaultFoundationHandler) resumeMigrationKeyGuarded(ctx context.Context, hint *legacyMigrationSetupHint, key []byte, custody func() error) error {
	step := func(string) error {
		if custody != nil {
			return custody()
		}
		return ctx.Err()
	}
	if err := step(""); err != nil {
		return err
	}
	setup, err := readLegacyMigrationSetup(ctx, hint.CanonicalSource, hint.Document, key)
	if err != nil {
		return err
	}
	if setup.UserData != h.userDataPath {
		return vault.ErrAuthentication
	}
	current, err := readVaultSlotFile(hint.CanonicalSource)
	if err != nil && !errors.Is(err, errVaultSlotMissing) {
		return err
	}
	// Publishing may already have moved the source away. It owns that recovery
	// window; the copy coordinator must never try to rebuild it from legacy data.
	if errors.Is(err, errVaultSlotMissing) || current.Migration != nil && current.Migration.Phase != vault.MigrationPublishing {
		if _, err := continueLegacyVaultMigrationWith(ctx, setup.LogicalSource, setup.UserData, setup.Initial, key, setup.Plan, step); err != nil {
			return h.retire(err)
		}
	}
	publication, err := publishLegacyVaultMigrationWith(ctx, setup.LogicalSource, setup.UserData, setup.Initial, key, setup.Plan, step)
	if err != nil {
		return h.retire(err)
	}
	// Adopt every part of the publication. Even cleanup failure retains the
	// exclusion and owner for shutdown retry, while the process is retired.
	h.owner, h.releaseWorkspace, h.databasePath = publication.owner, publication.releaseWorkspace, publication.canonicalSource
	if err := removeLegacyMigrationSetup(ctx, setup, key); err != nil {
		return h.retire(err)
	}
	return nil
}

func removeLegacyMigrationSetup(ctx context.Context, setup legacyMigrationSetup, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := openLegacyPublicationFS(filepath.Dir(setup.CanonicalSource))
	if err != nil {
		return err
	}
	defer f.root.Close()
	path := legacyMigrationSetupPath(setup.CanonicalSource, setup.Initial.FileID)
	before, err := f.lstat(path)
	if err != nil {
		return err
	}
	// Authenticate the exact capsule again before removing the durable retry
	// authority; a foreign or modified file must never be silently discarded.
	if _, err := readLegacyMigrationSetup(ctx, setup.CanonicalSource, setup.Initial, key); err != nil {
		return err
	}
	current, err := f.lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, current) {
		return vault.ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.verify(); err != nil {
		return err
	}
	name, err := f.relative(path)
	if err != nil {
		return err
	}
	if f.root.Remove(name) != nil || syncLegacyPublicationRoot(f.root) != nil {
		return errVaultSlotStorage
	}
	return f.verify()
}
