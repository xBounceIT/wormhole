package main

import (
	"context"
	"os"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// A synchronous, native-only capability borrowed by successive migration phases.
// It owns all source and stage locks until the callback returns. It contains no
// key, is never an IPC value, and becomes invalid before any lock is released.
type legacyVaultMigrationOwnership struct {
	source string
	stage  string
	active atomic.Bool
}

func withLegacyVaultMigrationOwnership(ctx context.Context, source, fileID string, run func(*legacyVaultMigrationOwnership) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id, err := uuid.Parse(fileID)
	if err != nil || id == uuid.Nil || id.String() != fileID || run == nil {
		return vault.ErrFormat
	}
	canonical, info, err := legacyVaultSourceIdentity(source)
	if err != nil {
		return err
	}
	release, err := lockLegacyVaultSource(ctx, canonical)
	if err != nil {
		return err
	}
	defer release()
	stage := canonical + ".migrating-" + fileID
	releaseStage, err := tryAcquireExclusiveFileLock(stage + ".vault.lock")
	if err != nil {
		return errVaultSlotConflict
	}
	defer releaseStage()
	current, currentInfo, err := legacyVaultSourceIdentity(source)
	if err != nil || current != canonical || !os.SameFile(info, currentInfo) {
		return errVaultMigrationSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ownership := &legacyVaultMigrationOwnership{source: canonical, stage: stage}
	ownership.active.Store(true)
	defer ownership.active.Store(false)
	return run(ownership)
}

func lockLegacyMigrationSourceOwned(ctx context.Context, source string, ownership *legacyVaultMigrationOwnership) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ownership == nil {
		return lockLegacyVaultSource(ctx, source)
	}
	if !ownership.active.Load() || ownership.source != source {
		return nil, vault.ErrPolicy
	}
	return func() {}, nil
}

func lockLegacyMigrationStageOwned(ctx context.Context, stage string, ownership *legacyVaultMigrationOwnership) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ownership == nil {
		return tryAcquireExclusiveFileLock(stage + ".vault.lock")
	}
	if !ownership.active.Load() || ownership.stage != stage {
		return nil, vault.ErrPolicy
	}
	return func() {}, nil
}
