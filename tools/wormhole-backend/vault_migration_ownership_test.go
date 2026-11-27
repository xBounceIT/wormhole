package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestVaultMigrationOwnershipIsScopedAndCannotRebind(t *testing.T) {
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "legacy.db")
	if err := os.WriteFile(source, []byte("native identity fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var borrowed *legacyVaultMigrationOwnership
	stop := errors.New("phase failure")
	err := withLegacyVaultMigrationOwnership(ctx, source, uuid.NewString(), func(ownership *legacyVaultMigrationOwnership) error {
		borrowed = ownership
		for _, acquire := range []func() (func(), error){
			func() (func(), error) { return lockLegacyMigrationSourceOwned(ctx, ownership.source, ownership) },
			func() (func(), error) { return lockLegacyMigrationStageOwned(ctx, ownership.stage, ownership) },
		} {
			release, err := acquire()
			if err != nil {
				t.Fatal("owned phase reacquired its own lock", err)
			}
			release()
		}
		if _, err := lockLegacyMigrationSourceOwned(ctx, source+".other", ownership); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal("borrowed source could be rebound", err)
		}
		if _, err := lockLegacyMigrationStageOwned(ctx, ownership.stage+".other", ownership); !errors.Is(err, vault.ErrPolicy) {
			t.Fatal("borrowed stage could be rebound", err)
		}
		if release, err := acquireWorkspaceOwnership(source, true); err == nil {
			release()
			t.Fatal("phase-local cleanup released outer ownership")
		}
		return stop
	})
	if !errors.Is(err, stop) || borrowed == nil {
		t.Fatal(err)
	}
	if _, err := lockLegacyMigrationSourceOwned(ctx, borrowed.source, borrowed); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("expired source capability accepted", err)
	}
	if _, err := lockLegacyMigrationStageOwned(ctx, borrowed.stage, borrowed); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("expired stage capability accepted", err)
	}
	for _, acquire := range []func() (func(), error){
		func() (func(), error) { return lockLegacyMigrationSourceOwned(ctx, source, nil) },
		func() (func(), error) { return lockLegacyMigrationStageOwned(ctx, borrowed.stage, nil) },
	} {
		release, err := acquire()
		if err != nil {
			t.Fatal("outer locks leaked after failure", err)
		}
		release()
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := lockLegacyMigrationSourceOwned(cancelled, source, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := lockLegacyMigrationStageOwned(cancelled, source, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestVaultMigrationOwnershipAdmissionAndPartialAcquisition(t *testing.T) {
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "legacy.db")
	if err := os.WriteFile(source, nil, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(*legacyVaultMigrationOwnership) error { return nil }
	for _, id := range []string{"", "../stage", uuid.Nil.String()} {
		if err := withLegacyVaultMigrationOwnership(ctx, source, id, run); !errors.Is(err, vault.ErrFormat) {
			t.Fatal("invalid stage id admitted", err)
		}
	}
	id := uuid.NewString()
	if err := withLegacyVaultMigrationOwnership(ctx, source, id, nil); !errors.Is(err, vault.ErrFormat) {
		t.Fatal(err)
	}
	if err := withLegacyVaultMigrationOwnership(ctx, source+".missing", id, run); err == nil {
		t.Fatal("missing source admitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := withLegacyVaultMigrationOwnership(cancelled, source, id, run); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, lock := range []string{filepath.Join(filepath.Dir(source), ".workspace-owner.lock"), source + ".migrating-" + id + ".vault.lock"} {
		release, err := tryAcquireExclusiveFileLock(lock)
		if err != nil {
			t.Fatal(err)
		}
		called := false
		err = withLegacyVaultMigrationOwnership(ctx, source, id, func(*legacyVaultMigrationOwnership) error { called = true; return nil })
		release()
		if err == nil || called {
			t.Fatal("contended migration admitted", err)
		}
		if err := withLegacyVaultMigrationOwnership(ctx, source, id, run); err != nil {
			t.Fatal("partial acquisition leaked locks", err)
		}
	}
}
