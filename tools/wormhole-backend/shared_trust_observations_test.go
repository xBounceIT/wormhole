package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedTrustObservationsSurviveFinalization(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "commit"}[commit], func(t *testing.T) {
			c, _, o, oldRoot, _, account, org := sharedPasswordFixture(t)
			if err := c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			current, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			newRoot := bytes.Repeat([]byte{99}, 32)
			original, err := stageSharedTrustRootTransition(o.TrustPath, oldRoot, newRoot, o.Binding, current.Revision)
			if err != nil {
				t.Fatal(err)
			}
			state := *account.State
			state.Sequence++
			state.Active = false
			state, err = vault.SignUserKeyState(state, org)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := original.ObserveAccount(o.Binding, state, current.WrappingRevision)
			if err != nil {
				t.Fatal(err)
			}
			syncDir := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDir })
			privateFileDirectorySync = func(string) error { return os.ErrPermission }
			if err := writeSharedTrustObservation(o.TrustPath, newRoot, o.Binding, original, observed); err != errSharedTrustCommitUncertain {
				t.Fatal(err)
			}
			privateFileDirectorySync = syncDir
			// Confirm the exact replacement even though the expected old journal is gone.
			if err := writeSharedTrustObservation(o.TrustPath, newRoot, o.Binding, original, observed); err != nil {
				t.Fatal(err)
			}
			if err := abortSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, observed); err != errSharedTrustConflict {
				t.Fatal("plain abort erased revocation", err)
			}
			if err := rollbackSharedTrustRootTransition(o.TrustPath, newRoot, bytes.Repeat([]byte{3}, 32), o.Binding, observed); err != errSharedTrustConflict {
				t.Fatal("wrong original root accepted", err)
			}
			finish := func(record sharedpg.TrustRootTransition) error {
				if commit {
					return promoteSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, record)
				}
				return rollbackSharedTrustRootTransition(o.TrustPath, newRoot, oldRoot, o.Binding, record)
			}
			privateFileDirectorySync = func(string) error { return os.ErrPermission }
			if err := finish(observed); err != errSharedTrustCommitUncertain {
				t.Fatal("replacement uncertainty lost", err)
			}
			privateFileDirectorySync = syncDir
			// A fresh authenticated update may arrive after destination replacement but
			// before journal removal; finalization must preserve the new observation too.
			state.Sequence++
			state.Active = true
			state, err = vault.SignUserKeyState(state, org)
			if err != nil {
				t.Fatal(err)
			}
			latest, err := observed.ObserveAccount(o.Binding, state, current.WrappingRevision)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeSharedTrustObservation(o.TrustPath, newRoot, o.Binding, observed, latest); err != nil {
				t.Fatal(err)
			}
			if err := finish(latest); err != nil {
				t.Fatal("intermediate destination not recovered", err)
			}
			if err := finish(latest); err != nil {
				t.Fatal("cleanup confirmation failed", err)
			}
			root := oldRoot
			floor := current.WrappingRevision
			if commit {
				root = newRoot
				floor++
			}
			restored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, current.Revision+1)
			if err != nil || restored.Account.Sequence != state.Sequence || !restored.Account.Active || restored.WrappingRevision != floor {
				t.Fatal("observation lost", err)
			}
			if _, err := os.Stat(sharedTrustTransitionPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("journal not removed")
			}
		})
	}
}

func TestSharedTrustObservationBoundaries(t *testing.T) {
	path, oldRoot, newRoot, b, current := sharedTransitionFixture(t)
	prepared, err := stageSharedTrustRootTransition(path, oldRoot, newRoot, b, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := prepared.ObserveAccount(b, *current.Account, current.WrappingRevision+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustObservation("relative", newRoot, b, prepared, observed); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	bad := observed
	bad.ID = uuid.New()
	if err := writeSharedTrustObservation(path, newRoot, b, prepared, bad); err == nil {
		t.Fatal("preparation replaced")
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	err = writeSharedTrustObservation(path, newRoot, b, prepared, observed)
	release()
	if err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if err := writeSharedTrustObservation(path, oldRoot, b, prepared, observed); err == nil {
		t.Fatal("wrong journal root")
	}
	if err := writeSharedTrustObservation(path, newRoot, b, prepared, observed); err != nil {
		t.Fatal(err)
	}
	if err := rollbackSharedTrustRootTransition(path, newRoot, oldRoot, b, observed); err != errSharedTrustConflict {
		t.Fatal("verified committed floor aborted", err)
	}
	if err := writeSharedTrustObservation(path, newRoot, b, observed, prepared); err == nil {
		t.Fatal("observation erased")
	}
	alternate := prepared
	alternate.ID = uuid.New()
	if err := writeSharedTrustObservation(path, newRoot, b, alternate, alternate); err != errSharedTrustConflict {
		t.Fatal("stale operation accepted", err)
	}
	// Missing/corrupt destination cannot prevent retaining a verified observation.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustObservation(path, newRoot, b, observed, observed); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedTrustRootTransition(path, newRoot, b, observed); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustObservation(path, newRoot, b, observed, observed); err != errSharedTrustMissing {
		t.Fatal(err)
	}
}
