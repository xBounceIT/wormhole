package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedTransitionFixture(t *testing.T) (string, []byte, []byte, sharedpg.TrustBinding, sharedpg.TrustState) {
	t.Helper()
	c, _, o, root, master, _, _ := sharedUnlockFixture(t)
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	return o.TrustPath, root, bytes.Repeat([]byte{92}, 32), o.Binding, state
}

func TestSharedTrustTransitionLifecycle(t *testing.T) {
	path, old, next, b, state := sharedTransitionFixture(t)
	record, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := readSharedTrustRootTransition(path, next, b)
	if err != nil || !reflect.DeepEqual(record, restored) {
		t.Fatalf("journal: %v", err)
	}
	if _, err := readSharedTrustRootTransition(path, old, b); err == nil {
		t.Fatal("old root opened journal")
	}
	if _, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision); err != errSharedTrustTransitionPending {
		t.Fatalf("overwrote pending: %v", err)
	}
	advanced, err := state.AdvanceAccount(*state.Account, state.WrappingRevision+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(path, old, b, advanced, state.Revision); err != errSharedTrustTransitionPending {
		t.Fatalf("write during transition: %v", err)
	}
	if err := confirmSharedTrustFile(path, old, b, state); err != errSharedTrustTransitionPending {
		t.Fatalf("confirmed while pending: %v", err)
	}
	if err := confirmSharedTrustRootTransition(path, next, b, record); err != nil {
		t.Fatal(err)
	}
	if err := promoteSharedTrustRootTransition(path, next, b, record); err != nil {
		t.Fatal(err)
	}
	current, err := readSharedTrustFile(path, next, b, record.Next.Revision)
	if err != nil || !reflect.DeepEqual(current, record.Next) {
		t.Fatalf("promotion: %v", err)
	}
	if _, err := readSharedTrustFile(path, old, b, 1); err == nil {
		t.Fatal("old root remained usable")
	}
	if _, err := os.Lstat(sharedTrustTransitionPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal retained")
	}
	if err := promoteSharedTrustRootTransition(path, next, b, record); err != nil {
		t.Fatalf("promotion retry: %v", err)
	}
	if err := abortSharedTrustRootTransition(path, next, b, record); err != errSharedTrustConflict {
		t.Fatalf("aborted promoted file: %v", err)
	}
}

func TestSharedTrustTransitionDurabilityRecovery(t *testing.T) {
	for _, phase := range []string{"stage", "promote", "promote-cleanup", "abort-cleanup"} {
		t.Run(phase, func(t *testing.T) {
			path, old, next, b, state := sharedTransitionFixture(t)
			syncDir := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDir })
			calls := 0
			failAt := 1
			if phase == "promote-cleanup" {
				failAt = 2
			}
			failSync := func(string) error {
				calls++
				if calls == failAt {
					return errors.New("injected sync failure")
				}
				return nil
			}
			if phase == "stage" {
				privateFileDirectorySync = failSync
			}
			record, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision)
			if phase == "stage" {
				if err != errSharedTrustCommitUncertain {
					t.Fatalf("stage: %v", err)
				}
				privateFileDirectorySync = syncDir
				if err := confirmSharedTrustRootTransition(path, next, b, record); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if phase == "abort-cleanup" {
				privateFileDirectorySync = failSync
				if err := abortSharedTrustRootTransition(path, next, b, record); err != errSharedTrustTransitionCleanup {
					t.Fatalf("abort: %v", err)
				}
				privateFileDirectorySync = syncDir
				if err := abortSharedTrustRootTransition(path, next, b, record); err != nil {
					t.Fatalf("abort confirmation: %v", err)
				}
				current, err := readSharedTrustFile(path, old, b, state.Revision)
				if err != nil || !reflect.DeepEqual(current, state) {
					t.Fatal("abort changed source")
				}
				return
			}
			if phase != "stage" {
				privateFileDirectorySync = failSync
			}
			err = promoteSharedTrustRootTransition(path, next, b, record)
			expected := error(nil)
			if phase == "promote" {
				expected = errSharedTrustCommitUncertain
			}
			if phase == "promote-cleanup" {
				expected = errSharedTrustTransitionCleanup
			}
			if err != expected {
				t.Fatalf("promotion %s: %v", phase, err)
			}
			privateFileDirectorySync = syncDir
			if err := promoteSharedTrustRootTransition(path, next, b, record); err != nil {
				t.Fatalf("recovery: %v", err)
			}
		})
	}
}

func TestSharedTrustTransitionConflictsAndBoundaries(t *testing.T) {
	path, old, next, b, state := sharedTransitionFixture(t)
	if _, err := stageSharedTrustRootTransition("relative", old, next, b, state.Revision); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if _, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision+1); err == nil {
		t.Fatal("stale source accepted")
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	release()
	record, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision)
	if err != nil {
		t.Fatal(err)
	}
	actions := []func(string, []byte, sharedpg.TrustBinding, sharedpg.TrustRootTransition) error{confirmSharedTrustRootTransition, promoteSharedTrustRootTransition, abortSharedTrustRootTransition}
	for _, action := range actions {
		if err := action("relative", next, b, record); err != errSharedTrustStorage {
			t.Fatal(err)
		}
		release, err := tryAcquireExclusiveFileLock(path + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		err = action(path, next, b, record)
		release()
		if err != errSharedTrustConflict {
			t.Fatalf("lock: %v", err)
		}
		bad := record
		bad.Next.Revision++
		if err := action(path, next, b, bad); err != errSharedTrustConflict {
			t.Fatalf("wrong expected: %v", err)
		}
		if err := action(path, old, b, record); err == nil {
			t.Fatal("wrong root accepted")
		}
	}
	// Even re-encryption of the same source changes the exact CAS snapshot.
	if err := persistSharedTrustFile(path, old, b, state); err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		if err := action(path, next, b, record); err != errSharedTrustConflict {
			t.Fatalf("source conflict: %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		if err := action(path, next, b, record); err != errSharedTrustMissing {
			t.Fatalf("missing source: %v", err)
		}
	}
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil {
		t.Fatal(err)
	}
	if _, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := confirmSharedTrustRootTransition(path, next, b, record); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := promoteSharedTrustRootTransition(path, next, b, record); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if err := os.Mkdir(sharedTrustTransitionPath(path), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readSharedTrustRootTransition(path, next, b); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := persistSharedTransitionBytes(sharedTrustTransitionPath(path), []byte("test")); err != errSharedTrustStorage {
		t.Fatalf("directory replaced: %v", err)
	}
}
