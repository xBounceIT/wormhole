package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedPendingObservations(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	defer vault.Wipe(org)
	state := *p.Trust.Account
	state.Sequence++
	state.Active = false
	state, err := vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	next, err := p.ObserveAccount(b, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation("relative", root, b, p, next); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation(path, root, b, next, p); err == nil {
		t.Fatal("rollback accepted")
	}
	if err := writeSharedPendingObservation(path, root, b, p, next); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation(path, root, b, p, next); err != errSharedTrustConflict {
		release()
		t.Fatal(err)
	}
	release()
	if err := os.WriteFile(sharedTrustTransitionPath(path), []byte("transition"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation(path, root, b, p, next); err != errSharedTrustTransitionPending {
		t.Fatal(err)
	}
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil {
		t.Fatal(err)
	}
	syncDirectory := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
	privateFileDirectorySync = func(string) error { return errors.New("injected sync failure") }
	if err := writeSharedPendingObservation(path, root, b, p, next); err != errSharedTrustCommitUncertain {
		t.Fatal(err)
	}
	privateFileDirectorySync = syncDirectory
	if err := writeSharedPendingObservation(path, root, b, p, next); err != nil {
		t.Fatal("exact uncertain readback", err)
	}
	actual, err := readSharedPendingEnrollment(path, root, b)
	if err != nil || !reflect.DeepEqual(actual, next) || actual.ObservedTrust().Account.Active {
		t.Fatal("revocation lost", err)
	}
	state.Active = true
	state, err = vault.SignUserKeyState(state, org)
	if err != nil {
		t.Fatal(err)
	}
	alternative, err := p.ObserveAccount(b, state, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation(path, root, b, p, alternative); err != errSharedTrustConflict {
		t.Fatal("concurrent journal replaced", err)
	}
	if err := writeSharedPendingObservation(path, root, b, p, p); err != errSharedTrustConflict {
		t.Fatal("pending observation erased", err)
	}
	if err := writeSharedPendingObservation(path, root, b, next, next); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedPendingObservation(path, make([]byte, 32), b, next, next); err != sharedpg.ErrTrustState {
		t.Fatal(err)
	}
}
