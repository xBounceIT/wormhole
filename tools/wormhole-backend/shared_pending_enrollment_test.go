package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedPendingFixture(t *testing.T) (string, []byte, sharedpg.TrustBinding, sharedpg.PendingEnrollment) {
	t.Helper()
	c, _, o, root, master, account, _ := sharedEnrolledFixture(t)
	trust, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	trust.FormatVersion, trust.Revision = 3, 1
	trust.WrappingRevision = 1
	trust.Enrollment = nil
	accountTrust, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := vault.OpenEnrolledUserKeys(master, account.Binding, account.Envelope, *account.EnrollmentCertificate, *account.State, accountTrust, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	account.Binding.Revision = 1
	account.Envelope, err = vault.SealUserKeys(master, account.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("wormhole/v1/pending-enrollment-capsule"))
	h.Write(account.Envelope.Nonce)
	h.Write(account.Envelope.Ciphertext)
	p := sharedpg.PendingEnrollment{FormatVersion: 1, Trust: trust, Certificate: *account.EnrollmentCertificate, CapsuleDigest: h.Sum(nil), RoleTag: "testscope", KDF: account.KDF, ASKRequired: account.ASKRequired}
	return filepath.Join(t.TempDir(), "new.trust"), root, o.Binding, p
}

func TestSharedPendingEnrollmentLifecycle(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	if _, err := readSharedPendingEnrollment(path, root, b); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != errSharedTrustMissing {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	restored, err := readSharedPendingEnrollment(path, root, b)
	if err != nil || !reflect.DeepEqual(restored, p) {
		t.Fatal("readback", err)
	}
	raw, err := os.ReadFile(sharedPendingEnrollmentPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, p.Trust.SignedProfile) || bytes.Contains(raw, []byte(p.Certificate.Manifest.Context.LoginName)) {
		t.Fatal("plaintext journal")
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedEnrollmentPending {
		t.Fatal("replaced pending", err)
	}
	if err := writeSharedTrustFile(path, root, b, p.Trust, 0); err != errSharedEnrollmentPending {
		t.Fatal("early trust activation", err)
	}
	if err := confirmSharedTrustFile(path, root, b, p.Trust); err != errSharedEnrollmentPending {
		t.Fatal("early trust confirmation", err)
	}
	if _, err := stageSharedTrustRootTransition(path, root, root, b, 1); err != errSharedEnrollmentPending {
		t.Fatal("password mutation while pending", err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging activated trust")
	}
	wrong := p
	wrong.CapsuleDigest = bytes.Repeat([]byte{1}, 32)
	if err := confirmSharedPendingEnrollment(path, root, b, wrong); err != errSharedTrustConflict {
		t.Fatal("changed intent confirmed", err)
	}
	if err := confirmSharedPendingEnrollment(path, make([]byte, 32), b, p); err != sharedpg.ErrTrustState {
		t.Fatal("wrong root", err)
	}
	if err := os.WriteFile(sharedPendingEnrollmentPath(path), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != sharedpg.ErrTrustState {
		t.Fatal("corruption replaced", err)
	}
}

func TestSharedPendingEnrollmentDurability(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	syncDirectory := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
	privateFileDirectorySync = func(string) error { return errors.New("injected sync failure") }
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedTrustCommitUncertain {
		t.Fatal("staging durability", err)
	}
	if _, err := readSharedPendingEnrollment(path, root, b); err != nil {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != errSharedTrustCommitUncertain {
		t.Fatal("readback mistaken for durable", err)
	}
	privateFileDirectorySync = syncDirectory
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != nil {
		t.Fatal(err)
	}
}

func TestSharedPendingEnrollmentBoundaries(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	if err := stageSharedPendingEnrollment("relative", root, b, p); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment("relative", root, b, p); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, nil, b, p); err != sharedpg.ErrTrustState {
		t.Fatal(err)
	}
	release, err := tryAcquireExclusiveFileLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	release()
	if err := os.WriteFile(path, []byte("existing trust"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedTrustConflict {
		t.Fatal("overwrote trust", err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != errSharedTrustConflict {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedTrustTransitionPath(path), []byte("password pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedTrustTransitionPending {
		t.Fatal(err)
	}
	if err := confirmSharedPendingEnrollment(path, root, b, p); err != errSharedTrustTransitionPending {
		t.Fatal(err)
	}
	if err := os.Remove(sharedTrustTransitionPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sharedPendingEnrollmentPath(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(path, root, b, p); err != errSharedEnrollmentPending {
		t.Fatal(err)
	}
	if _, err := readSharedPendingEnrollment(path, root, b); err != errSharedTrustStorage {
		t.Fatal(err)
	}
	obstacle := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(obstacle, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(filepath.Join(obstacle, "child"), root, b, p); err != errSharedTrustStorage {
		t.Fatal(err)
	}
}

func TestSharedPendingEnrollmentConcurrentStage(t *testing.T) {
	path, root, b, p := sharedPendingFixture(t)
	var group sync.WaitGroup
	outcomes := make(chan error, 2)
	for n := 0; n < 2; n++ {
		group.Add(1)
		go func() { defer group.Done(); outcomes <- stageSharedPendingEnrollment(path, root, b, p) }()
	}
	group.Wait()
	close(outcomes)
	successes := 0
	for err := range outcomes {
		if err == nil {
			successes++
		} else if err != errSharedTrustConflict && err != errSharedEnrollmentPending {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("nonexclusive staging", successes)
	}
	actual, err := readSharedPendingEnrollment(path, root, b)
	if err != nil || !reflect.DeepEqual(actual, p) {
		t.Fatal(err)
	}
}
