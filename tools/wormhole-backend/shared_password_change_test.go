package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedPasswordChangeCloseDuringDispatch(t *testing.T) {
	c, p, o, _, master, _, _ := sharedPasswordFixture(t)
	newRoot := bytes.Repeat([]byte{94}, 32)
	entered := make(chan struct{})
	p.changePassword = func(ctx context.Context, _ *sharedpg.PreparedPasswordChange, _ string) (*sharedpg.PasswordChangeReceipt, error) {
		close(entered)
		<-ctx.Done()
		return nil, sharedpg.ErrPasswordChangeUncertain
	}
	result := make(chan error, 1)
	go func() {
		_, err := c.ChangePassword(context.Background(), master, bytes.Repeat([]byte{93}, 32), newRoot, vault.KDFV1, false, "ui")
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch not reached")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, sharedpg.ErrPasswordChangeUncertain) {
			t.Fatal("uncertainty masked", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("change did not retire")
	}
	if _, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); err != nil {
		t.Fatal("close erased recovery", err)
	}
	if c.Admitted() || c.Unlocked() {
		t.Fatal("closed owner active")
	}
}

func sharedPasswordFixture(t *testing.T) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	t.Helper()
	c, p, o, root, master, account, org := sharedUnlockFixture(t)
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	return c, p, o, root, master, account, org
}

func TestSharedPasswordChangeRequiresDeviceTransition(t *testing.T) {
	c, p, o, oldRoot, master, _, _ := sharedPasswordFixture(t)
	p.changePassword = func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error) {
		t.Fatal("legacy change dispatched without device candidate")
		return nil, nil
	}
	before, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	device := []byte("existing device must never be silently ignored")
	if err := os.WriteFile(sharedDeviceEnrollmentPath(o.TrustPath), device, 0600); err != nil {
		t.Fatal(err)
	}
	receipt, err := c.ChangePassword(context.Background(), master, bytes.Repeat([]byte{93}, 32), bytes.Repeat([]byte{94}, 32), vault.KDFV1, false, "ui")
	if receipt != nil || !errors.Is(err, errSharedDevicePasswordTransitionRequired) {
		t.Fatal(receipt, err)
	}
	after, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, before.Revision)
	// Fetching authenticated account material may persist monotonic observations;
	// it must not advance the password wrapping floor or replace the active root.
	if err != nil || before.WrappingRevision != after.WrappingRevision {
		t.Fatal("password wrapping changed", err)
	}
	actual, err := os.ReadFile(sharedDeviceEnrollmentPath(o.TrustPath))
	if err != nil || !bytes.Equal(device, actual) {
		t.Fatal("device changed", err)
	}
	if _, err := os.Stat(sharedTrustTransitionPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy journal created", err)
	}
	if _, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1); err != nil {
		t.Fatal("old trust lost", err)
	}
}

func TestSharedPasswordChangeOutcomes(t *testing.T) {
	for _, mode := range []string{"commit", "commit-cleanup", "rejected", "uncertain", "uncertain-cleanup", "missing-receipt", "wrong-receipt", "promotion-failure", "owner-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, oldRoot, master, account, _ := sharedPasswordFixture(t)
			newMaster, newRoot := bytes.Repeat([]byte{93}, 32), bytes.Repeat([]byte{94}, 32)
			var pending sharedpg.TrustRootTransition
			calls := 0
			originalSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = originalSync })
			p.changePassword = func(ctx context.Context, plan *sharedpg.PreparedPasswordChange, source string) (*sharedpg.PasswordChangeReceipt, error) {
				calls++
				if plan == nil || source != "ui" || ctx.Err() != nil || c.Unlocked() {
					t.Fatal("invalid dispatch state")
				}
				var err error
				pending, err = readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
				if err != nil {
					t.Fatal("SQL preceded durable staging", err)
				}
				before, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, pending.Previous.Revision)
				if err != nil || before.WrappingRevision != account.Binding.Revision {
					t.Fatal("source changed before commit")
				}
				switch mode {
				case "rejected":
					return nil, sharedpg.ErrAuditUnavailable
				case "uncertain", "uncertain-cleanup":
					if mode == "uncertain-cleanup" {
						p.closeFailure.Store(true)
					}
					p.cancel()
					return nil, sharedpg.ErrPasswordChangeUncertain
				case "missing-receipt":
					return nil, nil
				case "wrong-receipt":
					return &sharedpg.PasswordChangeReceipt{WrappingRevision: 999, AuthEpoch: 2}, nil
				case "promotion-failure":
					privateFileDirectorySync = func(string) error { return os.ErrPermission }
				case "owner-cleanup":
					p.closeFailure.Store(true)
				}
				p.cancel() // Real commit retires Session.Done before local promotion.
				receipt := &sharedpg.PasswordChangeReceipt{WrappingRevision: account.Binding.Revision + 1, AuthEpoch: 2}
				if mode == "commit-cleanup" {
					return receipt, sharedpg.ErrSessionCleanup
				}
				return receipt, nil
			}
			receipt, err := c.ChangePassword(context.Background(), master, newMaster, newRoot, vault.KDFV1, false, "ui")
			if calls != 1 || c.Admitted() || c.Unlocked() {
				t.Fatal("owner not retired or SQL retried")
			}
			p.closeFailure.Store(false)
			privateFileDirectorySync = originalSync
			switch mode {
			case "rejected":
				if receipt != nil || !errors.Is(err, sharedpg.ErrAuditUnavailable) {
					t.Fatal(err)
				}
				if _, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); e != errSharedTrustMissing {
					t.Fatal("rejection retained journal", e)
				}
				if _, e := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, pending.Previous.Revision); e != nil {
					t.Fatal(e)
				}
			case "uncertain", "uncertain-cleanup", "missing-receipt", "wrong-receipt":
				if receipt != nil || !errors.Is(err, sharedpg.ErrPasswordChangeUncertain) {
					t.Fatal("uncertainty lost", err)
				}
				if mode == "uncertain-cleanup" && !errors.Is(err, errSharedAdmissionCleanup) {
					t.Fatal("cleanup failure lost", err)
				}
				if _, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); e != nil {
					t.Fatal("recovery erased", e)
				}
				if _, e := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, pending.Previous.Revision); e != nil {
					t.Fatal(e)
				}
			default:
				if receipt == nil {
					t.Fatal("commit proof lost", err)
				}
				if mode == "commit" && err != nil {
					t.Fatal(err)
				}
				if mode == "commit-cleanup" && !errors.Is(err, sharedpg.ErrSessionCleanup) {
					t.Fatal(err)
				}
				if mode == "owner-cleanup" && !errors.Is(err, errSharedAdmissionCleanup) {
					t.Fatal(err)
				}
				if mode == "promotion-failure" {
					if !errors.Is(err, errSharedTrustCommitUncertain) {
						t.Fatal(err)
					}
					if e := promoteSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, pending); e != nil {
						t.Fatal(e)
					}
				}
				after, e := readSharedTrustFile(o.TrustPath, newRoot, o.Binding, pending.Next.Revision)
				if e != nil || after.WrappingRevision != receipt.WrappingRevision {
					t.Fatal("new root not promoted", e)
				}
				if _, e := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1); e == nil {
					t.Fatal("old root accepted")
				}
			}
			if !bytes.Equal(master, bytes.Repeat([]byte{9}, 32)) || !bytes.Equal(newMaster, bytes.Repeat([]byte{93}, 32)) || !bytes.Equal(newRoot, bytes.Repeat([]byte{94}, 32)) {
				t.Fatal("borrowed input modified")
			}
		})
	}
}

func TestSharedPasswordChangePreflight(t *testing.T) {
	for _, mode := range []string{"invalid", "cancelled", "locked", "wrong-master", "revoked", "wrong-kdf", "stage-failure", "stage-confirmation", "cancel-after-stage"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, _, master, account, org := sharedPasswordFixture(t)
			newMaster, newRoot := bytes.Repeat([]byte{93}, 32), bytes.Repeat([]byte{94}, 32)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			preset := vault.KDFV1
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			calls := 0
			p.changePassword = func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error) {
				calls++
				return nil, sharedpg.ErrAuditUnavailable
			}
			switch mode {
			case "invalid":
				newRoot = nil
			case "cancelled":
				cancel()
			case "locked":
				c.unlocked.Store(false)
			case "wrong-master":
				master = bytes.Repeat([]byte{2}, 32)
			case "revoked":
				revoked := *account.State
				revoked.Sequence++
				revoked.Active = false
				signed, e := vault.SignUserKeyState(revoked, org)
				if e != nil {
					t.Fatal(e)
				}
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return &signed, nil }
			case "wrong-kdf":
				preset = vault.KDFLow
			case "stage-failure", "stage-confirmation", "cancel-after-stage":
				failures := 0
				privateFileDirectorySync = func(path string) error {
					if _, e := os.Stat(sharedTrustTransitionPath(o.TrustPath)); e == nil {
						if mode == "cancel-after-stage" {
							cancel()
							return original(path)
						}
						failures++
						if mode == "stage-failure" || failures == 1 {
							return os.ErrPermission
						}
					}
					return original(path)
				}
			}
			receipt, err := c.ChangePassword(ctx, master, newMaster, newRoot, preset, false, "ui")
			if receipt != nil || err == nil {
				t.Fatal("invalid attempt succeeded")
			}
			expectedCalls := 0
			if mode == "stage-confirmation" {
				expectedCalls = 1
			}
			if calls != expectedCalls {
				t.Fatal("unexpected dispatch", calls)
			}
			if mode == "invalid" || mode == "cancelled" {
				if !c.Unlocked() {
					t.Fatal("preflight altered owner")
				}
			} else if mode != "locked" && c.Admitted() {
				t.Fatal("failed attempt kept owner")
			}
			privateFileDirectorySync = original
			if mode == "stage-failure" {
				if _, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); e != nil {
					t.Fatal("uncertain stage lost", e)
				}
			}
			if mode == "cancel-after-stage" {
				if _, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); e != errSharedTrustMissing {
					t.Fatal("pre-dispatch cancellation retained journal", e)
				}
			}
		})
	}
}
