package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func invitationPreparationFixture(t *testing.T) (*sharedInvitationJoin, *recoveryFixture) {
	t.Helper()
	f, request := preparedJoinFixture(t)
	pending, err := request.PendingEnrollment(f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	f.pending = pending
	if err := stageSharedTransportSetup(f.o, f.root, pending.Trust); err != nil {
		t.Fatal(err)
	}
	if err := stageSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding, pending); err != nil {
		t.Fatal(err)
	}
	join := newSharedInvitationJoinWithSession(&invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error {
		t.Fatal("cleanup invoked SQL")
		return nil
	}}, func() sharedJoinRecovery { t.Fatal("cleanup invoked recovery"); return nil })
	join.started = true
	join.preparation = &sharedJoinPreparation{options: f.o, pending: pending, setupOwned: true, pendingOwned: true}
	t.Cleanup(func() {
		if err := join.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return join, f
}

func TestSharedInvitationPreparationCleanup(t *testing.T) {
	join, f := invitationPreparationFixture(t)
	syncDirectory := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
	privateFileDirectorySync = func(string) error { return os.ErrPermission }
	if err := join.DiscardPreparation(context.Background(), f.root); err != errSharedInvitationPreparationCleanup {
		t.Fatal(err)
	}
	if join.preparation == nil {
		t.Fatal("lost uncertain cleanup ownership")
	}
	for _, path := range []string{sharedPendingEnrollmentPath(f.o.TrustPath), sharedTransportSetupPath(f.o.TrustPath)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned record retained", err)
		}
	}
	privateFileDirectorySync = syncDirectory
	for attempt := 0; attempt < 2; attempt++ {
		if err := join.DiscardPreparation(context.Background(), f.root); err != nil {
			t.Fatal(err)
		}
	}
	if join.preparation != nil {
		t.Fatal("retained finished metadata")
	}
}

func TestSharedInvitationPreparationRefusesForeignState(t *testing.T) {
	for _, mode := range []string{"wrong-root", "changed-setup", "corrupt-setup", "changed-pending", "corrupt-pending", "unowned-pending", "active", "transition", "lock", "submitted"} {
		t.Run(mode, func(t *testing.T) {
			join, f := invitationPreparationFixture(t)
			root := append([]byte(nil), f.root...)
			switch mode {
			case "wrong-root":
				root[0] ^= 1
			case "changed-setup":
				changed := f.o.Settings
				changed.Database = "different"
				raw, err := sharedpg.SealTransportSetup(root, f.o.Binding, changed, f.pending.Trust, f.o.OSFloor, f.o.UserFloor, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := persistSharedTransitionBytes(sharedTransportSetupPath(f.o.TrustPath), raw); err != nil {
					t.Fatal(err)
				}
			case "corrupt-setup":
				if err := os.WriteFile(sharedTransportSetupPath(f.o.TrustPath), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-pending":
				state := *f.pending.Trust.Account
				state.Sequence++
				state, err := vault.SignUserKeyState(state, f.org)
				if err != nil {
					t.Fatal(err)
				}
				next, err := f.pending.ObserveAccount(f.o.Binding, state, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeSharedPendingObservation(f.o.TrustPath, root, f.o.Binding, f.pending, next); err != nil {
					t.Fatal(err)
				}
			case "corrupt-pending":
				if err := os.WriteFile(sharedPendingEnrollmentPath(f.o.TrustPath), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unowned-pending":
				join.preparation.pendingOwned = false
			case "active":
				if err := persistSharedTrustFile(f.o.TrustPath, root, f.o.Binding, f.pending.Trust); err != nil {
					t.Fatal(err)
				}
			case "transition":
				if err := os.WriteFile(sharedTrustTransitionPath(f.o.TrustPath), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				release, err := tryAcquireExclusiveFileLock(f.o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "submitted":
				join.submitted = true
			}
			if err := join.DiscardPreparation(context.Background(), root); err == nil {
				t.Fatal("discarded foreign or submitted state")
			}
			for _, path := range []string{sharedPendingEnrollmentPath(f.o.TrustPath), sharedTransportSetupPath(f.o.TrustPath)} {
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("partial deletion before validation", err)
				}
			}
		})
	}
}

func TestSharedInvitationPreparationInput(t *testing.T) {
	join, f := invitationPreparationFixture(t)
	if err := join.DiscardPreparation(nil, f.root); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if err := join.DiscardPreparation(context.Background(), nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := join.DiscardPreparation(ctx, f.root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := join.DiscardPreparation(context.Background(), f.root); err != nil {
		t.Fatal(err)
	}
}
