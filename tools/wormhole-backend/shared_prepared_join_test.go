package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Explicit preparation boundary: real master/root/commit/slot/envelope, with
// native session fetching tested separately against PostgreSQL.
type preparedDeviceProbe struct {
	master                     *sharedpg.AccountMaster
	root                       *sharedpg.DeviceTrustRoot
	commit                     *sharedpg.PreparedInvitationCommit
	key                        []byte
	slots                      vault.SlotFile
	envelope                   []byte
	borrows                    atomic.Int32
	storageError, accountError error
}

func (p *preparedDeviceProbe) Borrow(use func(*sharedpg.AccountMaster, *sharedpg.DeviceTrustRoot, *sharedpg.PreparedInvitationCommit) error) error {
	if p.accountError != nil {
		return p.accountError
	}
	return use(p.master, p.root, p.commit)
}
func (p *preparedDeviceProbe) BorrowDeviceStorage(use func([]byte, vault.SlotFile, []byte) error) error {
	p.borrows.Add(1)
	if p.storageError != nil {
		return p.storageError
	}
	return use(p.key, p.slots, p.envelope)
}

func preparedDeviceJoinFixture(t *testing.T) (*sharedInvitationJoin, *recoveryFixture, *preparedDeviceProbe, *invitationJoinProbe) {
	t.Helper()
	f, commit := preparedJoinFixture(t)
	root, err := f.master.DeriveTrustRoot(context.Background(), f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := root.Use(func(key []byte) error { f.root = bytes.Clone(key); return nil }); err != nil {
		t.Fatal(err)
	}
	slots, key := localSlotFixture(t)
	slots.Nodes = nil
	// A new device has not observed any shared source policy. The generic local
	// fixture's policy sequence belongs to a different workspace.
	slots.ProfileSequence = 0
	raw, err := vault.EncodeSlotFile(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commit.SealDeviceEnrollment(key, slots, f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	p := &preparedDeviceProbe{master: f.master, root: root, commit: commit, key: key, slots: slots, envelope: envelope}
	t.Cleanup(func() { vault.Wipe(key); vault.Wipe(f.root) })
	source := &invitationJoinProbe{commit: func(context.Context, *sharedpg.PreparedInvitationCommit) error { return nil }}
	j := newSharedInvitationJoinWithSession(source, func() sharedJoinRecovery { return f.c })
	t.Cleanup(func() {
		if err := j.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return j, f, p, source
}

func TestSharedPreparedJoinDurableBeforeDispatch(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "receipt", true: "uncertain"}[uncertain], func(t *testing.T) {
			j, f, p, source := preparedDeviceJoinFixture(t)
			source.commit = func(_ context.Context, commit *sharedpg.PreparedInvitationCommit) error {
				slots, envelope, err := readSharedDeviceEnrollment(f.o.TrustPath)
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := sharedpg.OpenDeviceEnrollment(p.key, slots, p.slots.VaultID, p.slots.FileID, 1, envelope)
				if err != nil || metadata.Binding() != f.o.Binding {
					t.Fatal("SQL before recoverable device", err)
				}
				if _, err := readSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding); err != nil {
					t.Fatal("SQL before intent", err)
				}
				if err := commit.ValidateAccountMaster(f.master); err != nil {
					t.Fatal(err)
				}
				if uncertain {
					return sharedpg.ErrInvitationCommitUncertain
				}
				return nil
			}
			options := f.o
			options.Binding = sharedpg.TrustBinding{}
			options.Request.DeviceID = uuid.New()
			result, err := j.joinPrepared(context.Background(), options, p)
			if err != nil || result == nil || !result.Submitted || !result.Committed || !result.Confirmed || source.calls != 1 {
				t.Fatal("prepared join", result, err)
			}
			if _, _, err := readSharedDeviceEnrollment(f.o.TrustPath); err != nil {
				t.Fatal("committed device deleted", err)
			}
			if err := j.DiscardDevicePreparation(context.Background(), f.root, p.key); err != errSharedTrustConflict {
				t.Fatal("submitted device discard", err)
			}
			before := p.borrows.Load()
			if _, err := j.joinPrepared(context.Background(), options, p); err == nil || p.borrows.Load() != before {
				t.Fatal("repeat touched preparation", err)
			}
		})
	}
}

func TestSharedPreparedJoinFailureOwnership(t *testing.T) {
	for _, mode := range []string{"storage-error", "account-error", "nil-master", "closed-root", "bad-api", "wrong-storage-root", "foreign-device", "existing-device", "sync-device", "sync-all", "competing-setup", "tampered-device", "rejected", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			j, f, p, source := preparedDeviceJoinFixture(t)
			syncDir := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDir })
			switch mode {
			case "storage-error":
				p.storageError = sharedpg.ErrConfiguration
			case "account-error":
				p.accountError = sharedpg.ErrConfiguration
			case "nil-master":
				p.master = nil
			case "closed-root":
				if err := p.root.Close(); err != nil {
					t.Fatal(err)
				}
			case "bad-api":
				f.o.Request.API = 0
			case "wrong-storage-root":
				p.key[0] ^= 1
			case "foreign-device":
				b := f.o.Binding
				b.KeyID = uuid.New()
				var err error
				p.envelope, err = p.commit.SealDeviceEnrollment(p.key, p.slots, b)
				if err != nil {
					t.Fatal(err)
				}
			case "existing-device":
				if err := os.MkdirAll(filepath.Dir(f.o.TrustPath), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sharedDeviceEnrollmentPath(f.o.TrustPath), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "sync-device", "sync-all", "competing-setup", "tampered-device":
				privateFileDirectorySync = func(path string) error {
					_, exists := os.Stat(sharedDeviceEnrollmentPath(f.o.TrustPath))
					if mode == "sync-all" || mode == "sync-device" && exists == nil {
						return os.ErrPermission
					}
					if mode == "competing-setup" && exists == nil {
						if err := os.WriteFile(sharedTransportSetupPath(f.o.TrustPath), []byte("foreign"), 0600); err != nil {
							return err
						}
					}
					if mode == "tampered-device" {
						if _, err := os.Stat(sharedPendingEnrollmentPath(f.o.TrustPath)); err == nil {
							if err := os.WriteFile(sharedDeviceEnrollmentPath(f.o.TrustPath), []byte("changed"), 0600); err != nil {
								return err
							}
						}
					}
					return syncDir(path)
				}
			case "rejected":
				source.commit = func(context.Context, *sharedpg.PreparedInvitationCommit) error { return sharedpg.ErrInvitation }
			case "unknown":
				source.commit = func(context.Context, *sharedpg.PreparedInvitationCommit) error {
					return sharedpg.ErrInvitationCommitUncertain
				}
				j.newRecovery = func() sharedJoinRecovery {
					return &joinRecoveryProbe{run: func(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
						return nil, sharedpg.ErrAuthentication
					}}
				}
			}
			result, err := j.joinPrepared(context.Background(), f.o, p)
			if err == nil {
				t.Fatal("failure accepted")
			}
			privateFileDirectorySync = syncDir
			submitted := mode == "rejected" || mode == "unknown"
			if submitted {
				if source.calls != 1 || result == nil || !result.Submitted {
					t.Fatal("remote outcome lost", result, err)
				}
				if _, _, e := readSharedDeviceEnrollment(f.o.TrustPath); e != nil {
					t.Fatal("submitted storage deleted", e)
				}
				if e := j.DiscardDevicePreparation(context.Background(), f.root, p.key); e != errSharedTrustConflict {
					t.Fatal(e)
				}
				return
			}
			if source.calls != 0 || result != nil {
				t.Fatal("preflight sent SQL", source.calls, result)
			}
			if mode == "existing-device" {
				raw, e := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
				if e != nil || string(raw) != "foreign" {
					t.Fatal("foreign file modified")
				}
				return
			}
			if mode == "competing-setup" || mode == "tampered-device" || mode == "sync-all" {
				if j.preparation == nil || len(j.preparation.deviceRaw) == 0 {
					t.Fatal("cleanup proof lost")
				}
				if e := j.DiscardPreparation(context.Background(), f.root); e == nil {
					t.Fatal("cleanup without storage root")
				}
				if e := j.DiscardDevicePreparation(context.Background(), f.root, bytes.Repeat([]byte{99}, 32)); e == nil {
					t.Fatal("wrong cleanup key")
				}
				if mode == "competing-setup" {
					if e := os.Remove(sharedTransportSetupPath(f.o.TrustPath)); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "tampered-device" {
					if e := os.WriteFile(sharedDeviceEnrollmentPath(f.o.TrustPath), j.preparation.deviceRaw, 0600); e != nil {
						t.Fatal(e)
					}
				}
				if e := j.DiscardDevicePreparation(context.Background(), f.root, p.key); e != nil {
					t.Fatal("cleanup retry", e)
				}
			}
			if _, e := os.Stat(sharedDeviceEnrollmentPath(f.o.TrustPath)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("owned preflight file remains", e)
			}
		})
	}
}

func TestSharedPreparedJoinCancellationAndGuards(t *testing.T) {
	j, f, p, source := preparedDeviceJoinFixture(t)
	entered := make(chan struct{})
	source.commit = func(ctx context.Context, _ *sharedpg.PreparedInvitationCommit) error {
		close(entered)
		<-ctx.Done()
		return sharedpg.ErrInvitationCommitUncertain
	}
	done := make(chan error, 1)
	go func() { _, err := j.joinPrepared(context.Background(), f.o, p); done <- err }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.joinPrepared(ctx, f.o, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if p.borrows.Load() != 1 {
		t.Fatal("concurrent canceled caller borrowed secrets")
	}
	if err := j.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("cancellation succeeded")
	}
	if _, _, err := readSharedDeviceEnrollment(f.o.TrustPath); err != nil {
		t.Fatal("uncertain device removed", err)
	}
	if _, err := j.JoinPrepared(context.Background(), f.o, nil); err == nil {
		t.Fatal("nil preparation")
	}
	if _, err := j.joinPrepared(nil, f.o, p); err == nil {
		t.Fatal("nil context")
	}
	o := f.o
	o.TrustPath = "relative"
	if _, err := j.joinPrepared(context.Background(), o, p); err == nil {
		t.Fatal("relative path")
	}
	if _, err := j.joinPrepared(context.Background(), f.o, nil); err == nil {
		t.Fatal("nil interface")
	}
	if err := j.DiscardDevicePreparation(context.Background(), f.root, nil); err == nil {
		t.Fatal("nil storage key")
	}
}

func TestSharedPreparedJoinFinalIntentMustMatch(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "exact"} {
		t.Run(mode, func(t *testing.T) {
			j, f, p, source := preparedDeviceJoinFixture(t)
			pending, err := p.commit.PendingEnrollment(f.o.Binding)
			if err != nil {
				t.Fatal(err)
			}
			j.preparation = &sharedJoinPreparation{options: f.o, pending: pending}
			device := &sharedJoinDeviceStorage{root: p.key, slots: p.slots, envelope: p.envelope}
			if err := j.stageDeviceLocked(f.o, device); err != nil {
				t.Fatal(err)
			}
			if mode != "missing" {
				if err := stageSharedPendingEnrollment(f.o.TrustPath, f.root, f.o.Binding, pending); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "changed" {
				pending.RoleTag = "different"
			}
			err = j.confirmDeviceWithIntentLocked(f.o, f.root, device, pending)
			if (err == nil) != (mode == "exact") {
				t.Fatal(mode, err)
			}
			if source.calls != 0 {
				t.Fatal("confirmation submitted SQL")
			}
		})
	}
}
