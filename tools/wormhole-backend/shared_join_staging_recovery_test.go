package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func recoverableJoinFixture(t *testing.T) (*recoveryFixture, *preparedDeviceProbe, sharedJoinStartup, sharedStartupProtection, sharedAdmissionOptions) {
	t.Helper()
	_, f, device, _ := sharedJoinPasswordPreparationFixture(t)
	pending, err := device.commit.PendingEnrollment(f.o.Binding)
	if err != nil {
		t.Fatal(err)
	}
	o := f.o
	o.Settings.DeviceRole = "wh_" + pending.RoleTag + "_d_" + o.Binding.DeviceID.String()
	o.Settings.Changes = sharedpg.ChangePolicy{TransactionPooler: true}
	o.Settings, err = pending.ObservedTrust().PrepareTransport(o.Settings, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		t.Fatal(err)
	}
	p, err := makeRecoverableSharedJoinStartup(o, &sharedJoinDeviceStorage{root: device.key, slots: device.slots, envelope: device.envelope}, f.root, pending)
	if err != nil {
		t.Fatal(err)
	}
	protection := startupTestProtection()
	o.startupProtection = &protection
	if err := writeSharedJoinStartup(context.Background(), o.TrustPath, p, protection, false); err != nil {
		t.Fatal(err)
	}
	return f, device, p, protection, o
}

func openRecoverableJoin(t *testing.T, o sharedAdmissionOptions, p sharedJoinStartup, protection sharedStartupProtection) *sharedSelectedDevice {
	t.Helper()
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := unlockSharedJoiningDevice(context.Background(), o, slots.Slots[0].ID, []byte("recovery-test-password"), nil, protection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := selected.Close(); err != nil {
			t.Error(err)
		}
	})
	return selected
}

func restoreJoinForTest(ctx context.Context, selected *sharedSelectedDevice) error {
	return selected.account.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error { return restoreSharedJoinStaging(ctx, selected, key, master) })
	})
}

func TestRecoverableJoinRestoresEveryMissingStagingPrefixWithoutActiveTrust(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			f, _, p, protection, o := recoverableJoinFixture(t)
			paths := []string{sharedDeviceEnrollmentPath(o.TrustPath), sharedTransportSetupPath(o.TrustPath), sharedPendingEnrollmentPath(o.TrustPath)}
			values := [][]byte{p.DeviceFile, p.Transport, p.Pending}
			for n, path := range paths {
				if mask&(1<<n) != 0 {
					if err := persistSharedTransitionBytes(path, values[n]); err != nil {
						t.Fatal(err)
					}
				}
			}
			selected := openRecoverableJoin(t, o, p, protection)
			if err := restoreJoinForTest(context.Background(), selected); err != nil {
				t.Fatal("restore staging", err)
			}
			if err := restoreJoinForTest(context.Background(), selected); err != nil {
				t.Fatal("repeat changed authenticated recovery", err)
			}
			device, err := os.ReadFile(paths[0])
			if err != nil || !bytes.Equal(device, p.DeviceFile) {
				t.Fatal("restored device changed", err)
			}
			pending, err := readSharedPendingEnrollment(o.TrustPath, f.root, o.Binding)
			original, e := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
			if err != nil || e != nil || !reflect.DeepEqual(pending, original) {
				t.Fatal("restored a different intent", err, e)
			}
			settings, err := readSharedTransportSetup(o, f.root, pending.ObservedTrust())
			if err != nil || settings.DeviceRole != o.Settings.DeviceRole || !reflect.DeepEqual(settings.Endpoints, o.Settings.Endpoints) {
				t.Fatal("restored caller-selected settings", err)
			}
			for _, path := range []string{o.TrustPath, sharedStartupAnchorPath(o.TrustPath)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("local recovery manufactured admission", err)
				}
			}
			controller, probe := selectedDeviceController(t, f)
			probe.open = func(context.Context, sharedpg.Settings) error { return sharedpg.ErrAuthentication }
			if err := selected.reconcileInitialEnrollment(context.Background(), controller); !errors.Is(err, sharedpg.ErrAuthentication) || probe.opens.Load() != 1 || controller.Unlocked() {
				t.Fatal("local reconstruction bypassed fresh device proof", err, probe.opens.Load())
			}
		})
	}
}

func TestRecoverableJoinPreservesUnknownOrReplacedState(t *testing.T) {
	for _, mode := range []string{"device", "connection", "intent", "redirect", "other-capsule", "snapshot", "transition", "active", "anchor", "canceled", "held", "protection", "relative", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			f, _, p, protection, o := recoverableJoinFixture(t)
			selected := openRecoverableJoin(t, o, p, protection)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var protectedPath string
			protected := []byte("preserve competing state")
			switch mode {
			case "device":
				protectedPath = sharedDeviceEnrollmentPath(o.TrustPath)
			case "connection", "oversized":
				protectedPath = sharedTransportSetupPath(o.TrustPath)
				if mode == "oversized" {
					protected = make([]byte, 2*sharedpg.MaxTransportSnapshotBytes+1)
				}
			case "intent":
				protectedPath = sharedPendingEnrollmentPath(o.TrustPath)
			case "redirect":
				protectedPath = sharedTransportSetupPath(o.TrustPath)
				settings := o.Settings
				settings.Endpoints = []sharedpg.Endpoint{{Host: "different.example", Port: 5432}}
				pending, e := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
				if e != nil {
					t.Fatal(e)
				}
				protected, e = sharedpg.SealTransportSetup(f.root, o.Binding, settings, pending.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API)
				if e != nil {
					t.Fatal(e)
				}
			case "other-capsule":
				protectedPath = sharedPendingEnrollmentPath(o.TrustPath)
				pending, e := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
				if e != nil {
					t.Fatal(e)
				}
				pending.CapsuleDigest = bytes.Repeat([]byte{9}, 32)
				protected, e = sharedpg.SealPendingEnrollment(f.root, o.Binding, pending)
				if e != nil {
					t.Fatal(e)
				}
			case "snapshot":
				changed := p
				changed.LoginName = "changed"
				if e := persistSharedJoinStartupValue(ctx, o.TrustPath, changed, protection); e != nil {
					t.Fatal(e)
				}
			case "transition":
				protectedPath = sharedTrustTransitionPath(o.TrustPath)
			case "active":
				protectedPath = o.TrustPath
			case "anchor":
				protectedPath = sharedStartupAnchorPath(o.TrustPath)
			case "canceled":
				cancel()
			case "held":
				release, e := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if e != nil {
					t.Fatal(e)
				}
				defer release()
			case "protection":
				selected.options.startupProtection = nil
			case "relative":
				selected.options.TrustPath = "relative"
			}
			if protectedPath != "" {
				if e := os.WriteFile(protectedPath, protected, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if err := restoreJoinForTest(ctx, selected); err == nil {
				t.Fatal("unsafe staging was adopted", mode)
			}
			if protectedPath != "" {
				actual, e := os.ReadFile(protectedPath)
				if e != nil || !bytes.Equal(actual, protected) {
					t.Fatal("competing state overwritten", mode, e)
				}
			}
		})
	}
}

func TestRecoverableJoinObservationSurvivesMissingOrdinaryIntent(t *testing.T) {
	for _, reverted := range []bool{false, true} {
		t.Run(fmt.Sprint(reverted), func(t *testing.T) {
			f, _, p, protection, o := recoverableJoinFixture(t)
			previous, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistSharedTransitionBytes(sharedPendingEnrollmentPath(o.TrustPath), p.Pending); err != nil {
				t.Fatal(err)
			}
			state := *previous.Trust.Account
			state.Sequence++
			state, err = vault.SignUserKeyState(state, f.org)
			if err != nil {
				t.Fatal(err)
			}
			first, err := previous.ObserveAccount(o.Binding, state, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistSharedEnrollmentObservation(o, f.root, &previous, first); err != nil {
				t.Fatal(err)
			}
			state.Sequence++
			state.Active = false
			state, err = vault.SignUserKeyState(state, f.org)
			if err != nil {
				t.Fatal(err)
			}
			next, err := previous.ObserveAccount(o.Binding, state, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistSharedEnrollmentObservation(o, f.root, &previous, next); err != nil {
				t.Fatal(err)
			}
			if reverted {
				if err := persistSharedTransitionBytes(sharedPendingEnrollmentPath(o.TrustPath), p.Pending); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(sharedPendingEnrollmentPath(o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			}
			updated, err := readSharedJoinStartup(o.TrustPath, protection)
			if err != nil {
				t.Fatal(err)
			}
			selected := openRecoverableJoin(t, o, updated, protection)
			if err := restoreJoinForTest(context.Background(), selected); err != nil {
				t.Fatal(err)
			}
			actual, err := readSharedPendingEnrollment(o.TrustPath, f.root, o.Binding)
			if err != nil || actual.ObservedTrust().Account.Sequence != state.Sequence || actual.ObservedTrust().Account.Active {
				t.Fatal("restoration erased authenticated revocation", err)
			}
			controller, probe := selectedDeviceController(t, f)
			if err := selected.reconcileInitialEnrollment(context.Background(), controller); !errors.Is(err, vault.ErrPolicy) || probe.opens.Load() != 0 || controller.Unlocked() {
				t.Fatal("revoked recovery reached the network or admitted", err, probe.opens.Load())
			}
		})
	}
}

func TestRecoverableJoinDoesNotRepairBeforePasswordAuthentication(t *testing.T) {
	_, _, p, protection, o := recoverableJoinFixture(t)
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := unlockSharedJoiningDevice(context.Background(), o, slots.Slots[0].ID, []byte("wrong password"), nil, protection)
	if selected != nil {
		if e := selected.Close(); e != nil {
			t.Fatal(e)
		}
	}
	if err == nil {
		t.Fatal("wrong password opened a recovery owner")
	}
	for _, path := range []string{sharedDeviceEnrollmentPath(o.TrustPath), sharedTransportSetupPath(o.TrustPath), sharedPendingEnrollmentPath(o.TrustPath)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unauthenticated recovery wrote files", err)
		}
	}
}

func TestRecoverableJoinRestorationRetriesEveryUncertainWrite(t *testing.T) {
	for failAt := 1; failAt <= 4; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			_, _, p, protection, o := recoverableJoinFixture(t)
			selected := openRecoverableJoin(t, o, p, protection)
			originalSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = originalSync })
			calls := 0
			privateFileDirectorySync = func(path string) error {
				calls++
				if calls == failAt {
					return errors.New("uncertain local sync")
				}
				return originalSync(path)
			}
			if err := restoreJoinForTest(context.Background(), selected); !errors.Is(err, errSharedTrustCommitUncertain) {
				t.Fatal("uncertain write was acknowledged", failAt, err)
			}
			privateFileDirectorySync = originalSync
			actual, err := readSharedJoinStartup(o.TrustPath, protection)
			if err != nil {
				t.Fatal(err)
			}
			if err := selected.Close(); err != nil {
				t.Fatal(err)
			}
			retry := openRecoverableJoin(t, o, actual, protection)
			if err := restoreJoinForTest(context.Background(), retry); err != nil {
				t.Fatal("fresh owned retry could not confirm staging", failAt, err)
			}
			// Even when all files were already visible, retry must do a durable
			// write rather than treating that readback as a confirmed sync.
			privateFileDirectorySync = func(string) error { return errors.New("still uncertain") }
			if err := restoreJoinForTest(context.Background(), retry); !errors.Is(err, errSharedTrustCommitUncertain) {
				t.Fatal("matching readback bypassed durability confirmation", err)
			}
			privateFileDirectorySync = originalSync
		})
	}
}

func TestRecoverableJoinAuthenticatesSnapshotRecordsAndRole(t *testing.T) {
	for _, mode := range []string{"pending", "transport", "role", "directory"} {
		t.Run(mode, func(t *testing.T) {
			f, _, p, protection, o := recoverableJoinFixture(t)
			switch mode {
			case "pending":
				p.Pending = []byte("unauthenticated intent")
			case "transport":
				p.Transport = []byte("unauthenticated transport")
			case "role":
				pending, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
				if err != nil {
					t.Fatal(err)
				}
				settings := o.Settings
				settings.DeviceRole = "another_device"
				p.Transport, err = sharedpg.SealTransportSetup(f.root, o.Binding, settings, pending.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API)
				if err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(sharedTransportSetupPath(o.TrustPath), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := persistSharedJoinStartupValue(context.Background(), o.TrustPath, p, protection); err != nil {
				t.Fatal(err)
			}
			selected := openRecoverableJoin(t, o, p, protection)
			if err := restoreJoinForTest(context.Background(), selected); err == nil {
				t.Fatal("OS protection replaced password-root record authentication", mode)
			}
			if _, err := os.Lstat(sharedDeviceEnrollmentPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid bundle wrote device state", mode, err)
			}
		})
	}
}
