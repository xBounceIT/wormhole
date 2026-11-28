package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedDeviceTransitionFixture(t *testing.T) (*recoveryFixture, sharedDevicePasswordCandidate, []byte, []byte, sharedpg.TrustState) {
	t.Helper()
	j, f, p, _ := preparedDeviceJoinFixture(t)
	if _, err := j.joinPrepared(context.Background(), f.o, p); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	target, err := sharedpg.PrepareDevicePasswordFile(context.Background(), p.key, source, p.slots.VaultID, p.slots.FileID, 1, []byte("new-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	return f, sharedDevicePasswordCandidate{p.key, target, p.slots.VaultID, p.slots.FileID, 1}, source, bytes.Repeat([]byte{95}, 32), state
}

func TestSharedDeviceTransitionLifecycle(t *testing.T) {
	for _, mode := range []string{"commit", "abort", "device-sync", "setup-sync", "trust-sync", "cleanup-sync", "changed-device", "missing-device", "bad-candidate", "bad-key", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			f, device, source, newRoot, state := sharedDeviceTransitionFixture(t)
			path := f.o.TrustPath
			originalSync := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = originalSync })
			if mode == "bad-candidate" {
				device.next = []byte("{}")
			}
			if mode == "bad-key" {
				device.storageRoot = bytes.Repeat([]byte{7}, 32)
			}
			if mode == "missing-source" {
				if err := os.Remove(sharedDeviceEnrollmentPath(path)); err != nil {
					t.Fatal(err)
				}
			}
			record, err := stageSharedTrustRootTransitionWithDevice(path, f.root, newRoot, f.o.Binding, state.Revision, &device)
			if mode == "bad-candidate" || mode == "bad-key" || mode == "missing-source" {
				if err == nil {
					t.Fatal("invalid device staged")
				}
				if _, e := os.Stat(sharedTrustTransitionPath(path)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("invalid journal", e)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := confirmSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err != nil {
				t.Fatal(err)
			}
			if got, e := os.ReadFile(sharedDeviceEnrollmentPath(path)); e != nil || !bytes.Equal(got, source) {
				t.Fatal("candidate activated before commit", e)
			}
			if _, e := readActiveSharedTrustFile(path, f.root, f.o.Binding, 1); e == nil {
				t.Fatal("pending did not block admission")
			}
			if mode == "abort" {
				if err := abortSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err != nil {
					t.Fatal(err)
				}
				if got, e := os.ReadFile(sharedDeviceEnrollmentPath(path)); e != nil || !bytes.Equal(got, source) {
					t.Fatal("abort changed device", e)
				}
				return
			}
			if mode == "changed-device" || mode == "missing-device" {
				if mode == "changed-device" {
					err = os.WriteFile(sharedDeviceEnrollmentPath(path), []byte("foreign"), 0600)
				} else {
					err = os.Remove(sharedDeviceEnrollmentPath(path))
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := confirmSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err == nil {
					t.Fatal("changed source confirmed")
				}
				if err := promoteSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err == nil {
					t.Fatal("changed source promoted")
				}
				if err := abortSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err == nil {
					t.Fatal("changed source aborted")
				}
				return
			}
			writes := 0
			if mode != "commit" {
				failAt := map[string]int{"device-sync": 1, "setup-sync": 2, "trust-sync": 3, "cleanup-sync": 4}[mode]
				privateFileDirectorySync = func(dir string) error {
					writes++
					if writes == failAt {
						return os.ErrPermission
					}
					return originalSync(dir)
				}
				if err := promoteSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err == nil {
					t.Fatal("sync failure ignored")
				}
				privateFileDirectorySync = originalSync
				if err := abortSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err == nil {
					t.Fatal("partially committed device aborted")
				}
			}
			if err := promoteSharedTrustRootTransition(path, newRoot, f.o.Binding, record); err != nil {
				t.Fatal("commit/retry", err)
			}
			if got, e := os.ReadFile(sharedDeviceEnrollmentPath(path)); e != nil || !bytes.Equal(got, device.next) {
				t.Fatal("candidate not published", e)
			}
			if _, e := readActiveSharedTrustFile(path, newRoot, f.o.Binding, record.Next.Revision); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(sharedTrustTransitionPath(path)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("journal remains", e)
			}
		})
	}
}

func TestSharedDevicePasswordChangeOutcomes(t *testing.T) {
	for _, mode := range []string{"commit", "rejected", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			f, device, source, newRoot, _ := sharedDeviceTransitionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			probe := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: f.probe.response, loginMaterial: f.probe.loginMaterial, accountState: f.probe.accountState, enrollmentMaterial: f.probe.enrollmentMaterial}
			c := newSharedAdmissionControllerWithSession(probe)
			t.Cleanup(func() {
				if err := c.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if err := c.OpenAccountFromSetup(context.Background(), f.o, f.root, f.master); err != nil {
				t.Fatal("reopen", err)
			}
			calls := 0
			probe.changePassword = func(_ context.Context, _ *sharedpg.PreparedPasswordChange, _ string) (*sharedpg.PasswordChangeReceipt, error) {
				calls++
				record, err := readSharedTrustRootTransition(f.o.TrustPath, newRoot, f.o.Binding)
				if err != nil || record.Device == nil {
					t.Fatal("SQL preceded journal", err)
				}
				if got, e := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath)); e != nil || !bytes.Equal(got, source) {
					t.Fatal("early publication", e)
				}
				if mode == "rejected" {
					return nil, sharedpg.ErrAuditUnavailable
				}
				if mode == "uncertain" {
					return nil, sharedpg.ErrPasswordChangeUncertain
				}
				return &sharedpg.PasswordChangeReceipt{WrappingRevision: record.Next.WrappingRevision, AuthEpoch: 2}, nil
			}
			var receipt *sharedpg.PasswordChangeReceipt
			err := f.master.Use(func(master []byte, preset vault.KDFPreset, ask bool) error {
				var e error
				receipt, e = c.ChangeDevicePassword(context.Background(), master, bytes.Repeat([]byte{94}, 32), newRoot, preset, ask, "ui", device)
				return e
			})
			if calls != 1 || (mode == "commit") != (err == nil) || (mode == "commit") != (receipt != nil) {
				t.Fatal(mode, calls, receipt, err)
			}
			got, e := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
			if e != nil {
				t.Fatal(e)
			}
			want := source
			if mode == "commit" {
				want = device.next
			}
			if !bytes.Equal(got, want) {
				t.Fatal("wrong device publication")
			}
			_, e = os.Stat(sharedTrustTransitionPath(f.o.TrustPath))
			if (mode == "uncertain") != (e == nil) {
				t.Fatal("wrong journal retention", e)
			}
		})
	}
}

func TestSharedDevicePasswordRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-password", true: "new-password"}[committed], func(t *testing.T) {
			f, device, source, newRoot, state := sharedDeviceTransitionFixture(t)
			if _, err := stageSharedTrustRootTransitionWithDevice(f.o.TrustPath, f.root, newRoot, f.o.Binding, state.Revision, &device); err != nil {
				t.Fatal(err)
			}
			actual := *f.account
			var master []byte
			err := f.master.Use(func(old []byte, _ vault.KDFPreset, _ bool) error {
				master = bytes.Clone(old)
				if committed {
					vault.Wipe(master)
					master = bytes.Repeat([]byte{96}, 32)
					var e error
					actual.Binding, actual.Envelope, e = vault.RewrapUserKeys(old, master, actual.Binding, actual.Envelope, actual.EnrollmentCertificate.Rekey.Public)
					return e
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(master)
			ctx, cancel := context.WithCancel(context.Background())
			probe := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: f.probe.response, accountState: func(context.Context) (*vault.UserKeyState, error) { return actual.State, nil }}
			probe.loginMaterial, err = vault.DeriveKey(master, nil, vault.PurposeLogin)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(probe.loginMaterial)
			probe.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
				if probe.starts.Load() != 1 {
					t.Fatal("capsule before fresh proof")
				}
				return &actual, nil
			}
			probe.changePassword = func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error) {
				t.Fatal("recovery retried mutation")
				return nil, nil
			}
			c := newSharedAdmissionControllerWithSession(probe)
			t.Cleanup(func() {
				if err := c.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			credential := sharedRecoveryOldPassword
			if committed {
				credential = sharedRecoveryNewPassword
			}
			result, err := c.RecoverPasswordChangeFromSetup(context.Background(), f.o, master, newRoot, f.root, actual.KDF, actual.ASKRequired, credential)
			if err != nil || result == nil || result.Changed != committed {
				t.Fatal("recovery", result, err)
			}
			want := source
			if committed {
				want = device.next
			}
			got, err := os.ReadFile(sharedDeviceEnrollmentPath(f.o.TrustPath))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("wrong recovered device", err)
			}
			if _, err := os.Stat(sharedTrustTransitionPath(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("journal remains", err)
			}
		})
	}
}

func TestSharedLegacyTransitionRejectsUnexpectedDevice(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			path, old, next, b, state := sharedTransitionFixture(t)
			record, err := stageSharedTrustRootTransition(path, old, next, b, state.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if directory {
				err = os.Mkdir(sharedDeviceEnrollmentPath(path), 0700)
			} else {
				err = os.WriteFile(sharedDeviceEnrollmentPath(path), []byte("unexpected"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := confirmSharedTrustRootTransition(path, next, b, record); err == nil {
				t.Fatal("unexpected device confirmed")
			}
			if err := promoteSharedTrustRootTransition(path, next, b, record); err == nil {
				t.Fatal("unexpected device promoted")
			}
			if err := abortSharedTrustRootTransition(path, next, b, record); err == nil {
				t.Fatal("unexpected device discarded")
			}
			if _, err := readSharedTrustFile(path, old, b, state.Revision); err != nil {
				t.Fatal("active source lost", err)
			}
		})
	}
}
