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

func transportTransitionFileFixture(t *testing.T) (sharedAdmissionOptions, []byte, []byte, sharedpg.TrustState, []byte) {
	t.Helper()
	path, old, next, b, state := sharedTransitionFixture(t)
	o := sharedAdmissionOptions{TrustPath: path, Binding: b, MinimumRevision: 1, Request: sharedpg.AdmissionRequest{API: 1, AppVersion: "1.2.3", Source: "ui", WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID}, Settings: sharedpg.Settings{Changes: sharedpg.ChangePolicy{TransactionPooler: true, ConcurrentDevices: 700}, Endpoints: []sharedpg.Endpoint{{Host: "localhost", Port: 5432}}, Database: "workspace", DeviceRole: "device_1", TLS: sharedpg.TLSVerified, Profile: vault.Standard, CAPEM: sharedControllerCA(t)}, OSFloor: vault.Default, UserFloor: vault.Default}
	raw, err := sharedpg.SealTransportSetup(old, b, o.Settings, state, o.OSFloor, o.UserFloor, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedTransitionBytes(sharedTransportSetupPath(path), raw); err != nil {
		t.Fatal(err)
	}
	return o, old, next, state, raw
}

func TestSharedTransportTransitionDurability(t *testing.T) {
	for _, phase := range []string{"success", "stage", "setup", "trust", "cleanup"} {
		t.Run(phase, func(t *testing.T) {
			o, old, next, state, source := transportTransitionFileFixture(t)
			syncDirectory := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = syncDirectory })
			calls := 0
			failAt := map[string]int{"stage": 1, "setup": 1, "trust": 2, "cleanup": 3}[phase]
			fail := func(path string) error {
				calls++
				if calls == failAt {
					return os.ErrPermission
				}
				return syncDirectory(path)
			}
			if phase == "stage" {
				privateFileDirectorySync = fail
			}
			record, err := stageSharedTrustRootTransition(o.TrustPath, old, next, o.Binding, state.Revision)
			if phase == "stage" {
				if err != errSharedTrustCommitUncertain {
					t.Fatal(err)
				}
				privateFileDirectorySync = syncDirectory
				if err := confirmSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if record.Transport == nil || record.FormatVersion != 2 {
				t.Fatal("setup omitted")
			}
			if _, err := readActiveSharedTrustFile(o.TrustPath, old, o.Binding, 1); err != errSharedTrustTransitionPending {
				t.Fatal("ordinary admission ignored pending password change", err)
			}
			actual, err := os.ReadFile(sharedTransportSetupPath(o.TrustPath))
			if err != nil || !bytes.Equal(actual, source) {
				t.Fatal("staging changed original setup", err)
			}
			if phase != "stage" && phase != "success" {
				privateFileDirectorySync = fail
			}
			err = promoteSharedTrustRootTransition(o.TrustPath, next, o.Binding, record)
			if phase == "setup" || phase == "trust" {
				if err != errSharedTrustCommitUncertain {
					t.Fatal("wrong uncertainty", err)
				}
				if _, e := readSharedTrustRootTransition(o.TrustPath, next, o.Binding); e != nil {
					t.Fatal("journal lost", e)
				}
				if e := abortSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); e == nil {
					t.Fatal("aborted partially promoted setup")
				}
			} else if phase == "cleanup" {
				if err != errSharedTrustTransitionCleanup {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			privateFileDirectorySync = syncDirectory
			for attempt := 0; attempt < 2; attempt++ {
				if err := promoteSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); err != nil {
					t.Fatal("promotion retry", err)
				}
			}
			current, err := readActiveSharedTrustFile(o.TrustPath, next, o.Binding, record.Next.Revision)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := readSharedTransportSetup(o, next, current)
			if err != nil || !reflect.DeepEqual(restored.Endpoints, o.Settings.Endpoints) || restored.Changes != o.Settings.Changes {
				t.Fatal("new root setup", err)
			}
			if _, err := readSharedTransportSetup(o, old, current); err == nil {
				t.Fatal("old root retained configuration")
			}
		})
	}
}

func TestSharedTransportTransitionConflicts(t *testing.T) {
	for _, mode := range []string{"changed", "missing", "corrupt", "unexpected-legacy"} {
		t.Run(mode, func(t *testing.T) {
			o, old, next, state, _ := transportTransitionFileFixture(t)
			if mode == "unexpected-legacy" {
				if err := os.Remove(sharedTransportSetupPath(o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			}
			record, err := stageSharedTrustRootTransition(o.TrustPath, old, next, o.Binding, state.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				if err := os.Remove(sharedTransportSetupPath(o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(sharedTransportSetupPath(o.TrustPath), []byte("foreign setup"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := confirmSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); err == nil {
				t.Fatal("confirmed changed source")
			}
			if err := promoteSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); err == nil {
				t.Fatal("overwrote changed source")
			}
			if err := abortSharedTrustRootTransition(o.TrustPath, next, o.Binding, record); err == nil {
				t.Fatal("erased conflict journal")
			}
			if _, err := readSharedTrustRootTransition(o.TrustPath, next, o.Binding); err != nil {
				t.Fatal("lost journal", err)
			}
			if _, err := readSharedTrustFile(o.TrustPath, old, o.Binding, state.Revision); err != nil {
				t.Fatal("changed trust before setup conflict", err)
			}
		})
	}
}

func TestSharedTransportTransitionAbort(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "rollback"}[rollback], func(t *testing.T) {
			o, old, next, state, source := transportTransitionFileFixture(t)
			record, err := stageSharedTrustRootTransition(o.TrustPath, old, next, o.Binding, state.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if rollback {
				err = rollbackSharedTrustRootTransition(o.TrustPath, next, old, o.Binding, record)
			} else {
				err = abortSharedTrustRootTransition(o.TrustPath, next, o.Binding, record)
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(sharedTransportSetupPath(o.TrustPath))
			if err != nil || !bytes.Equal(actual, source) {
				t.Fatal("abort changed setup", err)
			}
			if _, err := readSharedTransportSetup(o, old, state); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(sharedTrustTransitionPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("journal retained", err)
			}
		})
	}
}

func TestSharedPasswordRecoveryProtectedSetup(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-password", true: "new-password"}[committed], func(t *testing.T) {
			c, p, o, master, newRoot, oldRoot, _, _ := sharedRecoveryFixtureWithSetup(t, committed, true)
			expected := o.Settings
			p.open = func(_ context.Context, s sharedpg.Settings) error {
				if !reflect.DeepEqual(s.Endpoints, expected.Endpoints) || s.DeviceRole != expected.DeviceRole || s.TLS != expected.TLS {
					t.Fatal("used caller settings")
				}
				return nil
			}
			o.Settings = sharedpg.Settings{DeviceRole: "attacker", TLS: sharedpg.TLSOff}
			credential := sharedRecoveryOldPassword
			destination := oldRoot
			if committed {
				credential = sharedRecoveryNewPassword
				destination = newRoot
				oldRoot = nil
			}
			result, err := c.RecoverPasswordChangeFromSetup(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, credential)
			if err != nil || result == nil || result.Changed != committed {
				t.Fatal("recovery", result, err)
			}
			state, err := readActiveSharedTrustFile(o.TrustPath, destination, o.Binding, result.TrustRevision)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readSharedTransportSetup(o, destination, state); err != nil {
				t.Fatal("configuration not finalized", err)
			}
		})
	}
}

func TestSharedPasswordRecoverySetupFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "relative", "canceled", "missing", "legacy", "revoked", "policy"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, master, next, old, _, org := sharedRecoveryFixtureWithSetup(t, true, mode != "legacy")
			ctx := context.Background()
			switch mode {
			case "nil-context":
				ctx = nil
			case "relative":
				o.TrustPath = "relative"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing":
				if err := os.Remove(sharedTrustTransitionPath(o.TrustPath)); err != nil {
					t.Fatal(err)
				}
			case "policy":
				o.Request.API = 99
			case "revoked":
				record, err := readSharedTrustRootTransition(o.TrustPath, next, o.Binding)
				if err != nil {
					t.Fatal(err)
				}
				state := *record.Previous.Account
				state.Sequence++
				state.Active = false
				state, err = vault.SignUserKeyState(state, org)
				if err != nil {
					t.Fatal(err)
				}
				observed, err := record.ObserveAccount(o.Binding, state, record.Previous.WrappingRevision)
				if err != nil {
					t.Fatal(err)
				}
				if err := writeSharedTrustObservation(o.TrustPath, next, o.Binding, record, observed); err != nil {
					t.Fatal(err)
				}
			}
			result, err := c.RecoverPasswordChangeFromSetup(ctx, o, master, next, old, vault.KDFV1, false, sharedRecoveryNewPassword)
			if err == nil || result != nil || p.opens.Load() != 0 {
				t.Fatal("unsafe protected recovery", err)
			}
		})
	}
}

func TestSharedPasswordTransitionBlocksOrdinaryDial(t *testing.T) {
	o, old, next, state, _ := transportTransitionFileFixture(t)
	if _, err := stageSharedTrustRootTransition(o.TrustPath, old, next, o.Binding, state.Revision); err != nil {
		t.Fatal(err)
	}
	c, p, _, _, _, _ := sharedControllerFixture(t, vault.Standard)
	if err := c.Open(context.Background(), o, old, bytes.Repeat([]byte{7}, 32)); err != errSharedTrustTransitionPending {
		t.Fatal(err)
	}
	if p.opens.Load() != 0 || p.starts.Load() != 0 || c.Admitted() {
		t.Fatal("ordinary connection crossed incomplete publication")
	}
}

func TestSharedTransportTransitionCorruptSource(t *testing.T) {
	for _, mode := range []string{"corrupt", "directory"} {
		t.Run(mode, func(t *testing.T) {
			o, old, next, state, _ := transportTransitionFileFixture(t)
			path := sharedTransportSetupPath(o.TrustPath)
			if mode == "corrupt" {
				if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stageSharedTrustRootTransition(o.TrustPath, old, next, o.Binding, state.Revision); err == nil {
				t.Fatal("ignored invalid sidecar")
			}
			if _, err := os.Lstat(sharedTrustTransitionPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("staged invalid source", err)
			}
		})
	}
}

func TestSharedPasswordChangeStagesTransport(t *testing.T) {
	for _, mode := range []string{"commit", "rejected", "uncertain", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, old, master, account, _ := sharedPasswordFixture(t)
			current, err := readSharedTrustFile(o.TrustPath, old, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			source, err := sharedpg.SealTransportSetup(old, o.Binding, o.Settings, current, o.OSFloor, o.UserFloor, 1)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "corrupt" {
				source = []byte("bad")
			}
			if err := persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), source); err != nil {
				t.Fatal(err)
			}
			next := bytes.Repeat([]byte{94}, 32)
			calls := 0
			p.changePassword = func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error) {
				calls++
				pending, e := readSharedTrustRootTransition(o.TrustPath, next, o.Binding)
				if e != nil || pending.Transport == nil {
					t.Fatal("dispatch preceded complete journal", e)
				}
				payload, e := pending.TransportCiphertext(next, o.Binding)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := sharedpg.OpenTransportSetup(next, o.Binding, payload, pending.Previous, o.OSFloor, o.UserFloor, 1); e != nil {
					t.Fatal("unrecoverable setup before dispatch", e)
				}
				actual, e := os.ReadFile(sharedTransportSetupPath(o.TrustPath))
				if e != nil || !bytes.Equal(actual, source) {
					t.Fatal("setup promoted before remote outcome", e)
				}
				switch mode {
				case "rejected":
					return nil, sharedpg.ErrAuditUnavailable
				case "uncertain":
					return nil, sharedpg.ErrPasswordChangeUncertain
				}
				return &sharedpg.PasswordChangeReceipt{WrappingRevision: account.Binding.Revision + 1, AuthEpoch: 2}, nil
			}
			receipt, err := c.ChangePassword(context.Background(), master, bytes.Repeat([]byte{93}, 32), next, vault.KDFV1, false, "ui")
			if mode == "commit" {
				if err != nil || receipt == nil {
					t.Fatal(err)
				}
				state, e := readActiveSharedTrustFile(o.TrustPath, next, o.Binding, 1)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := readSharedTransportSetup(o, next, state); e != nil {
					t.Fatal(e)
				}
			} else if err == nil || receipt != nil {
				t.Fatal("invented commit", err)
			}
			expectedCalls := 1
			if mode == "corrupt" {
				expectedCalls = 0
			}
			if calls != expectedCalls {
				t.Fatal("dispatch count", calls)
			}
			if mode == "rejected" || mode == "uncertain" {
				actual, e := os.ReadFile(sharedTransportSetupPath(o.TrustPath))
				if e != nil || !bytes.Equal(actual, source) {
					t.Fatal("changed source without commit", e)
				}
			}
		})
	}
}
