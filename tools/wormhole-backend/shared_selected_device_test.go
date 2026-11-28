package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func selectedDeviceFixture(t *testing.T) (*recoveryFixture, *sharedpg.UnlockedDeviceAccount, sharedStartupAnchor, string) {
	t.Helper()
	f, owner := sharedStartupFixture(t)
	a, err := writeSharedStartupAnchor(context.Background(), f.o, owner, "Workspace", 0, startupTestProtection())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	err = owner.BorrowDeviceStorage(func(_ []byte, raw []byte) error {
		slots, _, e := sharedpg.DecodeDeviceEnrollmentFile(raw)
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				id = slot.ID
			}
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, owner, a, id
}

func selectedDeviceController(t *testing.T, f *recoveryFixture) (*sharedAdmissionController, *sharedAdmissionProbe) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: f.probe.response, loginMaterial: f.probe.loginMaterial, accountState: f.probe.accountState, enrollmentMaterial: f.probe.enrollmentMaterial}
	c := newSharedAdmissionControllerWithSession(p)
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return c, p
}

func TestSharedSelectedDeviceOpen(t *testing.T) {
	f, previous, a, id := selectedDeviceFixture(t)
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}
	o := f.o
	o.Binding = sharedpg.TrustBinding{}
	o.Request.DeviceID, o.Request.WorkspaceID, o.Request.UserID = uuid.New(), uuid.New(), uuid.New()
	o.Settings = sharedpg.Settings{Database: "untrusted", DeviceRole: "untrusted"}
	s, err := unlockSharedSelectedDevice(context.Background(), o, id, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, startupTestProtection())
	if s != nil {
		defer s.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if s.options.Binding != a.Binding || s.options.MinimumRevision < a.Trust.Revision {
		t.Fatal("selection was overridden")
	}
	c, p := selectedDeviceController(t, f)
	p.open = func(_ context.Context, got sharedpg.Settings) error {
		if !reflect.DeepEqual(got.Endpoints, f.o.Settings.Endpoints) || got.Database != f.o.Settings.Database || got.DeviceRole != f.o.Settings.DeviceRole {
			t.Fatal("caller redirected selected device")
		}
		return nil
	}
	if _, err := s.RecoverNewPassword(context.Background(), c); err == nil || p.opens.Load() != 0 {
		t.Fatal("ordinary owner entered recovery")
	}
	if err := s.Open(context.Background(), c); err != nil || !c.Unlocked() || p.opens.Load() != 1 {
		t.Fatal("selected open", err)
	}
	if err := s.Close(); err != nil || !c.Unlocked() {
		t.Fatal("admission retained selection owner", err)
	}
	if err := s.Open(context.Background(), c); err == nil {
		t.Fatal("closed selection reused")
	}
	var empty *sharedSelectedDevice
	if empty.Close() != nil || empty.Open(context.Background(), c) == nil {
		t.Fatal("nil selection")
	}
	if _, err := empty.RecoverNewPassword(context.Background(), c); err == nil {
		t.Fatal("nil recovery")
	}
}

func TestSharedSelectedDeviceFailures(t *testing.T) {
	for _, mode := range []string{"nil-context", "canceled", "relative", "mode", "locked", "enrollment", "transition", "missing-anchor", "missing-device", "bad-api", "password", "slot", "profile", "anchor-login", "anchor-kdf", "anchor-binding", "anchor-floor", "anchor-content", "sequence", "missing-trust", "missing-journal"} {
		t.Run(mode, func(t *testing.T) {
			f, _, a, id := selectedDeviceFixture(t)
			o, ctx, password := f.o, context.Background(), []byte("recovery-test-password")
			openMode := sharedDeviceOrdinary
			var remove, marker string
			switch mode {
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "relative":
				o.TrustPath = "relative"
			case "mode":
				openMode = 0
			case "locked":
				release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "enrollment":
				marker = sharedPendingEnrollmentPath(o.TrustPath)
			case "transition":
				marker = sharedTrustTransitionPath(o.TrustPath)
			case "missing-anchor":
				remove = sharedStartupAnchorPath(o.TrustPath)
			case "missing-device":
				remove = sharedDeviceEnrollmentPath(o.TrustPath)
			case "missing-trust":
				remove = o.TrustPath
			case "missing-journal":
				openMode = sharedDevicePasswordRecovery
			case "bad-api":
				o.Request.API = 0
			case "password":
				password = []byte("wrong")
			case "slot":
				id = uuid.NewString()
			case "profile":
				o.UserFloor = vault.Paranoid
			case "anchor-login":
				a.LoginName = "someone-else"
			case "anchor-kdf":
				a.KDF = vault.KDFV1
			case "anchor-binding":
				a.Binding.KeyID = uuid.New()
			case "anchor-floor":
				a.Trust.Revision++
				a.Trust.WrappingRevision++
			case "anchor-content":
				a.Trust.WrappingRevision++
			case "sequence":
				a.MinimumSequence++
			}
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = startupTestProtection().protect("", raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sharedStartupAnchorPath(f.o.TrustPath), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if remove != "" {
				if err := os.Remove(remove); err != nil {
					t.Fatal(err)
				}
			}
			if marker != "" {
				if err := os.WriteFile(marker, []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := unlockSharedSelectedDevice(ctx, o, id, password, nil, openMode, startupTestProtection())
			if s != nil {
				defer s.Close()
			}
			if err == nil || s != nil {
				t.Fatal("invalid selection returned owner", err)
			}
		})
	}
}

func TestSharedSelectedDevicePasswordRecovery(t *testing.T) {
	f, current, _, _ := selectedDeviceFixture(t)
	prepared, err := current.PreparePasswordChange(context.Background(), []byte("new-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	var id string
	err = prepared.BorrowPasswordChange(current, func(_, _ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot, key, raw []byte, selection sharedpg.DeviceUnlockSelection) error {
		slots, _, e := sharedpg.DecodeDeviceEnrollmentFile(raw)
		if e != nil {
			return e
		}
		for _, slot := range slots.Slots {
			if slot.Kind == vault.SlotPassword {
				id = slot.ID
			}
		}
		return root.Use(func(nextRoot []byte) error {
			state, e := readSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, 1)
			if e != nil {
				return e
			}
			_, e = stageSharedTrustRootTransitionWithDevice(f.o.TrustPath, f.root, nextRoot, f.o.Binding, state.Revision, &sharedDevicePasswordCandidate{key, raw, selection.VaultID, selection.FileID, selection.MinimumSequence})
			return e
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := unlockSharedSelectedDevice(context.Background(), f.o, id, []byte("new-password"), nil, sharedDevicePasswordRecovery, startupTestProtection())
	if s != nil {
		defer s.Close()
	}
	if err != nil {
		t.Fatal("restart recovery selection", err)
	}
	c, p := selectedDeviceController(t, f)
	if err := s.Open(context.Background(), c); err == nil || p.opens.Load() != 0 {
		t.Fatal("recovery entered ordinary admission")
	}
	err = s.account.Borrow(func(master *sharedpg.AccountMaster, _ *sharedpg.DeviceTrustRoot) error {
		return master.Use(func(key []byte, _ vault.KDFPreset, _ bool) error {
			var e error
			p.loginMaterial, e = vault.DeriveKey(key, nil, vault.PurposeLogin)
			return e
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(p.loginMaterial)
	// The probe represents the old remote capsule. New-password recovery must
	// reject it, retire its session and retain the journal rather than retry login.
	if _, err := s.RecoverNewPassword(context.Background(), c); err == nil || c.Unlocked() || p.opens.Load() != 1 {
		t.Fatal("invalid remote capsule accepted", err)
	}
	if _, err := os.Stat(sharedTrustTransitionPath(f.o.TrustPath)); err != nil {
		t.Fatal("unproven journal removed", err)
	}
	// A fresh session then observes the actually rewrapped capsule. Cryptographic
	// keys and disk journals are real; only the remote SQL/proof transport is fake.
	actual := *f.account
	err = s.account.Borrow(func(master *sharedpg.AccountMaster, _ *sharedpg.DeviceTrustRoot) error {
		return master.Use(func(next []byte, _ vault.KDFPreset, _ bool) error {
			return f.master.Use(func(old []byte, _ vault.KDFPreset, _ bool) error {
				var e error
				actual.Binding, actual.Envelope, e = vault.RewrapUserKeys(old, next, actual.Binding, actual.Envelope, actual.EnrollmentCertificate.Rekey.Public)
				return e
			})
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	c2, p2 := selectedDeviceController(t, f)
	p2.loginMaterial = p.loginMaterial
	p2.enrollmentMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return &actual, nil }
	result, err := s.RecoverNewPassword(context.Background(), c2)
	if err != nil || result == nil || !result.Changed || c2.Unlocked() || p2.opens.Load() != 1 || p2.starts.Load() != 1 {
		t.Fatal("selected recovery completion", result, err)
	}
	if _, err := os.Stat(sharedTrustTransitionPath(f.o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed journal retained", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := unlockSharedSelectedDevice(context.Background(), f.o, id, []byte("new-password"), nil, sharedDeviceOrdinary, startupTestProtection())
	if reopened != nil {
		defer reopened.Close()
	}
	if err != nil {
		t.Fatal("ordinary restart after recovery", err)
	}
	c3, p3 := selectedDeviceController(t, f)
	p3.loginMaterial = p.loginMaterial
	p3.enrollmentMaterial = p2.enrollmentMaterial
	if err := reopened.Open(context.Background(), c3); err != nil || !c3.Unlocked() {
		t.Fatal("recovered device admission", err)
	}
}

func TestSharedSelectedDeviceRetainsObservedFloor(t *testing.T) {
	f, _, a, id := selectedDeviceFixture(t)
	next, err := a.Trust.AdvanceAccount(*a.Trust.Account, a.Trust.WrappingRevision+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, next, a.Trust.Revision); err != nil {
		t.Fatal(err)
	}
	s, err := unlockSharedSelectedDevice(context.Background(), f.o, id, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, startupTestProtection())
	if s != nil {
		defer s.Close()
	}
	if err != nil || s.options.MinimumRevision != next.Revision {
		t.Fatal("new observation lost", err)
	}
	// Simulate replacement by a previously valid protected file between native
	// selection and admission. The newly observed floor must block network I/O.
	if err := persistSharedTrustFile(f.o.TrustPath, f.root, f.o.Binding, a.Trust); err != nil {
		t.Fatal(err)
	}
	c, p := selectedDeviceController(t, f)
	if err := s.Open(context.Background(), c); err == nil || p.opens.Load() != 0 {
		t.Fatal("rollback after selection admitted", err)
	}
}

func TestSharedSelectedDeviceAnchoredProfileBeforeUnlock(t *testing.T) {
	f, _, a, id := selectedDeviceFixture(t)
	policy, err := a.Trust.Policy()
	if err != nil {
		t.Fatal(err)
	}
	policy.Profile, policy.KDF, policy.LowKDFApproved = vault.Hardened, vault.KDFV2, false
	policy.Sequence++
	signed, err := vault.SignPolicy(policy, a.Trust.SignerKeyID, a.Trust.SignerKeyVersion, f.org)
	if err != nil {
		t.Fatal(err)
	}
	a.Trust.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(a.Trust.SignedProfile)
	a.Trust.PolicyDigest, a.Trust.PolicySequence, a.KDF = digest[:], policy.Sequence, policy.KDF
	if !a.valid(f.o.TrustPath) {
		t.Fatal("invalid anchored profile fixture")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = startupTestProtection().protect("", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedStartupAnchorPath(f.o.TrustPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// A missing device distinguishes rejecting the trusted profile before file
	// access/KDF from eventually rejecting a mismatched account after unlocking it.
	if err := os.Remove(sharedDeviceEnrollmentPath(f.o.TrustPath)); err != nil {
		t.Fatal(err)
	}
	s, err := unlockSharedSelectedDevice(context.Background(), f.o, id, []byte("recovery-test-password"), nil, sharedDeviceOrdinary, startupTestProtection())
	if s != nil {
		defer s.Close()
	}
	if !errors.Is(err, errSharedRuntimeUnsupported) || s != nil {
		t.Fatal("profile checked too late", err)
	}
}
