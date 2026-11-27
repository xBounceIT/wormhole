package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestRecoverableJoinPreparationRejectsUnboundRecords(t *testing.T) {
	for _, mode := range []string{"device", "binding", "login", "root", "transport"} {
		t.Run(mode, func(t *testing.T) {
			f, d, p, _, o := recoverableJoinFixture(t)
			pending, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
			if err != nil {
				t.Fatal(err)
			}
			device := &sharedJoinDeviceStorage{root: d.key, slots: d.slots, envelope: d.envelope}
			root := f.root
			switch mode {
			case "device":
				device = nil
			case "binding":
				o.Binding.DeviceID = uuid.New()
			case "login":
				pending.Certificate.Manifest.Context.LoginName = "different"
			case "root":
				root = nil
			case "transport":
				o.Settings.Endpoints = nil
			}
			if _, err := makeRecoverableSharedJoinStartup(o, device, root, pending); err == nil {
				t.Fatal("unbound recovery records accepted", mode)
			}
		})
	}
}

func TestRecoverableJoinFormatBoundsAndLegacySelection(t *testing.T) {
	_, _, p, _, o := recoverableJoinFixture(t)
	if !p.valid(o.TrustPath) {
		t.Fatal("valid v2 snapshot rejected")
	}
	for _, mode := range []string{"purpose", "pending", "transport", "large-pending", "large-transport", "future", "legacy-extra"} {
		t.Run(mode, func(t *testing.T) {
			bad := p
			switch mode {
			case "purpose":
				bad.Purpose = "wormhole/shared-join-startup/v1"
			case "pending":
				bad.Pending = nil
			case "transport":
				bad.Transport = nil
			case "large-pending":
				bad.Pending = make([]byte, sharedpg.MaxPendingEnrollmentBytes+1)
			case "large-transport":
				bad.Transport = make([]byte, 2*sharedpg.MaxTransportSnapshotBytes+1)
			case "future":
				bad.FormatVersion = 4
			case "legacy-extra":
				bad.FormatVersion, bad.Purpose = 1, "wormhole/shared-join-startup/v1"
			}
			if bad.valid(o.TrustPath) {
				t.Fatal("invalid or ambiguous format accepted", mode)
			}
		})
	}
	p.FormatVersion, p.Purpose, p.Pending, p.Transport = 1, "wormhole/shared-join-startup/v1", nil, nil
	if !p.valid(o.TrustPath) {
		t.Fatal("canonical v1 selection lost compatibility")
	}
}

func TestRecoverableJoinObservationMirrorPreservesSelectionOnFailure(t *testing.T) {
	for _, mode := range []string{"relative", "protection", "advance", "held", "transition", "corrupt", "binding", "root", "different-capsule", "protect"} {
		t.Run(mode, func(t *testing.T) {
			f, _, p, protection, o := recoverableJoinFixture(t)
			pending, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
			if err != nil {
				t.Fatal(err)
			}
			next := pending
			root := f.root
			switch mode {
			case "relative":
				o.TrustPath = "relative"
			case "protection":
				o.startupProtection = nil
			case "advance":
				next.CapsuleDigest = bytes.Repeat([]byte{2}, 32)
			case "held":
				release, e := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
				if e != nil {
					t.Fatal(e)
				}
				defer release()
			case "transition":
				if e := os.WriteFile(sharedTrustTransitionPath(o.TrustPath), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			case "corrupt":
				if e := os.WriteFile(sharedJoinStartupPath(o.TrustPath), []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			case "binding":
				o.Binding.DeviceID = uuid.New()
			case "root":
				root = bytes.Repeat([]byte{3}, 32)
			case "different-capsule":
				snapshot := pending
				snapshot.CapsuleDigest = bytes.Repeat([]byte{4}, 32)
				p.Pending, err = sharedpg.SealPendingEnrollment(root, o.Binding, snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if err := persistSharedJoinStartupValue(context.Background(), o.TrustPath, p, protection); err != nil {
					t.Fatal(err)
				}
			case "protect":
				protection.protect = func(string, []byte) ([]byte, error) { return nil, errors.New("keystore unavailable") }
				o.startupProtection = &protection
			}
			path := sharedJoinStartupPath(f.o.TrustPath)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := mirrorSharedJoinObservation(o, root, pending, next); err == nil {
				t.Fatal("invalid observation overwrote selection", mode)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed mirror lost existing selection", mode, err)
			}
		})
	}
}

func TestRecoverableJoinMirrorRetriesSyncAndLeavesLegacyUnchanged(t *testing.T) {
	f, _, p, protection, o := recoverableJoinFixture(t)
	pending, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
	if err != nil {
		t.Fatal(err)
	}
	original := privateFileDirectorySync
	t.Cleanup(func() { privateFileDirectorySync = original })
	calls := 0
	privateFileDirectorySync = func(path string) error {
		calls++
		if calls == 1 {
			return errors.New("uncertain directory sync")
		}
		return original(path)
	}
	if err := mirrorSharedJoinObservation(o, f.root, pending, pending); err != nil || calls != 2 {
		t.Fatal("mirror did not confirm uncertain snapshot", calls, err)
	}
	privateFileDirectorySync = original
	p.FormatVersion, p.Purpose, p.Pending, p.Transport = 1, "wormhole/shared-join-startup/v1", nil, nil
	if err := persistSharedJoinStartupValue(context.Background(), o.TrustPath, p, protection); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(sharedJoinStartupPath(o.TrustPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := mirrorSharedJoinObservation(o, f.root, pending, pending); err != nil {
		t.Fatal("legacy recovery changed", err)
	}
	after, err := os.ReadFile(sharedJoinStartupPath(o.TrustPath))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy snapshot was silently upgraded", err)
	}
	if err := os.Remove(sharedJoinStartupPath(o.TrustPath)); err != nil {
		t.Fatal(err)
	}
	if err := mirrorSharedJoinObservation(o, f.root, pending, pending); err != nil {
		t.Fatal("ordinary enrollment acquired an initial selection requirement", err)
	}
}

func TestRecoverableJoinMirrorsStrongerPolicyBeforeTransportDenial(t *testing.T) {
	f, _, p, protection, o := recoverableJoinFixture(t)
	pending, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, p.Pending)
	if err != nil {
		t.Fatal(err)
	}
	o.Settings.TLS, o.Settings.CAPEM, o.Settings.TLSBundle = sharedpg.TLSOff, nil, nil
	p.Transport, err = sharedpg.SealTransportSetup(f.root, o.Binding, o.Settings, pending.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedJoinStartupValue(context.Background(), o.TrustPath, p, protection); err != nil {
		t.Fatal(err)
	}
	policy, err := pending.Trust.Policy()
	if err != nil {
		t.Fatal(err)
	}
	policy.Sequence++
	policy.Profile, policy.KDF, policy.LowKDFApproved = vault.Standard, vault.KDFV1, false
	signed, err := vault.SignPolicy(policy, pending.Trust.SignerKeyID, pending.Trust.SignerKeyVersion, f.org)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	next, err := pending.ObserveProfile(o.Binding, &sharedpg.UnverifiedAdmission{
		WorkspaceID: o.Binding.WorkspaceID, UserID: o.Binding.UserID, DeviceID: o.Binding.DeviceID,
		MinAPI: 1, MaxAPI: 1, SignedProfile: encoded,
	}, o.Request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sharedpg.SealTransportSetup(f.root, o.Binding, o.Settings, next.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API); err == nil {
		t.Fatal("stronger profile unexpectedly accepted TLS Off transport")
	}
	if err := mirrorSharedJoinObservation(o, f.root, pending, next); err != nil {
		t.Fatal("transport rejection erased authenticated stronger policy", err)
	}
	actual, err := readSharedJoinStartup(o.TrustPath, protection)
	if err != nil || !bytes.Equal(actual.Transport, p.Transport) {
		t.Fatal("rejected transport was silently rewritten", err)
	}
	observed, err := sharedpg.OpenPendingEnrollment(f.root, o.Binding, actual.Pending)
	if err != nil || observed.ObservedTrust().PolicySequence != policy.Sequence {
		t.Fatal("snapshot lost stronger policy", err)
	}
	selected := openRecoverableJoin(t, o, actual, protection)
	if err := restoreJoinForTest(context.Background(), selected); err == nil {
		t.Fatal("recovery silently relaxed the stronger profile")
	}
	if _, err := os.Lstat(sharedDeviceEnrollmentPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected profile manufactured device staging", err)
	}
}
