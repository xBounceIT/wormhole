package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func readSharedJoinPiece(path string, maximum int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, errSharedTrustStorage
	}
	raw, err := readBoundedRegularFile(path, maximum)
	if err != nil {
		return nil, false, errSharedTrustStorage
	}
	return raw, false, nil
}

// Reconstruct only authenticated ciphertext from an independently selected v2
// snapshot after PW/ASK unlock. This creates pending local state, not active
// trust or permission to retry SQL. Fresh device/capsule proof remains required.
func restoreSharedJoinStaging(ctx context.Context, selected *sharedSelectedDevice, root []byte, master *sharedpg.AccountMaster) error {
	if ctx == nil || selected == nil || selected.initial == nil || master == nil {
		return sharedpg.ErrConfiguration
	}
	if selected.initial.FormatVersion == 1 {
		return ctx.Err()
	}
	o := selected.options
	if !filepath.IsAbs(o.TrustPath) || filepath.Clean(o.TrustPath) != o.TrustPath || len(root) != 32 || o.startupProtection == nil {
		return errSharedTrustStorage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	release, err := tryAcquireExclusiveFileLock(o.TrustPath + ".lock")
	if err != nil {
		return errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(o.TrustPath); err != nil {
		return err
	}
	p, err := readSharedJoinStartup(o.TrustPath, *o.startupProtection)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(p, *selected.initial) || p.Binding != o.Binding {
		return errSharedTrustConflict
	}
	device, missingDevice, err := readSharedJoinPiece(sharedDeviceEnrollmentPath(o.TrustPath), sharedpg.MaxDeviceEnrollmentFileBytes)
	if err != nil {
		return err
	}
	if !missingDevice && !bytes.Equal(device, p.DeviceFile) {
		return errSharedTrustConflict
	}
	connection, missingConnection, err := readSharedJoinPiece(sharedTransportSetupPath(o.TrustPath), 2*sharedpg.MaxTransportSnapshotBytes)
	if err != nil {
		return err
	}
	// Completed trust/selection has its own floors and recovery. Do not replace
	// it or manufacture a new pending intent over it from the initial snapshot.
	for _, active := range []string{o.TrustPath, sharedStartupAnchorPath(o.TrustPath)} {
		if _, err := os.Lstat(active); err == nil {
			if missingDevice || missingConnection {
				return errSharedTrustConflict
			}
			return ctx.Err()
		} else if !errors.Is(err, os.ErrNotExist) {
			return errSharedTrustStorage
		}
	}
	snapshot, err := sharedpg.OpenPendingEnrollment(root, o.Binding, p.Pending)
	if err != nil {
		return err
	}
	if snapshot.Certificate.Manifest.Context.LoginName != master.LoginName() {
		return sharedpg.ErrTrustState
	}
	intent, missingIntent, err := readSharedJoinPiece(sharedPendingEnrollmentPath(o.TrustPath), sharedpg.MaxPendingEnrollmentBytes)
	if err != nil {
		return err
	}
	pending := snapshot
	intentChanged := false
	if !missingIntent {
		actual, err := sharedpg.OpenPendingEnrollment(root, o.Binding, intent)
		if err != nil {
			return err
		}
		pending, err = newestSharedJoinObservation(o.Binding, snapshot, actual)
		if err != nil {
			return err
		}
		intentChanged = !reflect.DeepEqual(actual, pending)
	}
	trust := pending.ObservedTrust()
	settings, err := openSharedTransportSetup(o, root, trust, p.Transport)
	if err != nil {
		return err
	}
	if settings.DeviceRole != "wh_"+pending.RoleTag+"_d_"+o.Binding.DeviceID.String() {
		return sharedpg.ErrTrustState
	}
	if err := sharedAdmissionRuntimeProfile(settings.Profile); err != nil {
		return err
	}
	policy, err := trust.Policy()
	if err != nil {
		return err
	}
	if err := master.Use(func(_ []byte, preset vault.KDFPreset, ask bool) error {
		if preset != pending.KDF || ask != pending.ASKRequired {
			return sharedpg.ErrAccountRevision
		}
		return validateSharedAccountDerivation(policy, settings.Profile, preset, ask)
	}); err != nil {
		return err
	}
	if !missingConnection {
		actual, err := openSharedTransportSetup(o, root, trust, connection)
		if err != nil {
			return err
		}
		a, err := sharedpg.EncodeTransportSnapshot(actual, trust, o.OSFloor, o.UserFloor, o.Request.API)
		if err != nil {
			return err
		}
		b, err := sharedpg.EncodeTransportSnapshot(settings, trust, o.OSFloor, o.UserFloor, o.Request.API)
		if err != nil || !bytes.Equal(a, b) {
			return errSharedTrustConflict
		}
	}
	changed := !reflect.DeepEqual(snapshot, pending)
	if missingDevice || missingConnection || missingIntent || changed || intentChanged {
		p.Pending, err = sharedpg.SealPendingEnrollment(root, o.Binding, pending)
		if err != nil {
			return err
		}
		p.Transport, err = sharedpg.SealTransportSetup(root, o.Binding, settings, trust, o.OSFloor, o.UserFloor, o.Request.API)
		if err != nil {
			return err
		}
	}
	// Exact readback alone cannot resolve a failed directory sync from a prior
	// restoration. Confirm the selection and parent directory before remote proof.
	if err := persistSharedJoinStartupValue(ctx, o.TrustPath, p, *o.startupProtection); err != nil {
		return err
	}
	*selected.initial = p
	if err := ctx.Err(); err != nil {
		return err
	}
	if missingDevice {
		if err := persistSharedTransitionBytes(sharedDeviceEnrollmentPath(o.TrustPath), p.DeviceFile); err != nil {
			return err
		}
	}
	if missingConnection {
		if err := persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), p.Transport); err != nil {
			return err
		}
	}
	if missingIntent || intentChanged {
		if err := persistSharedTransitionBytes(sharedPendingEnrollmentPath(o.TrustPath), p.Pending); err != nil {
			return err
		}
	}
	return ctx.Err()
}
