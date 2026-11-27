package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

// The independently selected device still requires PW/ASK. Additional recovery
// records are encrypted under its password-derived account root, not merely OS
// protection. No factor, verifier, master or private key is stored in this bundle.
func makeRecoverableSharedJoinStartup(o sharedAdmissionOptions, device *sharedJoinDeviceStorage, root []byte, pending sharedpg.PendingEnrollment) (sharedJoinStartup, error) {
	p, err := makeSharedJoinStartup(o, device)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	if pending.Certificate.Manifest.Context.LoginName != p.LoginName {
		return sharedJoinStartup{}, sharedpg.ErrTrustState
	}
	p.Pending, err = sharedpg.SealPendingEnrollment(root, o.Binding, pending)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	p.Transport, err = sharedpg.SealTransportSetup(root, o.Binding, o.Settings, pending.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return sharedJoinStartup{}, err
	}
	p.FormatVersion, p.Purpose = 2, "wormhole/shared-join-startup/v2"
	if !p.valid(o.TrustPath) {
		return sharedJoinStartup{}, sharedpg.ErrConfiguration
	}
	return p, nil
}

// Pick a complete monotonically advancing observation, never a field-wise mix.
// Both records must describe exactly the same prepared certificate and capsule.
func newestSharedJoinObservation(binding sharedpg.TrustBinding, a, b sharedpg.PendingEnrollment) (sharedpg.PendingEnrollment, error) {
	if err := a.ValidateObservationSnapshot(binding, b); err == nil {
		return b, nil
	}
	if err := b.ValidateObservationSnapshot(binding, a); err == nil {
		return a, nil
	}
	return sharedpg.PendingEnrollment{}, sharedpg.ErrTrustRollback
}

// This is published BEFORE the ordinary pending file. If that file is removed,
// recovery retains the policy, account and TLS floors already exposed by a
// previous recovery attempt, including a revocation that prevented admission.
func mirrorSharedJoinObservation(o sharedAdmissionOptions, root []byte, expected, next sharedpg.PendingEnrollment) error {
	if !filepath.IsAbs(o.TrustPath) || filepath.Clean(o.TrustPath) != o.TrustPath {
		return sharedpg.ErrConfiguration
	}
	if err := requireNoSharedJoinStartup(o.TrustPath); err == nil {
		return nil
	} else if !errors.Is(err, errSharedTrustConflict) {
		return err
	}
	if o.startupProtection == nil {
		return errSharedTrustStorage
	}
	if err := expected.ValidateObservationAdvance(o.Binding, next); err != nil {
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
	if p.FormatVersion == 1 {
		return nil // legacy snapshots do not authorize missing-file reconstruction
	}
	if p.Binding != o.Binding {
		return sharedpg.ErrTrustState
	}
	current, err := sharedpg.OpenPendingEnrollment(root, o.Binding, p.Pending)
	if err != nil {
		return err
	}
	if err := current.ValidateObservationSnapshot(o.Binding, next); err != nil {
		return err
	}
	// Rewrite even an exact next value: matching readback does not confirm sync.
	p.Pending, err = sharedpg.SealPendingEnrollment(root, o.Binding, next)
	if err != nil {
		return err
	}
	// A newly observed profile may deliberately reject the old transport. Keep
	// that transport rather than losing the stronger observation on a seal error.
	if transport, err := sharedpg.SealTransportSetup(root, o.Binding, o.Settings, next.ObservedTrust(), o.OSFloor, o.UserFloor, o.Request.API); err == nil {
		p.Transport = transport
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = persistSharedJoinStartupValue(ctx, o.TrustPath, p, *o.startupProtection)
	if errors.Is(err, errSharedTrustCommitUncertain) {
		err = persistSharedJoinStartupValue(ctx, o.TrustPath, p, *o.startupProtection)
	}
	return err
}
