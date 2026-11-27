package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedInvitationCommitSession interface {
	CommitInvitation(context.Context, *sharedpg.PreparedInvitationCommit) error
	Close(context.Context) error
}
type sharedJoinRecovery interface {
	RecoverEnrollmentFromSetup(context.Context, sharedAdmissionOptions, []byte, *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error)
	Close(context.Context) error
}

type sharedInvitationJoinResult struct {
	Submitted     bool // native commit API invoked; unknown outcomes remain explicit
	Committed     bool // receipt or subsequent device confirmation proves commit
	Confirmed     bool
	TrustRevision uint64
}

// This owner consumes one prepared request. Its lifetime is deliberately separate
// from the invitation session: successful commit retires that temporary session.
// Keep the owner and retry Close if native cleanup is unconfirmed.
type sharedInvitationJoin struct {
	lifetime          context.Context
	cancel            context.CancelFunc
	gate              chan struct{}
	started           bool
	submitted         bool
	preparation       *sharedJoinPreparation
	invitation        sharedInvitationCommitSession
	recovery          sharedJoinRecovery
	newRecovery       func() sharedJoinRecovery
	initialInvitation *sharedpg.Invitation      // public native coordinates, fixed before start
	publication       *sharedInitialPublication // ciphertext and owned filesystem identities
}

func newSharedInvitationJoin(session *sharedpg.Session) (*sharedInvitationJoin, error) {
	if session == nil {
		return nil, sharedpg.ErrConfiguration
	}
	return newSharedInvitationJoinWithSession(session, func() sharedJoinRecovery { return newSharedAdmissionController() }), nil
}
func newSharedInvitationJoinWithSession(session sharedInvitationCommitSession, factory func() sharedJoinRecovery) *sharedInvitationJoin {
	ctx, cancel := context.WithCancel(context.Background())
	return &sharedInvitationJoin{lifetime: ctx, cancel: cancel, gate: make(chan struct{}, 1), invitation: session, newRecovery: factory}
}

func (j *sharedInvitationJoin) Close(ctx context.Context) error {
	if ctx == nil {
		return sharedpg.ErrConfiguration
	}
	j.cancel()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := takeSharedAdmissionGate(ctx, j.gate); err != nil {
		return err
	}
	defer func() { <-j.gate }()
	return j.closeLocked(ctx)
}
func (j *sharedInvitationJoin) closeLocked(ctx context.Context) error {
	failed := false
	if j.invitation != nil {
		if j.invitation.Close(ctx) != nil {
			failed = true
		} else {
			j.invitation = nil
		}
	}
	if j.recovery != nil {
		if j.recovery.Close(ctx) != nil {
			failed = true
		} else {
			j.recovery = nil
		}
	}
	if failed {
		return errSharedAdmissionCleanup
	}
	return ctx.Err()
}

// Join borrows the independently unlocked durable device root/binding and master.
// Native setup must already make that root recoverable; a metadata file cannot do
// so. The first started call consumes/Wipes prepared on every path. Repeated calls
// never inspect or wipe a request concurrently owned by the active invocation.
func (j *sharedInvitationJoin) Join(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster, prepared *sharedpg.PreparedInvitationCommit) (result *sharedInvitationJoinResult, err error) {
	if ctx == nil || len(root) != 32 || master == nil || !filepath.IsAbs(o.TrustPath) || o.MinimumRevision != 1 || o.Request.Validate() != nil || o.Binding.WorkspaceID != o.Request.WorkspaceID || o.Binding.UserID != o.Request.UserID || o.Binding.DeviceID != o.Request.DeviceID {
		return nil, sharedpg.ErrConfiguration
	}
	return j.runJoin(ctx, func(ctx context.Context) (*sharedInvitationJoinResult, error) {
		return j.joinLocked(ctx, o, root, master, prepared, nil)
	})
}

func (j *sharedInvitationJoin) runJoin(ctx context.Context, run func(context.Context) (*sharedInvitationJoinResult, error)) (result *sharedInvitationJoinResult, err error) {
	if ctx == nil {
		return nil, sharedpg.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	stop := context.AfterFunc(j.lifetime, cancel)
	defer stop()
	if err := takeSharedAdmissionGate(ctx, j.gate); err != nil {
		return nil, err
	}
	defer func() { <-j.gate }()
	if j.lifetime.Err() != nil {
		return nil, sharedpg.ErrSessionClosed
	}
	if j.started {
		return nil, sharedpg.ErrSessionStarted
	}
	j.started = true
	defer func() {
		j.cancel()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if j.closeLocked(cleanup) != nil {
			err = errors.Join(err, errSharedAdmissionCleanup)
		}
	}()
	return run(ctx)
}

func (j *sharedInvitationJoin) joinLocked(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster, prepared *sharedpg.PreparedInvitationCommit, device *sharedJoinDeviceStorage) (result *sharedInvitationJoinResult, err error) {
	defer func() {
		prepared.Wipe()
		if err != nil && !j.submitted {
			var storageRoot []byte
			if device != nil {
				storageRoot = device.root
			}
			if cleanupErr := j.discardPreparationWithDeviceLocked(root, storageRoot); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	if j.invitation == nil || j.newRecovery == nil {
		return nil, sharedpg.ErrConfiguration
	}
	if err := prepared.ValidateAccountMaster(master); err != nil {
		return nil, err
	}
	pending, err := prepared.PendingEnrollment(o.Binding)
	if err != nil {
		return nil, err
	}
	if master.WorkspaceID() != o.Binding.WorkspaceID || master.LoginName() != pending.Certificate.Manifest.Context.LoginName {
		return nil, sharedpg.ErrConfiguration
	}
	o.Settings.DeviceRole = "wh_" + pending.RoleTag + "_d_" + o.Binding.DeviceID.String()
	if o.Settings.TLSBundle != nil {
		pending, err = pending.ObserveTLS(o.Binding, o.Settings.TLSBundle)
		if err != nil {
			return nil, err
		}
	}
	current := pending.ObservedTrust()
	o.Settings, err = current.PrepareTransport(o.Settings, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(o.Settings.Profile); err != nil {
		return nil, err
	}
	policy, err := current.Policy()
	if err != nil {
		return nil, err
	}
	if err := master.Use(func(_ []byte, preset vault.KDFPreset, ask bool) error {
		if preset != pending.KDF || ask != pending.ASKRequired {
			return sharedpg.ErrAccountRevision
		}
		return validateSharedAccountDerivation(policy, o.Settings.Profile, preset, ask)
	}); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j.preparation = &sharedJoinPreparation{options: o, pending: pending}
	if j.initialInvitation != nil {
		if device == nil || device.startup == nil {
			return nil, sharedpg.ErrConfiguration
		}
		initial, err := makeRecoverableSharedJoinStartup(o, device, root, pending)
		if err != nil {
			return nil, err
		}
		initial.Continuation, err = prepared.SealContinuation(root, o.Binding, *j.initialInvitation)
		if err != nil {
			return nil, err
		}
		initial.FormatVersion, initial.Purpose = 3, "wormhole/shared-join-startup/v3"
		j.publication, err = publishSharedInitialBundle(ctx, o, initial, *device.startup)
		if j.publication != nil && j.publication.published {
			j.preparation.startup, j.preparation.startupProtection = &initial, device.startup
			j.preparation.directory = j.publication.directory
			j.preparation.setupOwned, j.preparation.pendingOwned = true, true
			j.preparation.deviceRaw = initial.DeviceFile
		}
		if err != nil {
			return nil, err
		}
		o.startupProtection = device.startup
		j.preparation.options = o
	} else {
		if device != nil && device.startup != nil {
			initial, err := makeRecoverableSharedJoinStartup(o, device, root, pending)
			if err != nil {
				return nil, err
			}
			err = writeSharedJoinStartup(ctx, o.TrustPath, initial, *device.startup, false)
			if err == nil || errors.Is(err, errSharedTrustCommitUncertain) {
				j.preparation.startup, j.preparation.startupProtection = &initial, device.startup
			}
			if errors.Is(err, errSharedTrustCommitUncertain) {
				err = writeSharedJoinStartup(ctx, o.TrustPath, initial, *device.startup, true)
			}
			if err != nil {
				return nil, err
			}
			o.startupProtection = device.startup
			j.preparation.options.startupProtection = device.startup
		}
		if device != nil {
			if err := j.stageDeviceLocked(o, device); err != nil {
				return nil, err
			}
		}
		err = stageSharedTransportSetup(o, root, current)
		j.preparation.setupOwned = err == nil || errors.Is(err, errSharedTrustCommitUncertain)
		if errors.Is(err, errSharedTrustCommitUncertain) {
			err = confirmSharedTransportSetup(o, root, current)
		}
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if o.Settings.TLSBundle != nil {
			if err := writeSharedTLSCache(o.TrustPath, o.Settings.TLSBundle); err != nil {
				return nil, err
			}
		}
		err = stageSharedPendingEnrollment(o.TrustPath, root, o.Binding, pending)
		j.preparation.pendingOwned = err == nil || errors.Is(err, errSharedTrustCommitUncertain)
		if errors.Is(err, errSharedTrustCommitUncertain) {
			err = confirmSharedPendingEnrollment(o.TrustPath, root, o.Binding, pending)
		}
		if err != nil {
			return nil, err
		}
	}
	// Recheck both protected records immediately before the only SQL submission.
	if err := confirmSharedTransportSetup(o, root, current); err != nil {
		return nil, err
	}
	if err := confirmSharedPendingEnrollment(o.TrustPath, root, o.Binding, pending); err != nil {
		return nil, err
	}
	if device != nil {
		if err := j.confirmDeviceWithIntentLocked(o, root, device, pending); err != nil {
			return nil, err
		}
		if device.startup != nil {
			if err := writeSharedJoinStartup(ctx, o.TrustPath, *j.preparation.startup, *device.startup, true); err != nil {
				return nil, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return j.commitAndRecover(ctx, o, root, master, prepared)
}

func (j *sharedInvitationJoin) commitAndRecover(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster, prepared *sharedpg.PreparedInvitationCommit) (result *sharedInvitationJoinResult, err error) {
	result = &sharedInvitationJoinResult{Submitted: true}
	j.submitted = true
	j.preparation = nil
	commitErr := j.invitation.CommitInvitation(ctx, prepared)
	prepared.Wipe()
	if commitErr != nil && !errors.Is(commitErr, sharedpg.ErrInvitationCommitUncertain) {
		return result, commitErr
	}
	result.Committed = commitErr == nil
	// A fresh device connection cannot outlive an unconfirmed invitation cleanup.
	cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := j.invitation.Close(cleanup)
	done()
	if closeErr != nil {
		return result, errors.Join(commitErr, errSharedAdmissionCleanup)
	}
	j.invitation = nil
	if err := ctx.Err(); err != nil {
		return result, errors.Join(commitErr, err)
	}
	j.recovery = j.newRecovery()
	if j.recovery == nil {
		return result, errors.Join(commitErr, sharedpg.ErrConfiguration)
	}
	recovered, recoveryErr := j.recovery.RecoverEnrollmentFromSetup(ctx, o, root, master)
	if recovered != nil && recovered.Confirmed {
		result.Committed, result.Confirmed, result.TrustRevision = true, true, recovered.TrustRevision
		return result, recoveryErr
	}
	if recoveryErr == nil {
		recoveryErr = sharedpg.ErrAdmissionResponse
	}
	return result, errors.Join(commitErr, recoveryErr)
}
