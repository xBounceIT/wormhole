package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedEnrollmentConfirmation func(context.Context) (sharedConfirmedEnrollment, error)
type sharedEnrollmentVerifier func(context.Context, sharedAdmissionSession, sharedpg.TrustBinding, sharedpg.PendingEnrollment, *sharedpg.AccountMaster, *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error)

func nativeSharedEnrollmentVerifier(ctx context.Context, session sharedAdmissionSession, b sharedpg.TrustBinding, p sharedpg.PendingEnrollment, master *sharedpg.AccountMaster, material *sharedpg.UnverifiedAccountKeys) (sharedEnrollmentConfirmation, error) {
	native, ok := session.(*sharedpg.Session)
	if !ok {
		return nil, sharedpg.ErrConfiguration
	}
	proof, err := native.VerifyPendingEnrollment(ctx, b, p, master, material)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (sharedConfirmedEnrollment, error) {
		return native.ConfirmVerifiedEnrollment(ctx, b, p, proof)
	}, nil
}

// Confirmed describes the remote device, not successful local publication when
// an error accompanies this result. This recovery owner never becomes unlocked.
type sharedEnrollmentRecoveryResult struct {
	Confirmed     bool
	TrustRevision uint64
}

// RecoverEnrollmentFromSetup uses only the protected on-disk transport settings.
// Callers still supply the independently unlocked root/binding and current local
// floors; caller Settings cannot redirect this recovery to a different endpoint.
func (c *sharedAdmissionController) RecoverEnrollmentFromSetup(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster) (*sharedEnrollmentRecoveryResult, error) {
	if ctx == nil || !filepath.IsAbs(o.TrustPath) {
		return nil, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pending, err := readSharedPendingEnrollment(o.TrustPath, root, o.Binding)
	if err != nil {
		return nil, err
	}
	if err := validateSharedEnrollmentState(pending); err != nil {
		return nil, err
	}
	o.Settings, err = readSharedTransportSetup(o, root, pending.ObservedTrust())
	if err != nil {
		return nil, err
	}
	return c.RecoverEnrollment(ctx, o, root, master)
}

// RecoverEnrollment never submits/retries commit_invitation. Options and root
// must come from authenticated native setup, never renderer assertions. Call with
// a fresh owner and the same pending device; retain/Close it if cleanup fails.
func (c *sharedAdmissionController) RecoverEnrollment(ctx context.Context, o sharedAdmissionOptions, root []byte, master *sharedpg.AccountMaster) (result *sharedEnrollmentRecoveryResult, err error) {
	if ctx == nil || len(root) != 32 || master == nil || master.WorkspaceID() != o.Binding.WorkspaceID || !filepath.IsAbs(o.TrustPath) || o.MinimumRevision == 0 || o.Request.Validate() != nil || o.Binding.WorkspaceID != o.Request.WorkspaceID || o.Binding.UserID != o.Request.UserID || o.Binding.DeviceID != o.Request.DeviceID || c.verifyEnrollment == nil {
		return nil, sharedpg.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return nil, err
	}
	defer func() { <-c.gate }()
	if c.lifetime.Err() != nil {
		return nil, sharedpg.ErrSessionClosed
	}
	if c.started {
		return nil, sharedpg.ErrSessionStarted
	}
	c.started = true
	defer func() {
		c.cancel()
		c.admitted.Store(false)
		c.unlocked.Store(false)
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if c.closeLocked(cleanup) != nil {
			err = errors.Join(err, errSharedAdmissionCleanup)
		}
	}()
	pending, err := readSharedPendingEnrollment(o.TrustPath, root, o.Binding)
	if err != nil {
		return nil, err
	}
	if master.LoginName() != pending.Certificate.Manifest.Context.LoginName || o.Settings.DeviceRole != "wh_"+pending.RoleTag+"_d_"+o.Binding.DeviceID.String() {
		return nil, sharedpg.ErrConfiguration
	}
	current := pending.ObservedTrust()
	if current.Revision < o.MinimumRevision {
		return nil, sharedpg.ErrTrustRollback
	}
	if err := validateSharedEnrollmentState(pending); err != nil {
		return nil, err
	}
	if err := loadSharedTLSCache(&o, current); err != nil {
		return nil, err
	}
	if o.Settings.TLSBundle != nil {
		next, e := pending.ObserveTLS(o.Binding, o.Settings.TLSBundle)
		if e != nil {
			return nil, e
		}
		if e := publishSharedTLSCache(o.TrustPath, o.Settings.TLSBundle, nil, func() error { return persistSharedEnrollmentObservation(o, root, &pending, next) }); e != nil {
			return nil, e
		}
		current = pending.ObservedTrust()
	}
	prepared, err := current.PrepareTransport(o.Settings, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(prepared.Profile); err != nil {
		return nil, err
	}
	policy, err := current.Policy()
	if err != nil {
		return nil, err
	}
	var material []byte
	var preset vault.KDFPreset
	var ask bool
	err = master.Use(func(secret []byte, kdf vault.KDFPreset, usedASK bool) error {
		preset, ask = kdf, usedASK
		if preset != pending.KDF || ask != pending.ASKRequired {
			return sharedpg.ErrAccountRevision
		}
		if e := validateSharedAccountDerivation(policy, prepared.Profile, preset, ask); e != nil {
			return e
		}
		var e error
		material, e = vault.DeriveKey(secret, nil, vault.PurposeLogin)
		return e
	})
	defer vault.Wipe(material)
	if err != nil {
		return nil, err
	}
	login, err := sharedpg.EncodeLoginSecret(material)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(login)
	// Recovery uses one query connection, with no unused notification listener.
	if err := c.session.Open(ctx, prepared, login, sharedpg.ChangePolicy{TransactionPooler: true}); err != nil {
		return nil, err
	}
	admission, err := c.session.AuthenticateSession(ctx, o.Request, material)
	if err != nil {
		return nil, err
	}
	next, err := pending.ObserveProfile(o.Binding, admission, o.Request)
	if err != nil {
		return nil, err
	}
	if err := persistSharedEnrollmentObservation(o, root, &pending, next); err != nil {
		return nil, err
	}
	current = pending.ObservedTrust()
	updated, err := current.PrepareTransport(prepared, o.OSFloor, o.UserFloor, o.Request.API)
	if err != nil {
		return nil, err
	}
	if err := sharedAdmissionRuntimeProfile(updated.Profile); err != nil {
		return nil, err
	}
	policy, err = current.Policy()
	if err != nil {
		return nil, err
	}
	if err := validateSharedAccountDerivation(policy, updated.Profile, preset, ask); err != nil {
		return nil, err
	}
	if updated.TLSBundle != nil {
		bundle, e := verifiedSessionTLS(ctx, c.session, current)
		if e != nil {
			return nil, e
		}
		next, e := pending.ObserveTLS(o.Binding, bundle)
		if e != nil {
			return nil, e
		}
		if e := publishSharedTLSCache(o.TrustPath, bundle, nil, func() error { return persistSharedEnrollmentObservation(o, root, &pending, next) }); e != nil {
			return nil, e
		}
		if pending.ObservedTrust().TLSSequence != current.TLSSequence {
			return nil, errSharedTLSChanged
		}
	}
	state, err := c.session.AccountKeyState(ctx)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	next, err = pending.ObserveAccount(o.Binding, *state, pending.ObservedTrust().WrappingRevision)
	if err != nil {
		return nil, err
	}
	if err := persistSharedEnrollmentObservation(o, root, &pending, next); err != nil {
		return nil, err
	}
	if err := validateSharedEnrollmentState(pending); err != nil {
		return nil, err
	}
	account, err := c.session.AccountEnrollmentMaterial(ctx)
	if err != nil {
		return nil, err
	}
	if account == nil || account.State == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	next, err = pending.ObserveAccount(o.Binding, *account.State, pending.ObservedTrust().WrappingRevision)
	if err != nil {
		return nil, err
	}
	if err := persistSharedEnrollmentObservation(o, root, &pending, next); err != nil {
		return nil, err
	}
	if err := validateSharedEnrollmentState(pending); err != nil {
		return nil, err
	}
	confirm, err := c.verifyEnrollment(ctx, c.session, o.Binding, pending, master, account)
	if err != nil {
		return nil, err
	}
	if confirm == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	confirmed, err := confirm(ctx)
	if err != nil {
		return nil, err
	}
	if confirmed == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	target, err := confirmed.ConfirmedActivation(o.Binding, pending)
	if err != nil {
		return nil, err
	}
	result = &sharedEnrollmentRecoveryResult{Confirmed: true, TrustRevision: target.Revision}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if c.lifetime.Err() != nil {
		return result, sharedpg.ErrSessionClosed
	}
	return result, promoteSharedEnrollment(o.TrustPath, root, o.Binding, pending, confirmed)
}

func persistSharedEnrollmentObservation(o sharedAdmissionOptions, root []byte, pending *sharedpg.PendingEnrollment, next sharedpg.PendingEnrollment) error {
	// The recoverable selection is the independent floor if the ordinary intent
	// is lost. Publish it first; never recreate an intent from an older snapshot.
	if err := mirrorSharedJoinObservation(o, root, *pending, next); err != nil {
		return err
	}
	err := writeSharedPendingObservation(o.TrustPath, root, o.Binding, *pending, next)
	if errors.Is(err, errSharedTrustCommitUncertain) {
		err = writeSharedPendingObservation(o.TrustPath, root, o.Binding, *pending, next)
	}
	if err == nil {
		*pending = next
	}
	return err
}

func validateSharedEnrollmentState(p sharedpg.PendingEnrollment) error {
	current := p.ObservedTrust()
	if current.Account == nil || !current.Account.Active {
		return vault.ErrPolicy
	}
	if p.Trust.Account == nil || current.Account.Encryption != p.Trust.Account.Encryption || current.Account.Signing != p.Trust.Account.Signing || current.WrappingRevision != 1 {
		return sharedpg.ErrAccountRevision
	}
	return nil
}
