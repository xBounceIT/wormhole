package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type sharedPasswordRecoveryCredential uint8

const (
	sharedRecoveryNewPassword sharedPasswordRecoveryCredential = iota + 1
	sharedRecoveryOldPassword
)

// This proves the observed remote outcome, not local durability if accompanied
// by an error. Recovery never publishes admitted/unlocked status on this owner.
type sharedPasswordRecoveryResult struct {
	Changed       bool
	TrustRevision uint64
}

// The new root opens the journal's authenticated target configuration even when
// the on-disk sidecar still uses the old root. Caller settings never redirect a
// protected recovery. Ordinary device unlock still requires separate key slots.
func (c *sharedAdmissionController) RecoverPasswordChangeFromSetup(ctx context.Context, o sharedAdmissionOptions, master, newRoot, oldRoot []byte, preset vault.KDFPreset, askUsed bool, credential sharedPasswordRecoveryCredential) (*sharedPasswordRecoveryResult, error) {
	if ctx == nil || !filepath.IsAbs(o.TrustPath) {
		return nil, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
	if err != nil {
		return nil, err
	}
	current := pending.ObservedTrust()
	if current.Account == nil || !current.Account.Active {
		return nil, vault.ErrPolicy
	}
	raw, err := pending.TransportCiphertext(newRoot, o.Binding)
	if err != nil || len(raw) == 0 {
		return nil, sharedpg.ErrTrustState
	}
	o.Settings, err = openSharedTransportSetup(o, newRoot, current, raw)
	if err != nil {
		return nil, err
	}
	return c.RecoverPasswordChange(ctx, o, master, newRoot, oldRoot, preset, askUsed, credential)
}

// RecoverPasswordChange uses a fresh audited proof on the enrolled SAME device
// before interpreting current account material. SCRAM success alone is not an
// ordering barrier against a delayed request carrying the superseded capability.
// Native derivation supplies borrowed inputs; oldRoot is required for old-password
// recovery, newRoot always authenticates the pending journal. There is no automatic
// fallback between credentials and no password mutation is submitted here.
func (c *sharedAdmissionController) RecoverPasswordChange(ctx context.Context, o sharedAdmissionOptions, master, newRoot, oldRoot []byte, preset vault.KDFPreset, askUsed bool, credential sharedPasswordRecoveryCredential) (result *sharedPasswordRecoveryResult, err error) {
	if ctx == nil || len(master) != 32 || len(newRoot) != 32 || !filepath.IsAbs(o.TrustPath) || o.MinimumRevision == 0 || o.Request.Validate() != nil || o.Binding.WorkspaceID != o.Request.WorkspaceID || o.Binding.UserID != o.Request.UserID || o.Binding.DeviceID != o.Request.DeviceID ||
		(credential != sharedRecoveryNewPassword && credential != sharedRecoveryOldPassword) || (credential == sharedRecoveryOldPassword && len(oldRoot) != 32) {
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
	pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
	if err != nil {
		return nil, err
	}
	current := pending.ObservedTrust()
	if current.Revision < o.MinimumRevision {
		return nil, sharedpg.ErrTrustRollback
	}
	if err := loadSharedTLSCache(&o, current); err != nil {
		return nil, err
	}
	if o.Settings.TLSBundle != nil {
		next, e := pending.ObserveTLS(o.Binding, o.Settings.TLSBundle)
		if e != nil {
			return nil, e
		}
		if e := publishSharedTLSCache(o.TrustPath, o.Settings.TLSBundle, nil, func() error {
			return persistSharedRecoveryObservation(o, newRoot, &pending, next)
		}); e != nil {
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
	cachedPolicy, err := current.Policy()
	if err != nil {
		return nil, err
	}
	if err := validateSharedAccountDerivation(cachedPolicy, prepared.Profile, preset, askUsed); err != nil {
		return nil, err
	}
	material, err := vault.DeriveKey(master, nil, vault.PurposeLogin)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(material)
	login, err := sharedpg.EncodeLoginSecret(material)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(login)
	if err := c.session.Open(ctx, prepared, login, o.Settings.Changes); err != nil {
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
	if err := persistSharedRecoveryObservation(o, newRoot, &pending, next); err != nil {
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
	policy, err := current.Policy()
	if err != nil {
		return nil, err
	}
	if err := validateSharedAccountDerivation(policy, updated.Profile, preset, askUsed); err != nil {
		return nil, err
	}
	if updated.TLSBundle != nil {
		verified, e := verifiedSessionTLS(ctx, c.session, current)
		if e != nil {
			return nil, e
		}
		observed, e := pending.ObserveTLS(o.Binding, verified)
		if e != nil {
			return nil, e
		}
		if e := publishSharedTLSCache(o.TrustPath, verified, nil, func() error {
			return persistSharedRecoveryObservation(o, newRoot, &pending, observed)
		}); e != nil {
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
	if err := observeSharedRecoveryAccount(o, newRoot, &pending, *state, pending.ObservedTrust().WrappingRevision); err != nil {
		return nil, err
	}
	if !state.Active {
		return nil, vault.ErrPolicy
	}
	account, err := readSharedAccountMaterial(ctx, c.session, pending.ObservedTrust())
	if err != nil {
		return nil, err
	}
	if account == nil || account.State == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	if err := observeSharedRecoveryAccount(o, newRoot, &pending, *account.State, pending.ObservedTrust().WrappingRevision); err != nil {
		return nil, err
	}
	if !account.State.Active || account.KDF != preset || account.ASKRequired != askUsed {
		return nil, vault.ErrPolicy
	}
	minimumWrapping := pending.ObservedTrust().WrappingRevision
	committed := credential == sharedRecoveryNewPassword
	if committed {
		minimumWrapping = max(minimumWrapping, pending.Next.WrappingRevision)
	} else if account.Binding.Revision != pending.Previous.WrappingRevision {
		return nil, sharedpg.ErrAccountRevision
	}
	// Keep independent public certificate observations even if the account
	// capsule or delegation later fails. Its claimed wrap is still untrusted.
	if account.EnrollmentCertificate != nil {
		next, observeErr := pending.ObserveEnrollment(o.Binding, *account.EnrollmentCertificate, pending.ObservedTrust().WrappingRevision)
		if next.ID != uuid.Nil {
			if err := persistSharedRecoveryObservation(o, newRoot, &pending, next); err != nil {
				return nil, err
			}
		}
		if observeErr != nil {
			return nil, observeErr
		}
	}
	keys, _, err := openSharedAccountKeys(master, account, pending.ObservedTrust(), minimumWrapping)
	if err != nil {
		return nil, err
	}
	keys.Wipe()
	if account.EnrollmentCertificate != nil {
		next, err := pending.ObserveEnrollment(o.Binding, *account.EnrollmentCertificate, account.Binding.Revision)
		if err != nil {
			return nil, err
		}
		if err := persistSharedRecoveryObservation(o, newRoot, &pending, next); err != nil {
			return nil, err
		}
	}
	if err := observeSharedRecoveryAccount(o, newRoot, &pending, *account.State, account.Binding.Revision); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var target sharedpg.TrustState
	if committed {
		target, err = pending.PromotionState(o.Binding)
	} else {
		target, err = pending.AbortState(o.Binding)
	}
	if err != nil {
		return nil, err
	}
	result = &sharedPasswordRecoveryResult{Changed: committed, TrustRevision: target.Revision}
	if committed {
		err = promoteSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, pending)
	} else {
		err = rollbackSharedTrustRootTransition(o.TrustPath, newRoot, oldRoot, o.Binding, pending)
	}
	return result, err
}

func persistSharedRecoveryObservation(o sharedAdmissionOptions, root []byte, pending *sharedpg.TrustRootTransition, next sharedpg.TrustRootTransition) error {
	err := writeSharedTrustObservation(o.TrustPath, root, o.Binding, *pending, next)
	if errors.Is(err, errSharedTrustCommitUncertain) {
		err = writeSharedTrustObservation(o.TrustPath, root, o.Binding, *pending, next)
	}
	if err == nil {
		*pending = next
	}
	return err
}

func observeSharedRecoveryAccount(o sharedAdmissionOptions, root []byte, pending *sharedpg.TrustRootTransition, state vault.UserKeyState, wrapping uint64) error {
	next, err := pending.ObserveAccount(o.Binding, state, wrapping)
	if err != nil {
		return err
	}
	return persistSharedRecoveryObservation(o, root, pending, next)
}
