package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Unlocked is native status only, not tree/grant authorization or renderer access.
func (c *sharedAdmissionController) Unlocked() bool { return c.Admitted() && c.unlocked.Load() }

// Unlock borrows the account master derived by the native password/ASK flow.
// Preset and askUsed describe that derivation, never renderer-supplied assertions.
// Once a new unlock attempt begins, failure retires this owner; retry through a
// fresh admission. Invalid arguments and repeated calls do not alter an owner.
func (c *sharedAdmissionController) Unlock(ctx context.Context, master []byte, preset vault.KDFPreset, askUsed bool) (err error) {
	if ctx == nil || len(master) != 32 {
		return sharedpg.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.lifetime, cancel)
	defer stop()
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if !c.Admitted() || c.root == nil {
		return sharedpg.ErrSessionClosed
	}
	if c.unlocked.Load() {
		return sharedpg.ErrSessionStarted
	}
	defer func() {
		if err != nil {
			c.cancel()
			c.admitted.Store(false)
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if c.closeLocked(cleanup) != nil {
				err = errSharedAdmissionCleanup
			}
		}
	}()
	_, keys, trust, err := c.verifiedAccountMaterial(ctx, master, preset, askUsed)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	if err = ctx.Err(); err != nil {
		return err
	}
	if c.tlsManaged && c.runtimeTLS == sharedpg.TLSVerified {
		if session, ok := c.session.(interface {
			EnsureAccountRecovery(context.Context, sharedpg.TrustState, *vault.UserKeys) (bool, error)
		}); ok {
			// Invalid custody material or write contention affects escrow only.
			// Account revocation and transport failures still retire the owner.
			if _, custodyErr := session.EnsureAccountRecovery(ctx, trust, keys); custodyErr != nil &&
				!errors.Is(custodyErr, sharedpg.ErrChangeInProgress) && !errors.Is(custodyErr, sharedpg.ErrAccountRecovery) {
				return custodyErr
			}
		}
	}
	c.privateKeys, err = securemem.New(64, false)
	if err != nil {
		return err
	}
	err = c.privateKeys.With(func(value []byte) error {
		copy(value[:32], keys.EncryptionPrivate)
		copy(value[32:], keys.SigningSeed)
		return nil
	})
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !c.Admitted() {
		return sharedpg.ErrSessionClosed
	}
	if !c.privateKeys.Locked() {
		c.memoryLockWarning.Store(true)
	}
	c.runtimeKDF, c.runtimeASK = preset, askUsed
	c.unlocked.Store(true)
	return nil
}

// Caller holds the operation gate and owns the returned temporary keys. Both
// unlock and password change revalidate current signed account material.
func (c *sharedAdmissionController) verifiedAccountMaterial(ctx context.Context, master []byte, preset vault.KDFPreset, askUsed bool) (account *sharedpg.UnverifiedAccountKeys, keys *vault.UserKeys, trust sharedpg.TrustState, err error) {
	material, err := vault.DeriveKey(master, nil, vault.PurposeLogin)
	if err != nil {
		return nil, nil, trust, err
	}
	commitment := sha256.Sum256(material)
	vault.Wipe(material)
	if subtle.ConstantTimeCompare(commitment[:], c.loginCommitment[:]) != 1 {
		return nil, nil, trust, vault.ErrAuthentication
	}
	var current sharedpg.TrustState
	err = c.root.With(func(root []byte) error {
		var e error
		current, e = readSharedTrustFile(c.trustPath, root, c.trustBinding, c.trustRevision)
		return e
	})
	if err != nil {
		return nil, nil, trust, err
	}
	if current.Revision != c.trustRevision {
		return nil, nil, trust, errSharedTrustConflict
	}
	if c.tlsManaged {
		if err := c.refreshTLSLocked(ctx, sharedAdmissionOptions{TrustPath: c.trustPath, Binding: c.trustBinding}, current); err != nil {
			return nil, nil, trust, err
		}
	}
	policy, err := current.Policy()
	if err != nil {
		return nil, nil, trust, err
	}
	if err := validateSharedAccountDerivation(policy, c.runtimeProfile, preset, askUsed); err != nil {
		return nil, nil, trust, err
	}
	state, err := c.session.AccountKeyState(ctx)
	if err != nil {
		return nil, nil, trust, err
	}
	if state == nil {
		return nil, nil, trust, sharedpg.ErrAdmissionResponse
	}
	floor := current.WrappingRevision
	if floor == 0 {
		floor = 1
	} // schema's universal lower bound, not an unverified server revision
	current, err = c.persistAccountState(current, *state, floor)
	if err != nil {
		return nil, nil, trust, err
	}
	if !state.Active {
		return nil, nil, trust, vault.ErrPolicy
	}
	account, err = readSharedAccountMaterial(ctx, c.session, current)
	if err != nil {
		return nil, nil, trust, err
	}
	if account == nil || account.State == nil {
		return nil, nil, trust, sharedpg.ErrAdmissionResponse
	}
	current, err = c.persistAccountState(current, *account.State, current.WrappingRevision)
	if err != nil {
		return nil, nil, trust, err
	}
	if !account.State.Active {
		return nil, nil, trust, vault.ErrPolicy
	}
	if account.KDF != preset || account.ASKRequired != askUsed {
		return nil, nil, trust, vault.ErrPolicy
	}
	var next sharedpg.TrustState
	keys, next, err = openSharedAccountKeys(master, account, current, current.WrappingRevision)
	defer func(owned *vault.UserKeys) {
		if err != nil && owned != nil {
			owned.Wipe()
		}
	}(keys)
	if next.Revision != 0 {
		persisted, persistErr := c.persistAccountTrust(current, next)
		if err == nil {
			err = persistErr
			current = persisted
		} else if persistErr != nil {
			err = errors.Join(err, persistErr)
		}
	}
	if err != nil {
		return nil, nil, trust, err
	}
	return account, keys, current, nil
}

func validateSharedAccountDerivation(policy vault.Policy, profile vault.Profile, preset vault.KDFPreset, askUsed bool) error {
	actual, err := vault.Parameters(preset)
	if err != nil {
		return err
	}
	derivationPolicy := policy
	derivationPolicy.Profile = profile
	derivationPolicy.KDF = preset
	derivationPolicy.ASKRequired = askUsed
	if err := derivationPolicy.Validate(); err != nil {
		return err
	}
	minimum, err := vault.Parameters(policy.KDF)
	if err != nil {
		return err
	}
	if actual.MemoryKiB < minimum.MemoryKiB || actual.Iterations < minimum.Iterations || (policy.ASKRequired && !askUsed) {
		return vault.ErrPolicy
	}
	return nil
}

func (c *sharedAdmissionController) persistAccountState(current sharedpg.TrustState, state vault.UserKeyState, wrapping uint64) (sharedpg.TrustState, error) {
	next, err := current.AdvanceAccount(state, wrapping)
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	return c.persistAccountTrust(current, next)
}

func (c *sharedAdmissionController) persistAccountTrust(current, next sharedpg.TrustState) (sharedpg.TrustState, error) {
	err := c.root.With(func(root []byte) error {
		var e error
		if next.Revision == current.Revision {
			e = confirmSharedTrustFile(c.trustPath, root, c.trustBinding, next)
		} else {
			e = writeSharedTrustFile(c.trustPath, root, c.trustBinding, next, current.Revision)
		}
		if errors.Is(e, errSharedTrustCommitUncertain) {
			e = confirmSharedTrustFile(c.trustPath, root, c.trustBinding, next)
		}
		return e
	})
	if err != nil {
		return sharedpg.TrustState{}, err
	}
	c.trustRevision = next.Revision
	if queued := len(next.SuspensionRotations) != 0; !c.rotationPending.Swap(queued) && queued {
		c.wakeSuspensionRotation()
	}
	return next, nil
}
