package main

import (
	"context"
	"errors"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ChangePassword is native-only. Both masters were derived with the same preset
// and ASK; newRoot comes from the new protected enrollment derivation. Inputs are
// borrowed until return and must never be renderer-supplied derivation assertions.
// A receipt proves remote commit, even if local promotion/cleanup returns an
// error. Any uncertain remote outcome leaves the journal for reconciliation.
// Once an attempt starts this owner is retired; reconnect with the proven state.
func (c *sharedAdmissionController) ChangePassword(ctx context.Context, oldMaster, newMaster, newRoot []byte, preset vault.KDFPreset, askUsed bool, source string) (receipt *sharedpg.PasswordChangeReceipt, err error) {
	return c.changePassword(ctx, oldMaster, newMaster, newRoot, preset, askUsed, source, nil)
}

// ChangeDevicePassword requires a candidate created from the same borrowed new
// password/ASK as newMaster/newRoot. It journals the device before SQL and only
// publishes it after a receipt or independent recovery proves the remote change.
func (c *sharedAdmissionController) ChangeDevicePassword(ctx context.Context, oldMaster, newMaster, newRoot []byte, preset vault.KDFPreset, askUsed bool, source string, device sharedDevicePasswordCandidate) (*sharedpg.PasswordChangeReceipt, error) {
	return c.changePassword(ctx, oldMaster, newMaster, newRoot, preset, askUsed, source, &device)
}

func (c *sharedAdmissionController) changePassword(ctx context.Context, oldMaster, newMaster, newRoot []byte, preset vault.KDFPreset, askUsed bool, source string, device *sharedDevicePasswordCandidate) (receipt *sharedpg.PasswordChangeReceipt, err error) {
	if ctx == nil || len(oldMaster) != 32 || len(newMaster) != 32 || len(newRoot) != 32 || (source != "ui" && source != "mcp") {
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
	if !c.Unlocked() || c.root == nil {
		return nil, sharedpg.ErrSessionClosed
	}
	c.unlocked.Store(false)
	defer func() {
		c.cancel()
		c.admitted.Store(false)
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if c.closeLocked(cleanup) != nil {
			err = errors.Join(err, errSharedAdmissionCleanup)
		}
	}()
	account, keys, _, err := c.verifiedAccountMaterial(ctx, oldMaster, preset, askUsed)
	if err != nil {
		return nil, err
	}
	public, err := keys.Public()
	keys.Wipe()
	if err != nil {
		return nil, err
	}
	plan, err := sharedpg.PreparePasswordChange(oldMaster, newMaster, account.Binding, account.Envelope, public)
	if err != nil {
		return nil, err
	}
	defer plan.Wipe()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var pending sharedpg.TrustRootTransition
	err = c.root.With(func(oldRoot []byte) error {
		var e error
		pending, e = stageSharedTrustRootTransitionWithDevice(c.trustPath, oldRoot, newRoot, c.trustBinding, c.trustRevision, device)
		if errors.Is(e, errSharedTrustCommitUncertain) {
			e = confirmSharedTrustRootTransition(c.trustPath, newRoot, c.trustBinding, pending)
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, abortSharedTrustRootTransition(c.trustPath, newRoot, c.trustBinding, pending))
	}
	receipt, err = c.session.ChangePassword(ctx, plan, source)
	if receipt == nil {
		if err == nil {
			err = sharedpg.ErrPasswordChangeUncertain
		}
		if !errors.Is(err, sharedpg.ErrPasswordChangeUncertain) {
			// Session's contract distinguishes definite preflight/SQL rejections from
			// every unknown post-dispatch outcome, including interrupted cleanup.
			err = errors.Join(err, abortSharedTrustRootTransition(c.trustPath, newRoot, c.trustBinding, pending))
		}
		return nil, err
	}
	if receipt.WrappingRevision != pending.Next.WrappingRevision || receipt.AuthEpoch == 0 {
		return nil, sharedpg.ErrPasswordChangeUncertain
	}
	// A successful SQL response retires Session.Done and cancels our lifetime.
	// That cancellation must not suppress durable local completion after commit.
	err = errors.Join(err, promoteSharedTrustRootTransition(c.trustPath, newRoot, c.trustBinding, pending))
	return receipt, err
}
