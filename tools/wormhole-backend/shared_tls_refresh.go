package main

import (
	"context"
	"errors"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

var errSharedTLSChanged = errors.New("shared_workspace_tls_reconnect_required")

// RefreshTLS checks authenticated server metadata against durable local trust.
// A changed bundle is committed before this owner is retired. Reconnect through
// a fresh controller, which loads the updated cache; never retry on this owner.
// Failure also retires the owner. Unmanaged legacy transports are not upgraded
// implicitly: their initial signed TLS pin must come from enrollment.
func (c *sharedAdmissionController) RefreshTLS(ctx context.Context) (err error) {
	if ctx == nil {
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
	if !c.tlsManaged {
		return sharedpg.ErrConfiguration
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
	var current sharedpg.TrustState
	err = c.root.With(func(root []byte) error {
		var e error
		current, e = readSharedTrustFile(c.trustPath, root, c.trustBinding, c.trustRevision)
		return e
	})
	if err != nil {
		return err
	}
	if current.Revision != c.trustRevision {
		return errSharedTrustConflict
	}
	return c.refreshTLSLocked(ctx, sharedAdmissionOptions{TrustPath: c.trustPath, Binding: c.trustBinding}, current)
}

// Caller holds the controller gate and an owned trust root. Used both before
// admission becomes visible and for later refreshes. No server-provided key is
// used as a trust anchor.
func (c *sharedAdmissionController) refreshTLSLocked(ctx context.Context, o sharedAdmissionOptions, current sharedpg.TrustState) error {
	verified, err := verifiedSessionTLS(ctx, c.session, current)
	if err != nil {
		return err
	}
	o.Settings.TLSBundle = verified
	var next sharedpg.TrustState
	err = c.root.With(func(root []byte) error {
		var e error
		next, e = acceptSharedTLSBundle(o, root, current)
		return e
	})
	if err != nil {
		return err
	}
	if next.TLSSequence != current.TLSSequence {
		// An active device must remember the new floor across its forced
		// reconnect, including updates initiated by a different administrator.
		if c.Unlocked() {
			if err := c.checkpointCatalogTrust(next); err != nil {
				return err
			}
		}
		return errSharedTLSChanged
	}
	return ctx.Err()
}

func verifiedSessionTLS(ctx context.Context, session sharedAdmissionSession, current sharedpg.TrustState) (*sharedpg.VerifiedTLSBundle, error) {
	bundle, err := session.TLSTrustBundle(ctx)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, sharedpg.ErrAdmissionResponse
	}
	raw, err := sharedpg.EncodeTLSTrustBundle(*bundle)
	if err != nil {
		return nil, err
	}
	verified, err := current.VerifyTLS(raw)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return verified, nil
}
