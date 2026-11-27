package localvault

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// PlanVNCConnection reveals public metadata only. No saved secret is borrowed
// while the isolated manual-password document waits for the user's input.
func (o *Owner) PlanVNCConnection(ctx context.Context, q TunnelPlanRequest) (vault.BundleBinding, error) {
	if err := q.Validate(); err != nil {
		return vault.BundleBinding{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q, false)
	if err != nil {
		return vault.BundleBinding{}, err
	}
	return vncConnectionBinding(r, q, false)
}

// Manual authorization wraps an opaque password envelope and never borrows a
// stored credential. Re-resolution and sealing hold the same owner lock.
func (o *Owner) SealManualVNCConnection(ctx context.Context, q TunnelBundleRequest, expected vault.BundleBinding, route *vault.TunnelBundleBinding, endpoint string, inner vault.SealedBundle) (VNCConnectionBundle, error) {
	if err := q.Validate(); err != nil {
		return VNCConnectionBundle{}, err
	}
	raw, err := vault.EncodeVNCManualAuthorization(inner)
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q.Plan(), false)
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	binding, err := vncConnectionBinding(r, q.Plan(), route != nil)
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	if binding != expected {
		return VNCConnectionBundle{}, vault.ErrPolicy
	}
	if route != nil {
		current, err := connectionTunnelBinding(r, q.Plan())
		if err != nil {
			return VNCConnectionBundle{}, err
		}
		if current != *route {
			return VNCConnectionBundle{}, vault.ErrPolicy
		}
	} else if endpoint != "" {
		return VNCConnectionBundle{}, vault.ErrPolicy
	}
	var bundle vault.SealedBundle
	if route == nil {
		bundle, err = vault.SealBundle(q.PublicKey, binding, raw)
	} else {
		bundle, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
	}
	if err != nil {
		return VNCConnectionBundle{}, err
	}
	if err = ctx.Err(); err != nil {
		vault.Wipe(bundle.Enc)
		vault.Wipe(bundle.Ciphertext)
		return VNCConnectionBundle{}, err
	}
	return VNCConnectionBundle{Binding: binding, Bundle: bundle}, nil
}
