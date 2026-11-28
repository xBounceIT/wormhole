package localvault

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// The owning native provider adapter validates the borrowed IPsec settings and
// extracts their configured fallback. It must not retain settings or reenter
// Owner. Neither a renderer ID nor an unverified public projection is a selector.
type TunnelFallbackSelector func(configuration []byte) (string, error)

type TunnelFallbackBundle struct {
	Binding vault.TunnelFallbackBinding `json:"binding"`
	Bundle  vault.SealedBundle          `json:"bundle"`
}

// PlanConnectionFallback authenticates both sources under one owner lock. It
// opens only the primary settings to resolve their reference; the SSL settings
// remain closed. This is not a release/exit receipt. The native caller must
// persist authenticated observations even on denial and verify original process
// retirement before requesting the separately purpose-bound secondary bundle.
func (o *Owner) PlanConnectionFallback(ctx context.Context, q TunnelPlanRequest, primary vault.TunnelBundleBinding, attempt string, selectFallback TunnelFallbackSelector) (vault.TunnelFallbackBinding, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	binding, _, err := o.planConnectionFallback(ctx, q, primary, attempt, selectFallback)
	return binding, err
}

func (o *Owner) planConnectionFallback(ctx context.Context, q TunnelPlanRequest, primary vault.TunnelBundleBinding, attempt string, selectFallback TunnelFallbackSelector) (vault.TunnelFallbackBinding, vaultstore.Tunnel, error) {
	secondary := q
	secondary.RequestID = attempt
	if ctx == nil || selectFallback == nil || q.Validate() != nil || secondary.Validate() != nil || attempt == q.RequestID {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, vault.ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	observing := o.vpnSSOObservingNodes
	o.vpnSSOObservingNodes = true
	defer func() { o.vpnSSOObservingNodes = observing }()
	r, err := o.resolveConnectionRequest(ctx, q, false)
	if err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	actual, err := connectionTunnelBinding(r, q)
	if err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	if actual != primary || actual.Kind != 9 {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, vault.ErrAuthentication
	}
	var id string
	err = o.withResolvedConnectionTunnel(ctx, r, func(_ Resolution, configuration []byte) error {
		var err error
		id, err = selectFallback(configuration)
		return err
	})
	if err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	if id == "" {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, vaultstore.ErrMissing
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id || id == actual.TunnelConfigID {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, vault.ErrPolicy
	}
	// The primary borrow has ended: verifying the target also borrows the root
	// buffer and cannot reenter it from inside the primary secret callback.
	target, err := o.readTunnel(ctx, id, 0)
	if err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	if target.Kind != 2 {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, vault.ErrPolicy
	}
	fallback := actual
	fallback.RequestID, fallback.TunnelConfigID, fallback.Kind = attempt, target.ID, 2
	fallback.RowVersion, fallback.ConfigurationVersion = target.RowVersion, target.ConfigurationVersion
	if err := ctx.Err(); err != nil {
		return vault.TunnelFallbackBinding{}, vaultstore.Tunnel{}, err
	}
	return vault.TunnelFallbackBinding{Primary: actual, Fallback: fallback}, target, nil
}

// SealConnectionFallback re-resolves the encrypted reference and both current
// manifests before opening the target. expected is only a native snapshot, not
// authority. No primary credentials or settings are returned to the caller.
func (o *Owner) SealConnectionFallback(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelFallbackBinding, public []byte, selectFallback TunnelFallbackSelector) (TunnelFallbackBundle, error) {
	if len(public) != 32 {
		return TunnelFallbackBundle{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	actual, target, err := o.planConnectionFallback(ctx, q, expected.Primary, expected.Fallback.RequestID, selectFallback)
	if err != nil {
		return TunnelFallbackBundle{}, err
	}
	if actual != expected {
		return TunnelFallbackBundle{}, vault.ErrAuthentication
	}
	var result TunnelFallbackBundle
	err = o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: target.ID, Field: "settings"}, target.ConfigurationVersion, true, func(configuration []byte) error {
		sealed, err := vault.SealTunnelFallback(public, actual, configuration)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			vault.Wipe(sealed.Enc)
			vault.Wipe(sealed.Ciphertext)
			return err
		}
		result = TunnelFallbackBundle{Binding: actual, Bundle: sealed}
		return nil
	})
	if err != nil {
		return TunnelFallbackBundle{}, err
	}
	return result, nil
}
