package localvault

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Planning reads authenticated public metadata without borrowing saved secrets.
func (o *Owner) PlanRDPConnection(ctx context.Context, q TunnelPlanRequest) (vault.BundleBinding, error) {
	if ctx == nil || q.Validate() != nil {
		return vault.BundleBinding{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, binding, _, err := o.planRDPBundle(ctx, q, nil, true)
	return binding, err
}

// The primary account remains an opaque document envelope. Only an independent
// selected gateway account may be borrowed, while this owner lock is held.
func (o *Owner) SealManualRDPConnection(ctx context.Context, q TunnelBundleRequest, expected vault.BundleBinding, route *vault.TunnelBundleBinding, endpoint string, inner vault.SealedBundle) (RDPConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return RDPConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return RDPConnectionBundle{}, vault.ErrPolicy
	}
	if route == nil && endpoint != "" || route != nil && !vault.ValidRouteEndpoint(endpoint) {
		return RDPConnectionBundle{}, vault.ErrPolicy
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, binding, settings, err := o.planRDPBundle(ctx, q.Plan(), route, true)
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	if binding != expected {
		return RDPConnectionBundle{}, vault.ErrPolicy
	}
	base, err := o.manualRDPBundlePayload(ctx, q.NodeID, r, settings, 0)
	defer func() { vault.Wipe(base.GatewayPassword) }()
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	raw, err := vault.EncodeRDPManualAuthorization(base, inner)
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	if err = ctx.Err(); err != nil {
		return RDPConnectionBundle{}, err
	}
	var sealed vault.SealedBundle
	if route == nil {
		sealed, err = vault.SealBundle(q.PublicKey, binding, raw)
	} else {
		sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
	}
	if err != nil {
		return RDPConnectionBundle{}, err
	}
	if err = ctx.Err(); err != nil {
		vault.Wipe(sealed.Enc)
		vault.Wipe(sealed.Ciphertext)
		return RDPConnectionBundle{}, err
	}
	return RDPConnectionBundle{Binding: binding, Bundle: sealed}, nil
}

func (o *Owner) manualRDPBundlePayload(ctx context.Context, nodeID string, r Resolution, settings vault.RDPSettings, skip vault.RDPBitwardenSlots) (vault.RDPBundlePayload, error) {
	settings.Domain = "" // The isolated primary account supplies its domain.
	base, err := o.rdpBundlePayload(ctx, nodeID, r, settings, skip|vault.RDPBitwardenPrimary)
	base.Username = ""
	return base, err
}
