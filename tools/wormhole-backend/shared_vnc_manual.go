package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Planning authenticates current Use and endpoint metadata without fetching or
// decrypting saved ciphertext while the protected password prompt is open.
func (c *sharedAdmissionController) PlanVNCConnection(ctx context.Context, q localvault.TunnelPlanRequest) (vault.BundleBinding, error) {
	if ctx == nil || q.Validate() != nil {
		return vault.BundleBinding{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return vault.BundleBinding{}, vault.ErrPolicy
	}
	current, err := c.PlanConnection(ctx, uuid.MustParse(q.NodeID))
	if err != nil {
		return vault.BundleBinding{}, err
	}
	return sharedVNCBinding(c.trustBinding.WorkspaceID, current.Plan, q)
}

// SealManualVNCConnection reauthorizes and audits against the current graph,
// commits its trust observations, then seals the opaque password envelope. The
// account private key and saved values are never borrowed by this operation.
func (c *sharedAdmissionController) SealManualVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, expected vault.BundleBinding, inner vault.SealedBundle, source string) (localvault.VNCConnectionBundle, error) {
	return c.sealManualVNCConnection(ctx, q, expected, nil, "", "", inner, source)
}

func (c *sharedAdmissionController) SealRoutedManualVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint, fileID string, inner vault.SealedBundle, source string) (localvault.VNCConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return localvault.VNCConnectionBundle{}, vault.ErrFormat
	}
	return c.sealManualVNCConnection(ctx, q, route.BundleBinding, &route, endpoint, fileID, inner, source)
}

func (c *sharedAdmissionController) sealManualVNCConnection(ctx context.Context, q localvault.TunnelBundleRequest, expected vault.BundleBinding, route *vault.TunnelBundleBinding, endpoint, fileID string, inner vault.SealedBundle, source string) (localvault.VNCConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return localvault.VNCConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.VNCConnectionBundle{}, vault.ErrPolicy
	}
	raw, err := vault.EncodeVNCManualAuthorization(inner)
	if err != nil {
		return localvault.VNCConnectionBundle{}, err
	}
	defer vault.Wipe(raw)
	var binding vault.BundleBinding
	var result localvault.VNCConnectionBundle
	err = c.withConnectionRelease(ctx, uuid.MustParse(q.NodeID), source, "vnc", func(p resolver.Plan) error {
		var err error
		binding, err = sharedVNCRouteBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		if err != nil {
			return err
		}
		if binding != expected {
			return vault.ErrPolicy
		}
		return nil
	}, func(ctx context.Context, _ sharedpg.TrustState, v *sharedpg.VerifiedCredentialRelease) error {
		if err := c.checkConnectionRoute(fileID, q.Plan(), route, endpoint)(v); err != nil {
			return err
		}
		var sealed vault.SealedBundle
		var err error
		if route == nil {
			sealed, err = vault.SealBundle(q.PublicKey, binding, raw)
		} else {
			sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
		}
		if err != nil {
			return err
		}
		result = localvault.VNCConnectionBundle{Binding: binding, Bundle: sealed}
		return ctx.Err()
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.VNCConnectionBundle{}, err
	}
	return result, nil
}
