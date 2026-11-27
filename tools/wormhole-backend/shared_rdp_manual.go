package main

import (
	"context"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"runtime"
)

func (c *sharedAdmissionController) PlanRDPConnection(ctx context.Context, q localvault.TunnelPlanRequest) (vault.BundleBinding, error) {
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
	current.Plan.ExternalRDPClient = current.ConfiguredExternalClient
	return sharedManualRDPBinding(c.trustBinding.WorkspaceID, current.Plan, q, false)
}
func (c *sharedAdmissionController) SealManualRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, expected vault.BundleBinding, inner vault.SealedBundle, source string) (localvault.RDPConnectionBundle, error) {
	return c.sealManualRDPConnection(ctx, q, expected, nil, "", "", inner, source)
}
func (c *sharedAdmissionController) SealRoutedManualRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, route vault.TunnelBundleBinding, endpoint, fileID string, inner vault.SealedBundle, source string) (localvault.RDPConnectionBundle, error) {
	if !vault.ValidRouteEndpoint(endpoint) {
		return localvault.RDPConnectionBundle{}, vault.ErrFormat
	}
	return c.sealManualRDPConnection(ctx, q, route.BundleBinding, &route, endpoint, fileID, inner, source)
}
func (c *sharedAdmissionController) sealManualRDPConnection(ctx context.Context, q localvault.TunnelBundleRequest, expected vault.BundleBinding, route *vault.TunnelBundleBinding, endpoint, fileID string, inner vault.SealedBundle, source string) (localvault.RDPConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return localvault.RDPConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.RDPConnectionBundle{}, vault.ErrPolicy
	}
	var binding vault.BundleBinding
	var result localvault.RDPConnectionBundle
	err := c.withConnectionRelease(ctx, uuid.MustParse(q.NodeID), source, "rdp", nil, func(ctx context.Context, committed sharedpg.TrustState, v *sharedpg.VerifiedCredentialRelease) error {
		p, err := v.RDPPlan(true)
		if err != nil {
			return err
		}
		binding, err = sharedManualRDPBinding(c.trustBinding.WorkspaceID, p, q.Plan(), route != nil)
		if err != nil {
			return err
		}
		if binding != expected {
			return vault.ErrPolicy
		}
		tunnel, err := v.Tunnel()
		if err != nil {
			return err
		}
		if err := sharedCurrentRoute(c.trustBinding.WorkspaceID, fileID, p, q.Plan(), tunnel, route, endpoint); err != nil {
			return err
		}
		settings, err := v.ManualRDPSettings()
		if err != nil {
			return err
		}
		settings = vault.RDPSettingsForPlatform(settings, runtime.GOOS)
		if err = vault.ValidateRDPRoute(settings, route != nil); err != nil {
			return err
		}
		settings.Domain = ""
		base := vault.RDPBundlePayload{Settings: settings}
		seal := func() error {
			raw, err := vault.EncodeRDPManualAuthorization(base, inner)
			if err != nil {
				return err
			}
			defer vault.Wipe(raw)
			var sealed vault.SealedBundle
			if route == nil {
				sealed, err = vault.SealBundle(q.PublicKey, binding, raw)
			} else {
				sealed, err = vault.SealRoutedBundle(q.PublicKey, *route, endpoint, raw)
			}
			if err != nil {
				return err
			}
			result = localvault.RDPConnectionBundle{Binding: binding, Bundle: sealed}
			return ctx.Err()
		}
		if settings.GatewayUsageMethod == 0 || settings.GatewayUseSameCreds ||
			(v.ProtocolPath() != "rdp" && settings.GatewayCredentialID == "") {
			return seal()
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return sharedpg.ErrTrustState
			}
			return v.WithGatewayValues(ctx, committed, keys[:32], func(_ resolver.Plan, values sharedpg.CredentialReleaseValues) error {
				g := values.Gateway
				if g == nil || values.Primary != nil || values.Inline != nil || values.Tunnel != nil || g.Metadata.ID != settings.GatewayCredentialID || g.Metadata.Provider != "local" || g.Metadata.Kind != "password" {
					return vault.ErrPolicy
				}
				base.GatewayUsername, base.GatewayDomain = g.Metadata.Username, g.Metadata.Domain
				base.GatewayPassword, base.GatewayPasswordProvided = g.Fields["password"]
				return seal()
			})
		})
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.RDPConnectionBundle{}, err
	}
	return result, nil
}

// The saved primary identity cannot force the manual account into an external
// client. Preserve explicit client policy; the recipient validates the actual
// decrypted manual identity before launching anything.
func sharedManualRDPBinding(workspace uuid.UUID, p resolver.Plan, q localvault.TunnelPlanRequest, routed bool) (vault.BundleBinding, error) {
	p.Username, p.Domain = "", ""
	return sharedRDPBinding(workspace, p, q, routed)
}
