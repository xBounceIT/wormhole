package localvault

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// FallbackVPNSSOBinding describes an already authenticated source pair. The
// caller must reauthorize both sources before every use of the personal archive.
// Attempts/destination sessions do not identify persistent provider storage;
// both source identities and configuration versions do.
func FallbackVPNSSOBinding(pair vault.TunnelFallbackBinding, accountID string, provider VPNSSOProvider) (VPNSSOBinding, error) {
	if err := pair.Validate(); err != nil {
		return VPNSSOBinding{}, err
	}
	p, f := pair.Primary, pair.Fallback
	public, _ := json.Marshal(struct {
		Purpose, WorkspaceID, FileID, PrimaryID, FallbackID string
		PrimaryConfiguration, FallbackConfiguration         uint64
	}{"wormhole/v1/vpn-sso-fallback-route", p.WorkspaceID, p.FileID, p.TunnelConfigID, f.TunnelConfigID, p.ConfigurationVersion, f.ConfigurationVersion})
	b := VPNSSOBinding{WorkspaceID: f.WorkspaceID, FileID: f.FileID, TunnelID: f.TunnelConfigID, AccountID: accountID, Kind: f.Kind, ConfigurationVersion: f.ConfigurationVersion, GatewayOrigin: provider.GatewayOrigin, Realm: provider.Realm, TrustDigest: provider.TrustDigest, RouteDigest: sha256.Sum256(public)}
	if _, err := b.digest(); err != nil {
		return VPNSSOBinding{}, err
	}
	return b, nil
}

func (o *Owner) PlanConnectionFallbackVPNSSO(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelFallbackBinding, selectFallback TunnelFallbackSelector, describe VPNSSODescribeProvider) (VPNSSOBinding, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.planConnectionFallbackVPNSSO(ctx, q, expected, selectFallback, describe)
}

func (o *Owner) planConnectionFallbackVPNSSO(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelFallbackBinding, selectFallback TunnelFallbackSelector, describe VPNSSODescribeProvider) (VPNSSOBinding, error) {
	if describe == nil || expected.Validate() != nil {
		return VPNSSOBinding{}, vault.ErrFormat
	}
	actual, target, err := o.planConnectionFallback(ctx, q, expected.Primary, expected.Fallback.RequestID, selectFallback)
	if err != nil {
		return VPNSSOBinding{}, err
	}
	if actual != expected {
		return VPNSSOBinding{}, vault.ErrAuthentication
	}
	var provider VPNSSOProvider
	err = o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: target.ID, Field: "settings"}, target.ConfigurationVersion, true, func(raw []byte) error {
		var err error
		provider, err = describe(actual.Fallback.Kind, raw)
		return err
	})
	if err != nil {
		return VPNSSOBinding{}, err
	}
	if err := ctx.Err(); err != nil {
		return VPNSSOBinding{}, err
	}
	return FallbackVPNSSOBinding(actual, o.store.Identity().WorkspaceID, provider)
}

// Admission and every staged source check run under the owner lock. The native
// selector reopens the primary reference, then ends that loan before SSL opens.
func (o *Owner) BeginConnectionFallbackVPNSSOTransfer(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelFallbackBinding, planned VPNSSOBinding, request VPNSSOTransferRequest, selectFallback TunnelFallbackSelector, describe VPNSSODescribeProvider) (VPNSSOTransferOffer, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	current, err := o.planConnectionFallbackVPNSSO(ctx, q, expected, selectFallback, describe)
	if err != nil {
		return VPNSSOTransferOffer{}, err
	}
	if current != planned || request.SessionID != q.SessionID || request.RequestID != q.RequestID || request.Epoch != q.Epoch {
		return VPNSSOTransferOffer{}, vault.ErrAuthentication
	}
	offer, err := o.beginVPNSSOTransfer(ctx, current, request, vpnSSOTransferLifetime)
	if err != nil {
		return VPNSSOTransferOffer{}, err
	}
	o.vpnSSOTransfers[offer.Context.TransferID].sourceCheck = func(ctx context.Context) error {
		fresh, err := o.planConnectionFallbackVPNSSO(ctx, q, expected, selectFallback, describe)
		if err != nil {
			return err
		}
		if fresh != planned {
			return vault.ErrAuthentication
		}
		return nil
	}
	return offer, nil
}
