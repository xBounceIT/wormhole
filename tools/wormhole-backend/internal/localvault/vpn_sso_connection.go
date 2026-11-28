package localvault

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// A native provider adapter derives these public facts from borrowed,
// authenticated configuration. It must not retain configuration or reenter Owner.
// It may validate a selected gateway against configured alternatives; it must
// never accept a caller-supplied origin/trust digest instead of checking settings.
type VPNSSOProvider struct {
	GatewayOrigin, Realm string
	TrustDigest          [32]byte
}
type VPNSSODescribeProvider func(kind uint16, configuration []byte) (VPNSSOProvider, error)

// PlanConnectionVPNSSO is native-only metadata for checkpoint selection. It
// neither reserves a transfer nor grants access. Begin independently re-resolves.
func (o *Owner) PlanConnectionVPNSSO(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelBundleBinding, describe VPNSSODescribeProvider) (VPNSSOBinding, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.planConnectionVPNSSO(ctx, q, expected, describe)
}

func (o *Owner) planConnectionVPNSSO(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelBundleBinding, describe VPNSSODescribeProvider) (VPNSSOBinding, error) {
	if q.Validate() != nil || describe == nil || expected.ConfigurationVersion == 0 || expected.ConfigurationVersion > expected.RowVersion || expected.RowVersion > math.MaxInt64 {
		return VPNSSOBinding{}, vault.ErrFormat
	}
	// Observe authenticated nodes before the resolver can deny a deleted source,
	// broken ancestry or changed account. Denial must not erase a revocation floor.
	o.vpnSSOObservingNodes = true
	defer func() { o.vpnSSOObservingNodes = false }()
	r, err := o.resolveConnectionRequest(ctx, q, false)
	if err != nil {
		return VPNSSOBinding{}, err
	}
	actual, err := connectionTunnelBinding(r, q)
	if err != nil {
		return VPNSSOBinding{}, err
	}
	if actual.RowVersion < expected.RowVersion {
		return VPNSSOBinding{}, vault.ErrRollback
	}
	// A metadata-only edit may advance the row without changing configuration.
	// Every target, provider, recipient session and configuration choice is exact.
	comparison := actual
	comparison.RowVersion = expected.RowVersion
	if comparison != expected || (actual.Kind != 2 && actual.Kind != 9) {
		return VPNSSOBinding{}, vault.ErrAuthentication
	}
	var provider VPNSSOProvider
	err = o.withResolvedConnectionTunnel(ctx, r, func(_ Resolution, configuration []byte) error {
		var err error
		provider, err = describe(actual.Kind, configuration)
		return err
	})
	if err != nil {
		return VPNSSOBinding{}, err
	}
	// Protected routes currently have one authenticated VPN hop. Keep this native
	// route identity separate from credentials, usernames and destination sessions.
	// Extending supported chains must extend this digest with every resolved hop.
	public, _ := json.Marshal(struct {
		Purpose, WorkspaceID, FileID, TunnelID string
		Kind                                   uint16
		ConfigurationVersion                   uint64
	}{"wormhole/v1/vpn-sso-upstream-route", actual.WorkspaceID, actual.FileID, actual.TunnelConfigID, actual.Kind, actual.ConfigurationVersion})
	binding := VPNSSOBinding{WorkspaceID: actual.WorkspaceID, FileID: actual.FileID, TunnelID: actual.TunnelConfigID, AccountID: r.Identity.WorkspaceID, Kind: actual.Kind, ConfigurationVersion: actual.ConfigurationVersion, GatewayOrigin: provider.GatewayOrigin, Realm: provider.Realm, RouteDigest: sha256.Sum256(public), TrustDigest: provider.TrustDigest}
	if _, err := binding.digest(); err != nil {
		return VPNSSOBinding{}, err
	}
	if err := ctx.Err(); err != nil {
		return VPNSSOBinding{}, err
	}
	return binding, nil
}

// BeginConnectionVPNSSOTransfer owns fresh resolution and transfer admission
// under the same lock. planned came from this native owner/checkpoint selection,
// never from renderer data. Subsequent actions recheck the source under that
// same lock, before any new ciphertext or acknowledgement can be released.
func (o *Owner) BeginConnectionVPNSSOTransfer(ctx context.Context, q TunnelPlanRequest, expected vault.TunnelBundleBinding, planned VPNSSOBinding, request VPNSSOTransferRequest, describe VPNSSODescribeProvider) (VPNSSOTransferOffer, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	current, err := o.planConnectionVPNSSO(ctx, q, expected, describe)
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
	stage := o.vpnSSOTransfers[offer.Context.TransferID]
	stage.sourceCheck = func(ctx context.Context) error {
		fresh, err := o.planConnectionVPNSSO(ctx, q, expected, describe)
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
