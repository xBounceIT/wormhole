package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func (c *sharedAdmissionController) withFallbackVPNSSOSource(ctx context.Context, p *sharedVPNSSOStorage, q nativeVPNSSOBegin, use func(context.Context, localvault.VPNSSOBinding) error) error {
	if q.fallback.Validate() != nil || q.binding != q.fallback.Fallback {
		return vault.ErrAuthentication
	}
	return c.withFallbackRelease(ctx, uuid.MustParse(q.request.NodeID), uuid.MustParse(q.fallback.Primary.TunnelConfigID), uuid.MustParse(q.fallback.Fallback.TunnelConfigID), "ui", func(ctx context.Context, committed sharedpg.TrustState, verified *sharedpg.VerifiedFallbackRelease) error {
		if p == nil || c.vpnSSO != p || q.custodyWorkspace != p.vaultID || q.custodyFile != p.fileID {
			return vault.ErrAuthentication
		}
		sources, err := verified.Sources()
		if err != nil {
			return err
		}
		actual, err := sharedFallbackBinding(c.trustBinding.WorkspaceID, p.fileID, q.request, q.fallback.Primary, q.fallback.Fallback.RequestID, sources)
		if err != nil {
			return err
		}
		if actual != q.fallback {
			return vault.ErrAuthentication
		}
		security, err := c.vpnSSOSecurity(ctx, committed)
		if err != nil {
			return err
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return vault.ErrAuthentication
			}
			return verified.WithConfiguration(ctx, committed, keys[:32], selectNativeIPsecFallback, func(_ sharedpg.FallbackSources, configuration []byte) error {
				provider, err := describeNativeSSLSSO(q.startURL, q.ignore)(actual.Fallback.Kind, configuration)
				if err != nil {
					return err
				}
				binding, err := localvault.FallbackVPNSSOBinding(actual, c.trustBinding.UserID.String(), provider)
				if err != nil {
					return err
				}
				receipt := &sharedVPNSSOReceipt{storage: p, security: security, binding: binding, active: true}
				defer func() { receipt.active = false }()
				return use(context.WithValue(ctx, sharedVPNSSOReceiptKey{}, receipt), binding)
			})
		})
	})
}
