package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// A fresh audited Source Use precedes every archive action. The personal owner
// accepts only the short-lived native receipt minted under this admission gate;
// its source check cannot acquire the gate recursively or use an old receipt.
func (c *sharedAdmissionController) withVPNSSOSource(ctx context.Context, p *sharedVPNSSOStorage, q nativeVPNSSOBegin, use func(context.Context, localvault.VPNSSOBinding) error) error {
	if q.request.Validate() != nil || q.request.CredentialOverride != "" || use == nil {
		return vault.ErrPolicy
	}
	if q.hasFallback {
		return c.withFallbackVPNSSOSource(ctx, p, q, use)
	}
	return c.withConnectionReleaseScope(ctx, uuid.MustParse(q.request.NodeID), "ui", sharedpg.DefaultConnectionPath, true, nil, func(ctx context.Context, trust sharedpg.TrustState, verified *sharedpg.VerifiedCredentialRelease) error {
		if p == nil || c.vpnSSO != p || q.custodyWorkspace != p.vaultID || q.custodyFile != p.fileID {
			return vault.ErrAuthentication
		}
		plan, err := verified.Plan()
		if err != nil {
			return err
		}
		tunnel, err := verified.Tunnel()
		if err != nil {
			return err
		}
		actual, err := sharedTunnelBinding(c.trustBinding.WorkspaceID, p.fileID, plan, q.request, tunnel)
		if err != nil {
			return err
		}
		if actual.RowVersion < q.binding.RowVersion {
			return vault.ErrRollback
		}
		comparison := actual
		comparison.RowVersion = q.binding.RowVersion
		if comparison != q.binding || (actual.Kind != 2 && actual.Kind != 9) {
			return vault.ErrAuthentication
		}
		security, err := c.vpnSSOSecurity(ctx, trust)
		if err != nil {
			return err
		}
		return c.privateKeys.With(func(keys []byte) error {
			if len(keys) != 64 {
				return vault.ErrAuthentication
			}
			return verified.WithTunnelValues(ctx, trust, keys[:32], func(_ resolver.Plan, values sharedpg.CredentialReleaseValues) error {
				if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil {
					return vault.ErrPolicy
				}
				provider, err := describeNativeVPNSSO(q.startURL, q.ignore)(actual.Kind, values.Tunnel.Fields["settings"])
				if err != nil {
					return err
				}
				public, _ := json.Marshal(struct {
					Purpose, WorkspaceID, FileID, TunnelID string
					Kind                                   uint16
					ConfigurationVersion                   uint64
				}{"wormhole/v1/vpn-sso-upstream-route", actual.WorkspaceID, actual.FileID, actual.TunnelConfigID, actual.Kind, actual.ConfigurationVersion})
				binding := localvault.VPNSSOBinding{WorkspaceID: actual.WorkspaceID, FileID: actual.FileID, TunnelID: actual.TunnelConfigID, AccountID: c.trustBinding.UserID.String(), Kind: actual.Kind, ConfigurationVersion: actual.ConfigurationVersion, GatewayOrigin: provider.GatewayOrigin, Realm: provider.Realm, RouteDigest: sha256.Sum256(public), TrustDigest: provider.TrustDigest}
				receipt := &sharedVPNSSOReceipt{storage: p, security: security, binding: binding, active: true}
				defer func() { receipt.active = false }()
				return use(context.WithValue(ctx, sharedVPNSSOReceiptKey{}, receipt), binding)
			})
		})
	})
}

func (c *sharedAdmissionController) vpnSSOSecurity(ctx context.Context, trust sharedpg.TrustState) (localvault.SecurityProfile, error) {
	policy, err := trust.Policy()
	if err != nil {
		return localvault.SecurityProfile{}, err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return localvault.SecurityProfile{}, err
	}
	return c.admittedSecurity(policy, floor)
}

func (p *sharedVPNSSOStorage) checkSource(planned localvault.VPNSSOBinding) func(context.Context) error {
	return func(ctx context.Context) error {
		if ctx == nil {
			return vault.ErrPolicy
		}
		r, _ := ctx.Value(sharedVPNSSOReceiptKey{}).(*sharedVPNSSOReceipt)
		if r == nil || !r.active || r.storage != p || r.binding != planned {
			return vault.ErrAuthentication
		}
		return nil
	}
}

func (c *sharedAdmissionController) lookupVPNSSOSource(ctx context.Context, id string) (*sharedVPNSSOStorage, sharedVPNSSOSource, error) {
	if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
		return nil, sharedVPNSSOSource{}, err
	}
	defer func() { <-c.gate }()
	p := c.vpnSSO
	if p == nil {
		return nil, sharedVPNSSOSource{}, sharedpg.ErrSessionClosed
	}
	if id == "" {
		return p, sharedVPNSSOSource{}, nil
	}
	s, ok := p.transfers[id]
	if !ok {
		return nil, s, vault.ErrAuthentication
	}
	return p, s, nil
}

func (c *sharedAdmissionController) runVPNSSO(ctx context.Context, operation string, raw []byte) (result json.RawMessage, err error) {
	var begin nativeVPNSSOBegin
	var action nativeVPNSSOAction
	if operation == "vpn-sso-begin" {
		begin, err = decodeNativeVPNSSOBegin(raw)
	} else {
		action, err = decodeNativeVPNSSOAction(operation, raw)
	}
	defer vault.Wipe(action.packet.Bundle.Ciphertext)
	if err != nil {
		return nil, err
	}
	if operation == "vpn-sso-cancel" {
		if err := takeSharedAdmissionGate(ctx, c.gate); err != nil {
			return nil, err
		}
		defer func() { <-c.gate }()
		if c.vpnSSO != nil {
			if err := c.vpnSSO.owner.CancelVPNSSOTransfer(action.context); err != nil {
				return nil, err
			}
			delete(c.vpnSSO.transfers, action.context.TransferID)
		}
		return json.RawMessage(`{"cancelled":true}`), nil
	}
	p, source, err := c.lookupVPNSSOSource(ctx, action.context.TransferID)
	if err != nil {
		return nil, err
	}
	if operation != "vpn-sso-begin" {
		begin = source.request
	}
	err = c.withVPNSSOSource(ctx, p, begin, func(ctx context.Context, binding localvault.VPNSSOBinding) (err error) {
		if err := c.checkpointVPNSSOLocked(ctx); err != nil {
			return fmt.Errorf("SSO checkpoint admission: %w", err)
		}
		var value any
		var receipt *vault.VPNSSOTransferContext
		var committed *localvault.VPNSSOCheckpoint
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if checkpoint := c.checkpointVPNSSOLocked(cleanup); checkpoint != nil {
				err = errors.Join(err, fmt.Errorf("SSO checkpoint publication: %w", checkpoint))
			}
			if err == nil && receipt != nil {
				err = p.owner.ValidateVPNSSOReceipt(cleanup, *receipt, committed)
				if err != nil {
					err = fmt.Errorf("SSO response validation: %w", err)
				}
			}
			if err == nil {
				result, err = json.Marshal(value)
			} else {
				result = nil
			}
		}()
		if operation == "vpn-sso-begin" {
			for id, old := range p.transfers {
				if !time.Now().Before(old.expires) {
					if err := p.owner.CancelVPNSSOTransfer(old.context); err != nil {
						return err
					}
					delete(p.transfers, id)
				}
			}
			offer, err := p.owner.BeginAuthorizedVPNSSOTransfer(ctx, binding, begin.transfer, p.checkSource(binding))
			if err != nil {
				return fmt.Errorf("SSO personal transfer: %w", err)
			}
			if p.transfers == nil {
				p.transfers = make(map[string]sharedVPNSSOSource)
			}
			p.transfers[offer.Context.TransferID] = sharedVPNSSOSource{request: begin, binding: binding, context: offer.Context, expires: time.Now().Add(5 * time.Minute)}
			value, receipt = offer, &offer.Context
		} else {
			if binding != source.binding {
				return vault.ErrAuthentication
			}
			value, committed, err = performNativeVPNSSOAction(p.owner, ctx, operation, action)
			if operation == "vpn-sso-commit" && err == nil {
				delete(p.transfers, action.context.TransferID)
			}
			receipt = &action.context
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
