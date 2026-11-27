package main

import (
	"context"
	"math"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// fileID is the native owner's authenticated startup identity, never a server or
// renderer-selected value. Public planning is separate from audited key opening.
func sharedTunnelBinding(workspace uuid.UUID, fileID string, p resolver.Plan, q localvault.TunnelPlanRequest, t *sharedpg.ResolvedTunnel) (vault.TunnelBundleBinding, error) {
	id, err := uuid.Parse(fileID)
	if err != nil || id == uuid.Nil || id.String() != fileID || workspace == uuid.Nil || q.Validate() != nil || q.CredentialOverride != "" || p.NodeID != q.NodeID || t == nil || p.TunnelID == "" || p.TunnelID != t.Metadata.ID || t.Metadata.Validate() != nil || t.Boundary == uuid.Nil || t.RowVersion == 0 || t.RowVersion > math.MaxInt64 || t.ConfigurationVersion == 0 || t.ConfigurationVersion > t.RowVersion {
		return vault.TunnelBundleBinding{}, vault.ErrPolicy
	}
	protocol := resolver.TunnelProtocol(p.Protocol)
	if protocol == "" {
		return vault.TunnelBundleBinding{}, vault.ErrPolicy
	}

	if p.Port < 1 || p.Port > 65535 || p.ExternalRDPClient || p.Host == "" || len(p.Host) > vault.MaxContextBytes || strings.IndexFunc(p.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return vault.TunnelBundleBinding{}, vault.ErrPolicy
	}
	return vault.TunnelBundleBinding{BundleBinding: vault.BundleBinding{WorkspaceID: workspace.String(), NodeID: q.NodeID, SessionID: q.SessionID, RequestID: q.RequestID, Protocol: protocol, Host: p.Host, Port: uint16(p.Port), TunnelConfigID: p.TunnelID, Epoch: q.Epoch}, FileID: fileID, Kind: uint16(t.Metadata.Kind), RowVersion: t.RowVersion, ConfigurationVersion: t.ConfigurationVersion}, nil
}

func sharedCurrentRoute(workspace uuid.UUID, fileID string, p resolver.Plan, q localvault.TunnelPlanRequest, t *sharedpg.ResolvedTunnel, route *vault.TunnelBundleBinding, endpoint string) error {
	if route == nil {
		if p.TunnelID != "" || t != nil || endpoint != "" {
			return vault.ErrPolicy
		}
		return nil
	}
	if !vault.ValidRouteEndpoint(endpoint) {
		return vault.ErrFormat
	}
	current, err := sharedTunnelBinding(workspace, fileID, p, q, t)
	if err != nil {
		return err
	}
	if current != *route {
		return vault.ErrPolicy
	}
	return nil
}

func (c *sharedAdmissionController) checkConnectionRoute(fileID string, q localvault.TunnelPlanRequest, route *vault.TunnelBundleBinding, endpoint string) func(*sharedpg.VerifiedCredentialRelease) error {
	return func(v *sharedpg.VerifiedCredentialRelease) error {
		p, err := v.Plan()
		if err != nil {
			return err
		}
		t, err := v.Tunnel()
		if err != nil {
			return err
		}
		return sharedCurrentRoute(c.trustBinding.WorkspaceID, fileID, p, q, t, route, endpoint)
	}
}

func (c *sharedAdmissionController) ResolveConnectionRoute(ctx context.Context, q localvault.TunnelPlanRequest, fileID string) (*vault.TunnelBundleBinding, error) {
	if ctx == nil || q.Validate() != nil {
		return nil, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return nil, vault.ErrPolicy
	}
	p, err := c.PlanConnection(ctx, uuid.MustParse(q.NodeID))
	if err != nil {
		return nil, err
	}
	if p.Plan.TunnelID == "" && p.Tunnel == nil {
		return nil, nil
	}
	binding, err := sharedTunnelBinding(c.trustBinding.WorkspaceID, fileID, p.Plan, q, p.Tunnel)
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

func (c *sharedAdmissionController) SealConnectionTunnel(ctx context.Context, q localvault.TunnelBundleRequest, fileID, source string) (localvault.TunnelConnectionBundle, error) {
	if ctx == nil || q.Validate() != nil {
		return localvault.TunnelConnectionBundle{}, vault.ErrFormat
	}
	if q.CredentialOverride != "" {
		return localvault.TunnelConnectionBundle{}, vault.ErrPolicy
	}
	var binding vault.TunnelBundleBinding
	var result localvault.TunnelConnectionBundle
	err := c.withConnectionValues(ctx, uuid.MustParse(q.NodeID), source, sharedpg.DefaultConnectionPath, nil, func(v *sharedpg.VerifiedCredentialRelease) error {
		p, err := v.Plan()
		if err != nil {
			return err
		}
		t, err := v.Tunnel()
		if err != nil {
			return err
		}
		binding, err = sharedTunnelBinding(c.trustBinding.WorkspaceID, fileID, p, q.Plan(), t)
		return err
	}, true, func(_ resolver.Plan, values sharedpg.CredentialReleaseValues) error {
		if values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil {
			return vault.ErrPolicy
		}
		sealed, err := vault.SealTunnelBundle(q.PublicKey, binding, values.Tunnel.Fields["settings"])
		if err != nil {
			return err
		}
		result = localvault.TunnelConnectionBundle{Binding: binding, Bundle: sealed}
		return nil
	})
	if err != nil {
		vault.Wipe(result.Bundle.Enc)
		vault.Wipe(result.Bundle.Ciphertext)
		return localvault.TunnelConnectionBundle{}, err
	}
	return result, nil
}

func (c *sharedAdmissionController) PlanConnectionTunnel(ctx context.Context, q localvault.TunnelPlanRequest, fileID string) (vault.TunnelBundleBinding, error) {
	route, err := c.ResolveConnectionRoute(ctx, q, fileID)
	if err != nil {
		return vault.TunnelBundleBinding{}, err
	}
	if route == nil {
		return vault.TunnelBundleBinding{}, vaultstore.ErrMissing
	}
	return *route, nil
}
