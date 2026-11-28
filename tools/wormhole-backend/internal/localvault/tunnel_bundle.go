package localvault

import (
	"context"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type TunnelPlanRequest struct {
	NodeID, CredentialOverride, SessionID, RequestID string
	Epoch                                            uint64
}

type TunnelBundleRequest struct {
	NodeID, CredentialOverride, SessionID, RequestID string
	Epoch                                            uint64
	PublicKey                                        []byte
}
type TunnelConnectionBundle struct {
	Binding vault.TunnelBundleBinding `json:"binding"`
	Bundle  vault.SealedBundle        `json:"bundle"`
}

func (q TunnelBundleRequest) Plan() TunnelPlanRequest {
	return TunnelPlanRequest{q.NodeID, q.CredentialOverride, q.SessionID, q.RequestID, q.Epoch}
}
func (q TunnelBundleRequest) Validate() error {
	if len(q.PublicKey) != 32 {
		return vault.ErrFormat
	}
	return q.Plan().Validate()
}
func (q TunnelPlanRequest) Validate() error {
	ids := []string{q.NodeID, q.SessionID, q.RequestID}
	if q.CredentialOverride != "" {
		ids = append(ids, q.CredentialOverride)
	}
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return vault.ErrFormat
		}
	}
	if q.Epoch == 0 || q.Epoch > 9007199254740991 {
		return vault.ErrFormat
	}
	return nil
}

// The caller selects a connection, never a raw tunnel ID or configuration.
// Re-resolution, route MAC verification and secret borrowing share the owner
// lock. Editing the connection cannot combine a new target with an old route.
func (o *Owner) SealConnectionTunnel(ctx context.Context, q TunnelBundleRequest) (TunnelConnectionBundle, error) {
	if err := q.Validate(); err != nil {
		return TunnelConnectionBundle{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q.Plan(), false)
	if err != nil {
		return TunnelConnectionBundle{}, err
	}
	var result TunnelConnectionBundle
	err = o.withResolvedConnectionTunnel(ctx, r, func(r Resolution, configuration []byte) error {
		binding, err := connectionTunnelBinding(r, q.Plan())
		if err != nil {
			return err
		}
		sealed, err := vault.SealTunnelBundle(q.PublicKey, binding, configuration)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			vault.Wipe(sealed.Ciphertext)
			return err
		}
		result = TunnelConnectionBundle{Binding: binding, Bundle: sealed}
		return nil
	})
	if err != nil {
		return TunnelConnectionBundle{}, err
	}
	return result, nil
}

// Planning authenticates current metadata but never borrows or decrypts settings.
// It is not a release capability: a new bundle re-resolves under the owner lock.
func (o *Owner) PlanConnectionTunnel(ctx context.Context, q TunnelPlanRequest) (vault.TunnelBundleBinding, error) {
	route, err := o.ResolveConnectionRoute(ctx, q)
	if err != nil {
		return vault.TunnelBundleBinding{}, err
	}
	if route == nil {
		return vault.TunnelBundleBinding{}, vaultstore.ErrMissing
	}
	return *route, nil
}

// A nil route is an authenticated direct-route decision, never an error fallback.
func (o *Owner) ResolveConnectionRoute(ctx context.Context, q TunnelPlanRequest) (*vault.TunnelBundleBinding, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.resolveConnectionRequest(ctx, q, false)
	if err != nil {
		return nil, err
	}
	if r.Tunnel == nil {
		return nil, nil
	}
	binding, err := connectionTunnelBinding(r, q)
	if err != nil {
		return nil, err
	}
	return &binding, nil
}
func connectionTunnelBinding(r Resolution, q TunnelPlanRequest) (vault.TunnelBundleBinding, error) {
	if r.Tunnel == nil {
		return vault.TunnelBundleBinding{}, vaultstore.ErrMissing
	}
	protocol := resolver.TunnelProtocol(r.Plan.Protocol)
	if protocol == "" {
		return vault.TunnelBundleBinding{}, vault.ErrPolicy
	}

	external := r.Plan.ExternalRDPClient
	if r.Plan.Protocol == 1 {
		// A VPN lease authorizes the route, not the saved primary identity.
		// The RDP recipient checks its actual account before opening a session.
		external = r.rdpSettings.UseExternalClient
	}
	if r.Plan.Port < 1 || r.Plan.Port > 65535 || external || r.Plan.Host == "" || len(r.Plan.Host) > vault.MaxContextBytes || strings.IndexFunc(r.Plan.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return vault.TunnelBundleBinding{}, vault.ErrPolicy
	}
	return vault.TunnelBundleBinding{
		BundleBinding: vault.BundleBinding{WorkspaceID: r.Identity.WorkspaceID, SessionID: q.SessionID, RequestID: q.RequestID, NodeID: q.NodeID, Protocol: protocol, Host: r.Plan.Host, Port: uint16(r.Plan.Port), TunnelConfigID: r.Tunnel.ID, Epoch: q.Epoch},
		FileID:        r.Identity.FileID, Kind: uint16(r.Tunnel.Kind), RowVersion: r.Tunnel.RowVersion, ConfigurationVersion: r.Tunnel.ConfigurationVersion,
	}, nil
}
