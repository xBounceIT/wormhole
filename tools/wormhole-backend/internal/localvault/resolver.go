package localvault

import (
	"context"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type ResolutionRevision struct {
	ID      string
	Version uint64
}

// Resolution is native metadata, not a capability or a renderer DTO. It records
// the exact authenticated inputs of this resolution. The owner re-resolves at
// every secret release instead of trusting a plan returned to a caller earlier.
type Resolution struct {
	quickID           string
	Identity          vaultstore.Identity
	Plan              resolver.Plan
	Nodes             []ResolutionRevision
	Credential        *vaultstore.Credential
	GatewayCredential *vaultstore.Credential
	Tunnel            *vaultstore.Tunnel
	Account           resolver.EffectiveCredentialSnapshot
	GatewayAccount    resolver.EffectiveCredentialSnapshot
	leaf              vaultstore.Node
	rdpSettings       vault.RDPSettings
	serialSettings    vault.SerialSettings
	externalRDP       bool
}

func (o *Owner) ResolveConnection(ctx context.Context, id, override string) (Resolution, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.resolveConnection(ctx, id, override)
}

func (o *Owner) resolveConnection(ctx context.Context, id, override string) (Resolution, error) {
	return o.resolveConnectionPath(ctx, id, override, "")
}

func (o *Owner) resolveCandidateConnection(ctx context.Context, id, override string) (Resolution, error) {
	s, err := o.nodeStore()
	if err != nil {
		return Resolution{}, err
	}
	r := Resolution{Identity: s.Identity()}
	chain := make([]vaultstore.NodeMetadata, 0, 8)
	seen := map[string]bool{}
	for current := id; current != ""; {
		if err := ctx.Err(); err != nil {
			return Resolution{}, err
		}
		if seen[current] || len(chain) >= vaultstore.MaxNodeDepth {
			return Resolution{}, resolver.ErrChain
		}
		seen[current] = true
		n, err := s.ReadNode(ctx, current)
		if err != nil {
			return Resolution{}, err
		}
		if n.ID != current {
			return Resolution{}, vault.ErrAuthentication
		}
		if err := o.verifyNode(n); err != nil {
			return Resolution{}, err
		}
		if n.RowVersion < o.nodeFloors[n.ID] {
			return Resolution{}, vault.ErrRollback
		}
		if n.Deleted {
			return Resolution{}, vaultstore.ErrMissing
		}
		if len(chain) == 0 {
			r.leaf = n
		}
		r.Nodes = append(r.Nodes, ResolutionRevision{n.ID, n.RowVersion})
		chain = append(chain, n.NodeMetadata)
		current = ""
		if n.ParentID != nil {
			current = *n.ParentID
		}
	}
	r.Plan, err = resolver.Resolve(chain, override)
	if err != nil {
		return Resolution{}, err
	}
	if r.Plan.Protocol == 1 {
		r.rdpSettings = resolver.ProjectRDPSettings(chain)
	} else if r.Plan.Protocol == 5 {
		r.serialSettings = resolver.ProjectSerialSettings(chain)
	}
	return o.completeConnectionCandidate(ctx, r)
}

func (o *Owner) completeConnectionCandidate(ctx context.Context, r Resolution) (Resolution, error) {
	if r.Plan.Credential.Kind == "slot" {
		return Resolution{}, vault.ErrPolicy
	}
	if r.Plan.Credential.Kind == "saved" || r.Plan.Credential.Kind == "override" {
		c, err := o.resolutionCredential(ctx, r.Plan.Credential.ID, resolver.CredentialProtocol(r.Plan.Protocol))
		if err != nil {
			return Resolution{}, err
		}
		r.Credential = &c
		r.Plan, err = resolver.ApplyCredential(r.Plan, c.CredentialMetadata)
		if err != nil {
			return Resolution{}, err
		}
	}
	if r.Plan.GatewayCredentialID != "" {
		if r.Credential != nil && r.Credential.ID == r.Plan.GatewayCredentialID {
			r.GatewayCredential = r.Credential
		} else {
			c, err := o.resolutionCredential(ctx, r.Plan.GatewayCredentialID, "rdp")
			if err != nil {
				return Resolution{}, err
			}
			r.GatewayCredential = &c
		}
	}
	if r.Plan.TunnelID != "" {
		ts, ok := o.store.(vaultstore.TunnelStore)
		if !ok {
			return Resolution{}, vaultstore.ErrStorage
		}
		t, err := ts.ReadTunnel(ctx, r.Plan.TunnelID)
		if err != nil {
			return Resolution{}, err
		}
		if t.ID != r.Plan.TunnelID {
			return Resolution{}, vault.ErrAuthentication
		}
		if err := o.verifyTunnel(t); err != nil {
			return Resolution{}, err
		}
		if t.Deleted {
			return Resolution{}, vaultstore.ErrMissing
		}
		r.Tunnel = &t
	}
	return r, nil
}

func (o *Owner) resolutionCredential(ctx context.Context, id, protocol string) (vaultstore.Credential, error) {
	s, err := o.credentialStore()
	if err != nil {
		return vaultstore.Credential{}, err
	}
	c, err := s.ReadCredential(ctx, id)
	if err != nil {
		return vaultstore.Credential{}, err
	}
	if c.ID != id {
		return vaultstore.Credential{}, vault.ErrAuthentication
	}
	if err := o.verifyCredential(c); err != nil {
		return vaultstore.Credential{}, err
	}
	if c.Deleted {
		return vaultstore.Credential{}, vaultstore.ErrMissing
	}
	if protocol != "" && c.Protocol != protocol {
		return vaultstore.Credential{}, resolver.ErrCredential
	}
	return c, nil
}

// WithConnectionSecret releases only the credential chosen for this connection,
// with its entire current routing chain authenticated under the same owner lock.
// This local primitive assumes local ownership; shared Use/Reveal and profile
// enforcement must precede it. No native transport exposes this plaintext API.
// Consumers must not reenter Owner, retain plaintext or convert it to a string.
func (o *Owner) WithConnectionSecret(ctx context.Context, id, override, path, field string, use func(Resolution, []byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if use == nil || !vaultstore.CredentialSecretField(field) {
		return vault.ErrFormat
	}
	if path == "" {
		return vault.ErrPolicy
	}
	r, err := o.resolveConnectionPath(ctx, id, override, path)
	if err != nil {
		return err
	}
	if r.Account.SourceKind == "system" || (r.externalRDP && path != "reveal") {
		return vault.ErrPolicy
	}
	c := r.Credential
	inline := r.Account.SourceKind == "inline"
	if path == "rdp-gateway" {
		if r.Plan.GatewayMethod == 0 {
			return vaultstore.ErrMissing
		}
	}
	if inline {
		if field != "password" {
			return vault.ErrPolicy
		}
		for _, f := range r.leaf.Fields {
			if f.Field == "inlinePassword" && f.Present {
				return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: id, Field: f.Field}, f.Version, true, func(value []byte) error { return use(r, value) })
			}
		}
		return vaultstore.ErrMissing
	}
	if c == nil {
		return vaultstore.ErrMissing
	}
	if c.Provider != "local" {
		return vault.ErrPolicy
	}
	for _, f := range c.Fields {
		if f.Field == field && f.Present {
			return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "credential", OwnerID: c.ID, Field: field}, f.Version, true, func(value []byte) error { return use(r, value) })
		}
	}
	return vaultstore.ErrMissing
}

// WithConnectionTunnel refuses a missing/disabled route and lends configuration
// only after re-resolving the current connection. Lease ownership and the sealed
// protocol handoff remain the caller's responsibility.
func (o *Owner) WithConnectionTunnel(ctx context.Context, id string, use func(Resolution, []byte) error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.withConnectionTunnel(ctx, id, "", use)
}

func (o *Owner) withConnectionTunnel(ctx context.Context, id, override string, use func(Resolution, []byte) error) error {
	if use == nil {
		return vault.ErrFormat
	}
	r, err := o.resolveConnection(ctx, id, override)
	if err != nil {
		return err
	}
	return o.withResolvedConnectionTunnel(ctx, r, use)
}

func (o *Owner) withResolvedConnectionTunnel(ctx context.Context, r Resolution, use func(Resolution, []byte) error) error {
	if r.Tunnel == nil {
		return vaultstore.ErrMissing
	}
	return o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: r.Tunnel.ID, Field: "settings"}, r.Tunnel.ConfigurationVersion, true, func(value []byte) error { return use(r, value) })
}
