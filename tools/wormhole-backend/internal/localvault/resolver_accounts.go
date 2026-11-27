package localvault

import (
	"context"
	"runtime"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// ResolveConnectionPath authenticates the route and selects the account for one
// protocol path. Plan's identity/credential and Credential describe that path;
// GatewayAccount separately describes RDP's gateway. This remains native metadata,
// never a capability: every secret release repeats resolution under the owner lock.
func (o *Owner) ResolveConnectionPath(ctx context.Context, id, override, path string) (Resolution, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if path == "" {
		return Resolution{}, vault.ErrPolicy
	}
	return o.resolveConnectionPath(ctx, id, override, path)
}

func (o *Owner) resolveConnectionPath(ctx context.Context, id, override, path string) (Resolution, error) {
	return o.resolveConnectionAccounts(ctx, id, override, path, false)
}

func (o *Owner) resolveConnectionAccounts(ctx context.Context, id, override, path string, manualRDP bool) (Resolution, error) {
	r, err := o.resolveCandidateConnection(ctx, id, override)
	if err != nil {
		return Resolution{}, err
	}
	return o.selectConnectionAccounts(ctx, r, override, path, manualRDP)
}

func (o *Owner) selectConnectionAccounts(ctx context.Context, r Resolution, override, path string, manualRDP bool) (Resolution, error) {
	var err error
	base := r.Plan
	if manualRDP {
		if base.Protocol != 1 || override != "" {
			return Resolution{}, vault.ErrPolicy
		}
		// Only the primary identity is replaced. Explicit client settings and
		// independently selected/pinned gateway credentials remain authoritative.
		base.Username, base.Domain = "", ""
		base.Credential = resolver.Choice{Kind: "none"}
	}
	if path == "" {
		path = resolver.DefaultPath(base.Protocol)
	}
	if !resolver.PathAllowed(base.Protocol, path) {
		return Resolution{}, vault.ErrPolicy
	}
	var migration resolver.MigrationPlan
	for _, f := range r.leaf.Fields {
		if f.Field == vaultstore.NodeResolverMigrationField && f.Present {
			migration, err = o.readResolverMigration(ctx, r.leaf)
			if err != nil {
				return Resolution{}, err
			}
		}
	}
	for _, entry := range migration.Entries {
		if entry.Choice == "keep" && !resolver.PathAllowed(base.Protocol, entry.Legacy.ProtocolPath) {
			return Resolution{}, vault.ErrPolicy
		}
	}
	credentials := map[string]vaultstore.Credential{}
	for _, c := range []*vaultstore.Credential{r.Credential, r.GatewayCredential} {
		if c != nil {
			credentials[c.ID] = *c
		}
	}
	readCredential := func(id, protocol string) (vaultstore.Credential, error) {
		if c, ok := credentials[id]; ok {
			if protocol != "" && c.Protocol != protocol {
				return vaultstore.Credential{}, resolver.ErrCredential
			}
			return c, nil
		}
		c, err := o.resolutionCredential(ctx, id, protocol)
		if err == nil {
			credentials[id] = c
		}
		return c, err
	}
	overridden := func(path string) bool {
		return override != "" && (path != "rdp-gateway" || base.GatewaySameCredentials)
	}
	account := func(path string) (resolver.EffectiveCredentialSnapshot, error) {
		if !overridden(path) && !(manualRDP && path == "rdp") {
			for _, entry := range migration.Entries {
				if entry.Legacy.ProtocolPath == path && entry.Choice == "keep" {
					return entry.Legacy, nil
				}
			}
		}
		return resolver.AccountSnapshot(base, path, runtime.GOOS, func(id string) (vaultstore.CredentialMetadata, error) {
			c, err := readCredential(id, "rdp")
			return c.CredentialMetadata, err
		})
	}
	mainPath := resolver.DefaultPath(base.Protocol)
	main, err := account(mainPath)
	if err != nil {
		return Resolution{}, err
	}
	mainPlan := base
	mainPlan.Username, mainPlan.Domain = main.Username, main.Domain
	r.externalRDP = main.SourceKind == "system" || resolver.RequiresExternalRDP(runtime.GOOS, mainPlan)
	selected := main
	if path != mainPath {
		selected, err = account(path)
		if err != nil {
			return Resolution{}, err
		}
	}
	selectedCredential := func(s resolver.EffectiveCredentialSnapshot) (*vaultstore.Credential, error) {
		if s.SourceKind != "saved" {
			return nil, nil
		}
		protocol := resolver.CredentialProtocol(base.Protocol)
		if s.ProtocolPath == "reveal" {
			protocol = ""
		} // Historical Reveal may deliberately select another protocol's profile.
		c, err := readCredential(s.CredentialID, protocol)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	r.Credential, err = selectedCredential(selected)
	if err != nil {
		return Resolution{}, err
	}
	if base.Protocol == 1 && base.GatewayMethod != 0 {
		gateway, err := account("rdp-gateway")
		if err != nil {
			return Resolution{}, err
		}
		r.GatewayAccount = gateway
		r.externalRDP = r.externalRDP || gateway.SourceKind == "system"
		same := base.GatewaySameCredentials && gateway.SourceKind == main.SourceKind && gateway.CredentialID == main.CredentialID && gateway.Username == main.Username
		r.Plan.GatewaySameCredentials = same
		r.Plan.GatewayCredentialID = ""
		r.GatewayCredential = nil
		if !same {
			r.GatewayCredential, err = selectedCredential(gateway)
			if err != nil {
				return Resolution{}, err
			}
			if gateway.SourceKind == "saved" {
				r.Plan.GatewayCredentialID = gateway.CredentialID
			}
		}
	}
	r.Account = selected
	r.Plan.ExternalRDPClient = base.ExternalRDPClient || r.externalRDP
	r.Plan.Username, r.Plan.Domain = selected.Username, selected.Domain
	// A retained migration choice is an explicit leaf setting. A candidate
	// choice keeps its original inheritance owner, including override isolation.
	if selected.ResolverVersion == 0 || (path == "rdp-gateway" && !base.GatewaySameCredentials) {
		r.Plan.Credential = resolver.Choice{Kind: selected.SourceKind, ID: selected.CredentialID, NodeID: selected.NodeID}
	}
	if selected.SourceKind == "system" {
		r.Plan.Credential = resolver.Choice{Kind: "none"}
	}
	if selected.SourceKind == "saved" && overridden(path) {
		r.Plan.Credential.Kind = "override"
	}
	return r, nil
}
