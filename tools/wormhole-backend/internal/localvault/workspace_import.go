package localvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const workspaceImportMetadataLimit = 8 * 1024 * 1024

// WorkspaceImport is an authenticated, native-only view of a local source.
// Accounts records the actual choices, including retained legacy pins. A
// destination can remap the IDs and compare these with its own resolver before
// authorizing an upload. The fingerprint binds source identity, revisions,
// metadata and those choices to the preview.
type WorkspaceImport struct {
	Source      vaultstore.Identity
	Catalog     Catalog
	Accounts    []resolver.EffectiveCredentialSnapshot
	TunnelFallbacks map[string]string
	Fingerprint [sha256.Size]byte
}

func (WorkspaceImport) MarshalJSON() ([]byte, error) { return nil, vault.ErrPolicy }

// ResolverMigration compares the approved source accounts with resolutions for
// the translated destination graph. Retained source pins become the baseline
// just like other active source choices. A difference defaults to a new pin.
func (s WorkspaceImport) ResolverMigration(workspaceID string, nodes, credentials map[string]string, candidate []resolver.EffectiveCredentialSnapshot) (resolver.MigrationPlan, error) {
	if s.Fingerprint == ([sha256.Size]byte{}) {
		return resolver.MigrationPlan{}, resolver.ErrMigration
	}
	baseline := make([]resolver.EffectiveCredentialSnapshot, 0, len(s.Accounts))
	for _, account := range s.Accounts {
		account.NodeID = nodes[account.NodeID]
		account.ResolverVersion = 0
		switch account.SourceKind {
		case "inline":
			account.CredentialID = account.NodeID
		case "saved":
			account.CredentialID = credentials[account.CredentialID]
		}
		baseline = append(baseline, account)
	}
	return resolver.BuildMigration(workspaceID, baseline, candidate)
}

func (o *Owner) CaptureWorkspaceImport(ctx context.Context) (WorkspaceImport, error) {
	if ctx == nil {
		return WorkspaceImport{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.captureWorkspaceImport(ctx)
}

// CaptureWorkspaceImportWithFallbacks lets the native provider codec extract
// bounded route IDs from the same locked snapshot. It lends only the relevant
// Fortinet IPsec settings and keeps every plaintext out of the preview object.
func (o *Owner) CaptureWorkspaceImportWithFallbacks(ctx context.Context, inspect func([]byte) (string, error)) (WorkspaceImport, error) {
	if ctx == nil || inspect == nil {
		return WorkspaceImport{}, vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	source, err := o.captureWorkspaceImport(ctx)
	if err != nil {
		return WorkspaceImport{}, err
	}
	source.TunnelFallbacks = make(map[string]string)
	for _, tunnel := range source.Catalog.Tunnels {
		if tunnel.Kind != 9 {
			continue
		}
		err := o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "tunnel", OwnerID: tunnel.ID, Field: "settings"},
			tunnel.ConfigurationVersion, true, func(value []byte) error {
				fallback, err := inspect(value)
				if err == nil && fallback != "" {
					source.TunnelFallbacks[tunnel.ID] = fallback
				}
				return err
			})
		if err != nil {
			return WorkspaceImport{}, err
		}
	}
	return source, ctx.Err()
}

func (o *Owner) captureWorkspaceImport(ctx context.Context) (WorkspaceImport, error) {
	if o.closed {
		return WorkspaceImport{}, vaultstore.ErrClosed
	}
	store, ok := o.store.(catalogStore)
	if !ok {
		return WorkspaceImport{}, vaultstore.ErrStorage
	}
	if err := store.CheckForeignKeys(ctx); err != nil {
		return WorkspaceImport{}, err
	}
	catalog, err := o.readCatalog(ctx, workspaceImportMetadataLimit)
	if err != nil {
		return WorkspaceImport{}, err
	}
	result := WorkspaceImport{Source: o.store.Identity(), Catalog: catalog}
	digest := sha256.New()
	digest.Write([]byte("wormhole/v1/workspace-import-source\x00"))
	encoder := json.NewEncoder(digest)
	if err := encoder.Encode(result.Source); err != nil {
		return WorkspaceImport{}, err
	}
	if err := encoder.Encode(catalog); err != nil {
		return WorkspaceImport{}, err
	}
	nodeVersions := make(map[string]uint64, len(catalog.Nodes))
	credentialSeals := make(map[string][]byte, len(catalog.Credentials))
	tunnelSeals := make(map[string][]byte, len(catalog.Tunnels))
	for _, node := range catalog.Nodes {
		nodeVersions[node.ID] = node.RowVersion
	}
	for _, credential := range catalog.Credentials {
		credentialSeals[credential.ID] = credential.Seal
	}
	for _, tunnel := range catalog.Tunnels {
		tunnelSeals[tunnel.ID] = tunnel.Seal
	}
	credentialMatches := func(c *vaultstore.Credential) bool {
		return c == nil || bytes.Equal(credentialSeals[c.ID], c.Seal)
	}
	remaining := workspaceImportMetadataLimit
	for _, node := range catalog.Nodes {
		if node.Kind == 0 {
			continue
		}
		candidate, err := o.resolveCandidateConnection(ctx, node.ID, "")
		if err != nil {
			return WorkspaceImport{}, err
		}
		if !bytes.Equal(candidate.leaf.Seal, node.Seal) || candidate.Identity != result.Source ||
			!credentialMatches(candidate.Credential) || !credentialMatches(candidate.GatewayCredential) ||
			(candidate.Tunnel != nil && !bytes.Equal(tunnelSeals[candidate.Tunnel.ID], candidate.Tunnel.Seal)) {
			return WorkspaceImport{}, vault.ErrAuthentication
		}
		for _, ancestor := range candidate.Nodes {
			if nodeVersions[ancestor.ID] != ancestor.Version {
				return WorkspaceImport{}, vault.ErrAuthentication
			}
		}
		for _, path := range resolver.AccountPaths(candidate.Plan.Protocol) {
			resolved, err := o.selectConnectionAccounts(ctx, candidate, "", path, false)
			if err != nil {
				return WorkspaceImport{}, err
			}
			if !credentialMatches(resolved.Credential) || !credentialMatches(resolved.GatewayCredential) {
				return WorkspaceImport{}, vault.ErrAuthentication
			}
			raw, err := json.Marshal(resolved.Account)
			if err != nil || len(raw)+1 > remaining {
				return WorkspaceImport{}, vault.ErrFormat
			}
			remaining -= len(raw) + 1
			digest.Write(raw)
			digest.Write([]byte{'\n'})
			result.Accounts = append(result.Accounts, resolved.Account)
		}
	}
	if err := ctx.Err(); err != nil {
		return WorkspaceImport{}, err
	}
	copy(result.Fingerprint[:], digest.Sum(nil))
	return result, nil
}

// WithWorkspaceImportSecrets rechecks the approved preview before opening any
// field. It lends one exact, authenticated value at a time and wipes it after
// use. The native consumer must stage ciphertext only and discard the staged
// import on error. It must not retain plaintext, commit or reenter the owner
// from the callback. The source remains unchanged.
func (o *Owner) WithWorkspaceImportSecrets(ctx context.Context, fingerprint [sha256.Size]byte, use func(vaultstore.SecretRef, []byte) error) error {
	if ctx == nil || use == nil || fingerprint == ([sha256.Size]byte{}) {
		return vault.ErrFormat
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	source, err := o.captureWorkspaceImport(ctx)
	if err != nil {
		return err
	}
	if source.Fingerprint != fingerprint {
		return vaultstore.ErrConflict
	}
	// The destination regenerates resolver pins against its own workspace and
	// key graph. The source's sealed migration document is never transferred.
	read := func(kind, id string, fields []vaultstore.SecretField) error {
		for _, field := range fields {
			if !field.Present || kind == "node" && !vaultstore.NodeEditableField(field.Field) {
				continue
			}
			ref := vaultstore.SecretRef{OwnerKind: kind, OwnerID: id, Field: field.Field}
			if err := o.withSecret(ctx, ref, field.Version, true, func(value []byte) error {
				return use(ref, value)
			}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, node := range source.Catalog.Nodes {
		if err := read("node", node.ID, node.Fields); err != nil {
			return err
		}
	}
	for _, credential := range source.Catalog.Credentials {
		if err := read("credential", credential.ID, credential.Fields); err != nil {
			return err
		}
	}
	for _, tunnel := range source.Catalog.Tunnels {
		if err := read("tunnel", tunnel.ID, []vaultstore.SecretField{{Field: "settings", Version: tunnel.ConfigurationVersion, Present: true}}); err != nil {
			return err
		}
	}
	return ctx.Err()
}
