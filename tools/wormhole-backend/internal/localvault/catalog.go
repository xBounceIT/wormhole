package localvault

import (
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Catalog is an authenticated native snapshot. Never marshal it to a renderer:
// the transport must project explicit display fields, excluding seals/manifests.
type Catalog struct {
	Nodes       []vaultstore.Node
	Credentials []vaultstore.Credential
	Tunnels     []vaultstore.Tunnel
}

type catalogStore interface {
	vaultstore.NodeStore
	vaultstore.CredentialStore
	vaultstore.TunnelStore
	CheckForeignKeys(context.Context) error
}

// ReadCatalog holds ownership across all pages and domains. A mutation cannot
// interleave with the read. maximum bounds accumulated serialized metadata;
// exceeding it returns no partial catalog. No secret field is decrypted here.
func (o *Owner) ReadCatalog(ctx context.Context, maximum int) (Catalog, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readCatalog(ctx, maximum)
}

func (o *Owner) readCatalog(ctx context.Context, maximum int) (Catalog, error) {
	if o.closed {
		return Catalog{}, vaultstore.ErrClosed
	}
	if maximum < 1024 || maximum > 8*1024*1024 {
		return Catalog{}, vault.ErrFormat
	}
	store, ok := o.store.(catalogStore)
	if !ok {
		return Catalog{}, vaultstore.ErrStorage
	}
	var result Catalog
	var err error
	result.Nodes, err = readCatalogRecords(ctx, &maximum, store.ListNodes, func(n vaultstore.Node) (string, bool, error) {
		if n.RowVersion < o.nodeFloors[n.ID] {
			return "", false, vault.ErrRollback
		}
		return n.ID, n.Deleted, o.verifyNode(n)
	})
	if err != nil {
		return Catalog{}, err
	}
	result.Credentials, err = readCatalogRecords(ctx, &maximum, store.ListCredentials, func(c vaultstore.Credential) (string, bool, error) { return c.ID, c.Deleted, o.verifyCredential(c) })
	if err != nil {
		return Catalog{}, err
	}
	result.Tunnels, err = readCatalogRecords(ctx, &maximum, store.ListTunnels, func(t vaultstore.Tunnel) (string, bool, error) { return t.ID, t.Deleted, o.verifyTunnel(t) })
	if err != nil {
		return Catalog{}, err
	}
	if err := validateCatalogReferences(ctx, result); err != nil {
		return Catalog{}, err
	}
	return result, nil
}

func readCatalogRecords[T any](ctx context.Context, remaining *int, list func(context.Context, string, int) ([]T, error), verify func(T) (string, bool, error)) ([]T, error) {
	result := []T{}
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := list(ctx, after, 128)
		if err != nil {
			return nil, err
		}
		if len(page) > 128 {
			return nil, vault.ErrAuthentication
		}
		for _, value := range page {
			id, deleted, err := verify(value)
			if err != nil {
				return nil, err
			}
			if deleted || id <= after {
				return nil, vault.ErrAuthentication
			}
			raw, err := json.Marshal(value)
			if err != nil || len(raw)+1 > *remaining {
				return nil, vault.ErrFormat
			}
			*remaining -= len(raw) + 1
			result = append(result, value)
			after = id
		}
		if len(page) < 128 {
			return result, nil
		}
	}
}

func validateCatalogReferences(ctx context.Context, catalog Catalog) error {
	nodes := make(map[string]vaultstore.Node, len(catalog.Nodes))
	credentials, tunnels := map[string]bool{}, map[string]bool{}
	for _, n := range catalog.Nodes {
		nodes[n.ID] = n
	}
	for _, c := range catalog.Credentials {
		credentials[c.ID] = true
	}
	for _, t := range catalog.Tunnels {
		tunnels[t.ID] = true
	}
	for _, n := range catalog.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, id := range []*string{n.CredentialID, n.RDPGatewayCredentialID} {
			if id != nil && !credentials[*id] {
				return vault.ErrAuthentication
			}
		}
		if n.TunnelConfigID != nil && !tunnels[*n.TunnelConfigID] {
			return vault.ErrAuthentication
		}
		current := n
		for depth := 1; current.ParentID != nil; depth++ {
			parent, ok := nodes[*current.ParentID]
			if !ok || parent.Kind != 0 || depth >= vaultstore.MaxNodeDepth {
				return vault.ErrAuthentication
			}
			current = parent
		}
	}
	return ctx.Err()
}
