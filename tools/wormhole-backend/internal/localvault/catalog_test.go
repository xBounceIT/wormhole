package localvault

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type catalogTestStore struct {
	catalogStore
	nodes       func(context.Context, string, int) ([]vaultstore.Node, error)
	credentials func(context.Context, string, int) ([]vaultstore.Credential, error)
	tunnels     func(context.Context, string, int) ([]vaultstore.Tunnel, error)
}

func (s catalogTestStore) ListNodes(ctx context.Context, after string, limit int) ([]vaultstore.Node, error) {
	if s.nodes != nil {
		return s.nodes(ctx, after, limit)
	}
	return s.catalogStore.ListNodes(ctx, after, limit)
}
func (s catalogTestStore) ListCredentials(ctx context.Context, after string, limit int) ([]vaultstore.Credential, error) {
	if s.credentials != nil {
		return s.credentials(ctx, after, limit)
	}
	return s.catalogStore.ListCredentials(ctx, after, limit)
}
func (s catalogTestStore) ListTunnels(ctx context.Context, after string, limit int) ([]vaultstore.Tunnel, error) {
	if s.tunnels != nil {
		return s.tunnels(ctx, after, limit)
	}
	return s.catalogStore.ListTunnels(ctx, after, limit)
}

func TestCatalogAtomicAuthenticatedDomainsAndPagination(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	c := draft()
	if _, err := o.PutCredential(ctx, c, []SecretChange{{Field: "password", Value: []byte("private")}}, 0); err != nil {
		t.Fatal(err)
	}
	tunnel := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "VPN", Kind: 0}
	if _, err := o.PutTunnel(ctx, tunnel, []byte(`{"password":"private"}`), 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 130; i++ {
		n := nodeDraft()
		n.Name = fmt.Sprintf("Node %d", i)
		n.CredentialID = &c.ID
		n.CredentialMode = nodePtr(2)
		n.TunnelConfigID = &tunnel.ID
		if _, err := o.PutNode(ctx, n, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := o.ReadCatalog(ctx, 8*1024*1024)
	if err != nil || len(catalog.Nodes) != 130 || len(catalog.Credentials) != 1 || len(catalog.Tunnels) != 1 {
		t.Fatal("catalog omitted domain/page", err)
	}
	for i, n := range catalog.Nodes {
		if i > 0 && catalog.Nodes[i-1].ID >= n.ID {
			t.Fatal("unordered catalog")
		}
	}
	if partial, err := o.ReadCatalog(ctx, 1024); err != vault.ErrFormat || len(partial.Nodes) != 0 {
		t.Fatal("budget returned partial catalog", err)
	}
	base := o.store.(catalogStore)
	entered, release := make(chan struct{}), make(chan struct{})
	first := true
	o.store = catalogTestStore{catalogStore: base, nodes: func(ctx context.Context, after string, limit int) ([]vaultstore.Node, error) {
		if first {
			first = false
			close(entered)
			<-release
		}
		return base.ListNodes(ctx, after, limit)
	}}
	readDone := make(chan Catalog, 1)
	readErr := make(chan error, 1)
	go func() { value, err := o.ReadCatalog(ctx, 8*1024*1024); readDone <- value; readErr <- err }()
	<-entered
	if o.mu.TryLock() {
		o.mu.Unlock()
		close(release)
		t.Fatal("catalog released ownership between pages")
	}
	writeStarted, writeDone := make(chan struct{}), make(chan error, 1)
	go func() { close(writeStarted); _, err := o.PutNode(ctx, nodeDraft(), nil, 0); writeDone <- err }()
	<-writeStarted
	select {
	case err := <-writeDone:
		t.Fatal("mutation interleaved", err)
	default:
	}
	close(release)
	if value := <-readDone; len(value.Nodes) != 130 {
		t.Fatal("mixed snapshot", len(value.Nodes))
	}
	if err := <-readErr; err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if value, err := o.ReadCatalog(ctx, 8*1024*1024); err != nil || len(value.Nodes) != 131 {
		t.Fatal("mutation not visible after snapshot", err)
	}
}

func TestCatalogRejectsTamperingFaultsAndStaleNodes(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, err := o.PutNode(ctx, nodeDraft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := o.store.(catalogStore)
	for _, mode := range []string{"nodes-error", "credentials-error", "tunnels-error", "tampered-node", "stale-node", "deleted-node", "duplicate-node", "large-page"} {
		t.Run(mode, func(t *testing.T) {
			wrapped := catalogTestStore{catalogStore: base}
			sentinel := errors.New("storage failure")
			switch mode {
			case "nodes-error":
				wrapped.nodes = func(context.Context, string, int) ([]vaultstore.Node, error) { return nil, sentinel }
			case "credentials-error":
				wrapped.credentials = func(context.Context, string, int) ([]vaultstore.Credential, error) { return nil, sentinel }
			case "tunnels-error":
				wrapped.tunnels = func(context.Context, string, int) ([]vaultstore.Tunnel, error) { return nil, sentinel }
			default:
				wrapped.nodes = func(context.Context, string, int) ([]vaultstore.Node, error) {
					value := n
					switch mode {
					case "tampered-node":
						value.Name = "redirect"
					case "stale-node":
						o.nodeFloors[n.ID] = n.RowVersion + 1
					case "deleted-node":
						value.Deleted = true
						_ = o.root.With(func(key []byte) error { value.Seal, err = nodeMAC(key, o.store.Identity(), value); return err })
					case "duplicate-node":
						return []vaultstore.Node{value, value}, nil
					case "large-page":
						return make([]vaultstore.Node, 129), nil
					}
					return []vaultstore.Node{value}, nil
				}
			}
			o.store = wrapped
			value, err := o.ReadCatalog(ctx, 8*1024*1024)
			if err == nil || len(value.Nodes) != 0 || len(value.Credentials) != 0 || len(value.Tunnels) != 0 {
				t.Fatal("invalid catalog escaped", mode, err)
			}
			delete(o.nodeFloors, n.ID)
			o.store = base
		})
	}
	for _, maximum := range []int{0, 1023, 8*1024*1024 + 1} {
		if _, err := o.ReadCatalog(ctx, maximum); err != vault.ErrFormat {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadCatalog(cancelled, 1024); err != context.Canceled {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadCatalog(ctx, 1024); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestCatalogReferenceGraph(t *testing.T) {
	root, child := nodeDraft(), nodeDraft()
	root.Kind = 0
	child.ParentID = &root.ID
	base := Catalog{Nodes: []vaultstore.Node{{NodeMetadata: root}, {NodeMetadata: child}}}
	if err := validateCatalogReferences(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"parent", "parent-kind", "cycle", "credential", "gateway", "tunnel"} {
		value := Catalog{Nodes: append([]vaultstore.Node{}, base.Nodes...)}
		missing := uuid.NewString()
		switch mode {
		case "parent":
			value.Nodes[1].ParentID = &missing
		case "parent-kind":
			value.Nodes[0].Kind = 1
		case "cycle":
			value.Nodes[0].ParentID = &child.ID
			value.Nodes[1].Kind = 0
		case "credential":
			value.Nodes[1].CredentialID = &missing
		case "gateway":
			value.Nodes[1].RDPGatewayCredentialID = &missing
		case "tunnel":
			value.Nodes[1].TunnelConfigID = &missing
		}
		if err := validateCatalogReferences(context.Background(), value); err != vault.ErrAuthentication {
			t.Fatal("invalid graph", mode, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateCatalogReferences(ctx, base); err != context.Canceled {
		t.Fatal(err)
	}
}
