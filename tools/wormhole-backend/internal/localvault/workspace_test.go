package localvault

import (
	"context"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

type workspaceTestStore struct {
	catalogStore
	readNode   func(context.Context, string) (vaultstore.Node, error)
	readSecret func(context.Context, vaultstore.SecretRef) (vaultstore.Secret, error)
}

func TestWorkspaceBoundsInheritedDisplayExpansion(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	parent := nodeDraft()
	parent.Kind = 0
	parent.Host = nodePtr(strings.Repeat("h", 16384))
	if _, err := o.PutNode(ctx, parent, nil, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		n := nodeDraft()
		n.ParentID = &parent.ID
		n.Host = nil
		if _, err := o.PutNode(ctx, n, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if catalog, err := o.ReadCatalog(ctx, 1024*1024); err != nil || len(catalog.Nodes) != 101 {
		t.Fatal("fixture exceeds catalog budget", err)
	}
	if view, err := o.ReadWorkspace(ctx, 1024*1024); err != vault.ErrFormat || len(view.Resolutions) != 0 || len(view.Catalog.Nodes) != 0 {
		t.Fatal("inherited expansion escaped budget", err)
	}
}

func (s workspaceTestStore) ReadNode(ctx context.Context, id string) (vaultstore.Node, error) {
	if s.readNode != nil {
		return s.readNode(ctx, id)
	}
	return s.catalogStore.ReadNode(ctx, id)
}
func (s workspaceTestStore) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	if s.readSecret != nil {
		return s.readSecret(ctx, ref)
	}
	return s.catalogStore.ReadSecret(ctx, ref)
}

func TestWorkspaceAuthenticatedResolutionAndIncompleteTargets(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, parent, c, _ := resolutionFixture(t, o)
	// Pin an identity different from current metadata, exactly as a legacy import does.
	meta := n.NodeMetadata
	meta.Protocol = nodePtr(0)
	n, err := o.PutNode(ctx, meta, nil, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"ssh": {SourceKind: "saved", CredentialID: c.ID, Username: "retained-user"}})
	incomplete := nodeDraft()
	incomplete.Host = nodePtr("")
	if _, err := o.PutNode(ctx, incomplete, nil, 0); err != nil {
		t.Fatal(err)
	}
	base := o.store.(catalogStore)
	secretReads := 0
	o.store = workspaceTestStore{catalogStore: base, readSecret: func(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
		if ref.Field != vaultstore.NodeResolverMigrationField {
			t.Fatal("workspace read a connection secret", ref.Field)
		}
		secretReads++
		return base.ReadSecret(ctx, ref)
	}}
	view, err := o.ReadWorkspace(ctx, 8*1024*1024)
	if err != nil || len(view.Catalog.Nodes) != 3 || len(view.Resolutions) != 1 {
		t.Fatal("incomplete snapshot", err)
	}
	r := view.Resolutions[n.ID]
	if r.Host != *parent.Host || r.Username != "retained-user" || secretReads != 1 {
		t.Fatal("resolution pin lost")
	}
	if _, ok := view.Resolutions[incomplete.ID]; ok {
		t.Fatal("incomplete target resolved")
	}
}

func TestWorkspaceFailsAtomicallyOnTamperingCancellationAndClosure(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, _, _, _ := resolutionFixture(t, o)
	base := o.store.(catalogStore)
	o.store = workspaceTestStore{catalogStore: base, readNode: func(ctx context.Context, id string) (vaultstore.Node, error) {
		if o.mu.TryLock() {
			o.mu.Unlock()
			t.Fatal("snapshot released owner before resolution")
		}
		value, err := base.ReadNode(ctx, id)
		if id == n.ID {
			value.Host = nodePtr("tampered.example")
		}
		return value, err
	}}
	view, err := o.ReadWorkspace(ctx, 8*1024*1024)
	if err != vault.ErrAuthentication || len(view.Catalog.Nodes) != 0 || len(view.Resolutions) != 0 {
		t.Fatal("partial or unauthenticated snapshot", err)
	}
	o.store = base
	if _, err := o.ReadWorkspace(ctx, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadWorkspace(canceled, 1024); err != context.Canceled {
		t.Fatal(err)
	}
	canceled, cancel = context.WithCancel(ctx)
	o.store = catalogTestStore{catalogStore: base, tunnels: func(ctx context.Context, after string, limit int) ([]vaultstore.Tunnel, error) {
		values, err := base.ListTunnels(ctx, after, limit)
		cancel()
		return values, err
	}}
	if view, err := o.ReadWorkspace(canceled, 8*1024*1024); err != context.Canceled || len(view.Catalog.Nodes) != 0 {
		t.Fatal(err)
	}
	o.store = base
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadWorkspace(ctx, 1024); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}
