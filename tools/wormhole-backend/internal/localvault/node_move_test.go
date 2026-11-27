package localvault

import (
	"context"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"reflect"
	"testing"
)

func TestOwnerMovePreservesCiphertextAndAuthentication(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := ownerTree(t, o), ownerTree(t, o)
	ctx := context.Background()
	ref := vaultstore.SecretRef{OwnerKind: "node", OwnerID: a[1].ID, Field: "inlinePassword"}
	before, err := o.store.ReadSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	q := vaultstore.NodeMoveRequest{Nodes: []vaultstore.NodeRevision{{ID: a[0].ID, RowVersion: 1}}, Target: vaultstore.NodeRevision{ID: b[0].ID, RowVersion: 1}, Placement: "inside"}
	if count, err := o.MoveNodes(ctx, q); err != nil || count == 0 {
		t.Fatal(count, err)
	}
	got, err := o.ReadNode(ctx, a[0].ID, 2)
	if err != nil || got.ParentID == nil || *got.ParentID != b[0].ID {
		t.Fatal(err)
	}
	after, err := o.store.ReadSecret(ctx, ref)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("ciphertext changed", err)
	}
	if err := o.WithNodeField(ctx, a[1].ID, "inlinePassword", 1, func(value []byte) error {
		if string(value) != "leaf private password" {
			t.Fatal("lost password")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	original := o.store
	o.store = struct{ vaultstore.NodeStore }{original.(vaultstore.NodeStore)}
	if _, err := o.MoveNodes(ctx, q); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = original
	o.Close()
	if _, err := o.MoveNodes(ctx, q); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

type corruptMove struct{ vaultstore.NodeMoveStore }

func (s corruptMove) MoveNodes(ctx context.Context, q vaultstore.NodeMoveRequest, verify func(vaultstore.Node) error, seal func(vaultstore.Node) (vaultstore.Node, error)) (uint64, error) {
	return s.NodeMoveStore.MoveNodes(ctx, q, func(n vaultstore.Node) error { n.Name = "altered"; return verify(n) }, seal)
}
func TestOwnerMoveRejectsTampering(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := ownerTree(t, o), ownerTree(t, o)
	original := o.store
	o.store = corruptMove{original.(vaultstore.NodeMoveStore)}
	_, err := o.MoveNodes(context.Background(), vaultstore.NodeMoveRequest{Nodes: []vaultstore.NodeRevision{{ID: a[0].ID, RowVersion: 1}}, Target: vaultstore.NodeRevision{ID: b[0].ID, RowVersion: 1}, Placement: "inside"})
	o.store = original
	if err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if got, err := o.ReadNode(context.Background(), a[0].ID, 1); err != nil || got.RowVersion != 1 || got.ParentID != nil {
		t.Fatal(err)
	}
}

type failingMove struct{ vaultstore.NodeMoveStore }

func (s failingMove) MoveNodes(ctx context.Context, q vaultstore.NodeMoveRequest, verify func(vaultstore.Node) error, seal func(vaultstore.Node) (vaultstore.Node, error)) (uint64, error) {
	return s.NodeMoveStore.MoveNodes(ctx, q, verify, func(n vaultstore.Node) (vaultstore.Node, error) {
		if _, err := seal(n); err != nil {
			return vaultstore.Node{}, err
		}
		return vaultstore.Node{}, vaultstore.ErrConflict
	})
}
func TestOwnerMoveHonorsObservedRevisionsAndPublishesOnlyOnCommit(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := ownerTree(t, o), ownerTree(t, o)
	ctx := context.Background()
	q := vaultstore.NodeMoveRequest{Nodes: []vaultstore.NodeRevision{{ID: a[0].ID, RowVersion: 1}}, Target: vaultstore.NodeRevision{ID: b[0].ID, RowVersion: 1}, Placement: "inside"}
	o.nodeFloors[a[0].ID] = 2
	if _, err := o.MoveNodes(ctx, q); err != vault.ErrRollback {
		t.Fatal("replayed signed metadata accepted", err)
	}
	o.nodeFloors[a[0].ID] = 1
	original := o.store
	o.store = failingMove{original.(vaultstore.NodeMoveStore)}
	if _, err := o.MoveNodes(ctx, q); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	o.store = original
	if o.nodeFloors[a[0].ID] != 1 {
		t.Fatal("failed transaction advanced floor")
	}
	if _, err := o.MoveNodes(ctx, q); err != nil {
		t.Fatal(err)
	}
	if o.nodeFloors[a[0].ID] != 2 || o.nodeFloors[b[0].ID] != 1 {
		t.Fatal("committed placement or observed target revision not remembered")
	}
}

func TestNodeWriteCannotBypassMoveRevisionFloor(t *testing.T) {
	o, _, _, _ := owner(t)
	nodes := ownerTree(t, o)
	ctx := context.Background()
	n := nodes[0]
	o.nodeFloors[n.ID] = 2
	if _, err := o.PutNode(ctx, n.NodeMetadata, nil, 1); err != vault.ErrRollback {
		t.Fatal("edit bypassed observed floor", err)
	}
	if err := o.DeleteNode(ctx, n.ID, 1); err != vault.ErrRollback {
		t.Fatal("delete bypassed observed floor", err)
	}
	o.nodeFloors[n.ID] = 1
	got, err := o.PutNode(ctx, n.NodeMetadata, nil, 1)
	if err != nil || o.nodeFloors[n.ID] != got.RowVersion {
		t.Fatal("edit did not publish committed revision", err)
	}
	if _, err := o.PutNode(ctx, n.NodeMetadata, nil, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if o.nodeFloors[n.ID] != got.RowVersion {
		t.Fatal("stale edit changed floor")
	}
}
