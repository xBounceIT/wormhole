package localvault

import (
	"context"
	"errors"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestNodeTreesOwnerAuthenticatesAndRetiresUnion(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := ownerTree(t, o), ownerTree(t, o)
	ctx := context.Background()
	targets := []vaultstore.NodeRevision{{ID: a[0].ID, RowVersion: 1}, {ID: a[1].ID, RowVersion: 1}, {ID: b[0].ID, RowVersion: 1}}
	if count, err := o.DeleteNodeTrees(ctx, targets); err != nil || count != 4 {
		t.Fatal(count, err)
	}
	for _, n := range append(a, b...) {
		stored, err := o.store.(vaultstore.NodeStore).ReadNode(ctx, n.ID)
		if err != nil || !stored.Deleted || o.verifyNode(stored) != nil {
			t.Fatal(err)
		}
		for _, f := range stored.Fields {
			if f.Present {
				t.Fatal("live field survived deletion")
			}
		}
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.DeleteNodeTrees(ctx, targets); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

type corruptTrees struct {
	vaultstore.NodeTreesStore
	id string
}

func (s corruptTrees) DeleteNodeTrees(ctx context.Context, targets []vaultstore.NodeRevision, prepare vaultstore.NodeDeletion) (uint64, error) {
	return s.NodeTreesStore.DeleteNodeTrees(ctx, targets, func(n vaultstore.Node, read vaultstore.SecretReader) (vaultstore.Node, []vaultstore.Secret, error) {
		if n.ID == s.id {
			n.Seal = append([]byte(nil), n.Seal...)
			n.Seal[0] ^= 1
		}
		return prepare(n, read)
	})
}

func TestNodeTreesOwnerRollsBackEarlierRootOnLateSealFailure(t *testing.T) {
	o, _, _, _ := owner(t)
	a, b := ownerTree(t, o), ownerTree(t, o)
	original := o.store
	o.store = corruptTrees{original.(vaultstore.NodeTreesStore), b[0].ID}
	count, err := o.DeleteNodeTrees(context.Background(), []vaultstore.NodeRevision{{ID: a[0].ID, RowVersion: 1}, {ID: b[0].ID, RowVersion: 1}})
	o.store = original
	if count != 0 || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal(count, err)
	}
	for _, n := range append(a, b...) {
		got, err := o.ReadNode(context.Background(), n.ID, 1)
		if err != nil || got.RowVersion != 1 {
			t.Fatal("partial deletion", err)
		}
		if err := o.WithNodeField(context.Background(), n.ID, "notes", 1, func(value []byte) error {
			if len(value) == 0 {
				t.Fatal("earlier secret erased")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNodeTreesOwnerRejectsStoreWithoutAtomicSupport(t *testing.T) {
	o, _, _, _ := owner(t)
	original := o.store
	o.store = struct{ vaultstore.NodeStore }{original.(vaultstore.NodeStore)}
	defer func() { o.store = original }()
	if _, err := o.DeleteNodeTrees(context.Background(), nil); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
}
