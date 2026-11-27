package localvault

import (
	"context"
	"math"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// DeleteNodeTree removes the root and every live descendant atomically. As with
// other owner writes, the caller must authorize the entire affected tree first.
func (o *Owner) DeleteNodeTree(ctx context.Context, id string, expected uint64) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return 0, err
	}
	tree, ok := s.(vaultstore.NodeTreeStore)
	if !ok {
		return 0, vaultstore.ErrStorage
	}
	return tree.DeleteNodeTree(ctx, id, expected, o.prepareNodeDeletion(ctx, s))
}

func (o *Owner) DeleteNodeTrees(ctx context.Context, targets []vaultstore.NodeRevision) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return 0, err
	}
	trees, ok := s.(vaultstore.NodeTreesStore)
	if !ok {
		return 0, vaultstore.ErrStorage
	}
	return trees.DeleteNodeTrees(ctx, targets, o.prepareNodeDeletion(ctx, s))
}

func (o *Owner) prepareNodeDeletion(ctx context.Context, s vaultstore.NodeStore) vaultstore.NodeDeletion {
	return func(old vaultstore.Node, read vaultstore.SecretReader) (vaultstore.Node, []vaultstore.Secret, error) {
		if err := o.verifyNode(old); err != nil {
			return vaultstore.Node{}, nil, err
		}
		if old.Deleted || old.RowVersion >= math.MaxInt64 {
			return vaultstore.Node{}, nil, vaultstore.ErrConflict
		}
		n := old
		n.Fields = append([]vaultstore.SecretField{}, old.Fields...)
		n.Deleted = true
		n.RowVersion++
		n.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		var secrets []vaultstore.Secret
		for i, f := range n.Fields {
			if !f.Present {
				continue
			}
			secret, err := o.prepareSecretWithReader(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: n.ID, Field: f.Field}, nil, f.Version, read)
			if err != nil {
				return vaultstore.Node{}, nil, err
			}
			secrets = append(secrets, secret)
			n.Fields[i].Present = false
			n.Fields[i].Version++
		}
		err := o.root.With(func(key []byte) error { var err error; n.Seal, err = nodeMAC(key, s.Identity(), n); return err })
		return n, secrets, err
	}
}
