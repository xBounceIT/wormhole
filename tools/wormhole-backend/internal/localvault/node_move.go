package localvault

import (
	"context"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"time"
)

func (o *Owner) MoveNodes(ctx context.Context, q vaultstore.NodeMoveRequest) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, err := o.nodeStore()
	if err != nil {
		return 0, err
	}
	moves, ok := s.(vaultstore.NodeMoveStore)
	if !ok {
		return 0, vaultstore.ErrStorage
	}
	pending := make(map[string]uint64)
	count, err := moves.MoveNodes(ctx, q, func(n vaultstore.Node) error {
		if err := o.verifyNode(n); err != nil {
			return err
		}
		if n.RowVersion < o.nodeFloors[n.ID] {
			return vault.ErrRollback
		}
		pending[n.ID] = n.RowVersion
		return nil
	}, func(n vaultstore.Node) (vaultstore.Node, error) {
		n.RowVersion++
		pending[n.ID] = n.RowVersion
		n.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		err := o.root.With(func(key []byte) error { var err error; n.Seal, err = nodeMAC(key, s.Identity(), n); return err })
		return n, err
	})
	if err != nil {
		return 0, err
	}
	// Publish observed revisions only after the complete transaction committed.
	for id, revision := range pending {
		o.nodeFloors[id] = revision
	}
	return count, nil
}
