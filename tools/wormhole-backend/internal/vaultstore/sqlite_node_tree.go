package vaultstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
)

var _ NodeTreeStore = (*SQLite)(nil)

// DeleteNodeTree visits descendants in postorder using an O(depth) stack and
// indexed child lookups. It holds one transaction for the complete tree; no size
// cap or partial commits are needed, and cancellation rolls everything back.
func (s *SQLite) DeleteNodeTree(ctx context.Context, id string, expected uint64, prepare NodeDeletion) (uint64, error) {
	return s.DeleteNodeTrees(ctx, []NodeRevision{{ID: id, RowVersion: expected}}, prepare)
}

// DeleteNodeTrees validates every selected root before any write, then removes
// their union in one transaction. Overlapping selections are deleted only once.
func (s *SQLite) DeleteNodeTrees(ctx context.Context, targets []NodeRevision, prepare NodeDeletion) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if len(targets) == 0 || len(targets) > MaxNodeDeleteRoots || prepare == nil {
		return 0, ErrFormat
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		if !validID(target.ID) || target.RowVersion == 0 || target.RowVersion >= math.MaxInt64 || seen[target.ID] {
			return 0, ErrFormat
		}
		seen[target.ID] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, storeError(err)
	}
	defer tx.Rollback()
	for _, target := range targets {
		root, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Id=?;`, target.ID))
		if err != nil {
			return 0, err
		}
		if root.Deleted || root.RowVersion != target.RowVersion {
			return 0, ErrConflict
		}
	}
	var total uint64
	for _, target := range targets {
		root, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Id=?;`, target.ID))
		if err != nil {
			return 0, err
		}
		// A previously visited selected ancestor already removed this root.
		if root.Deleted {
			continue
		}
		count, err := s.deleteNodeTree(ctx, tx, root, prepare)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if err := commitChange(ctx, tx); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *SQLite) deleteNodeTree(ctx context.Context, tx *sql.Tx, root Node, prepare NodeDeletion) (uint64, error) {
	stack := []Node{root}
	active := map[string]bool{root.ID: true}
	var count uint64
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := stack[len(stack)-1]
		child, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE ParentId=? AND Deleted=0 LIMIT 1;`, n.ID))
		if err == nil {
			if n.Kind != 0 || active[child.ID] || len(stack) >= MaxNodeDepth {
				return 0, ErrConflict
			}
			active[child.ID] = true
			stack = append(stack, child)
			continue
		}
		if !errors.Is(err, ErrMissing) {
			return 0, err
		}
		read := func(ctx context.Context, ref SecretRef) (Secret, error) {
			if ref.OwnerKind != "node" || ref.OwnerID != n.ID || !NodeSecretField(ref.Field) {
				return Secret{}, ErrFormat
			}
			return s.readSecret(ctx, tx, ref)
		}
		value, secrets, err := prepare(n, read)
		if err != nil {
			return 0, err
		}
		if value.ID != n.ID || !value.Deleted {
			return 0, ErrFormat
		}
		if err := s.writeNode(ctx, tx, value, secrets, n.RowVersion); err != nil {
			return 0, err
		}
		count++
		delete(active, n.ID)
		stack = stack[:len(stack)-1]
	}
	return count, nil
}
