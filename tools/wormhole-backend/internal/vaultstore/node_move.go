package vaultstore

import (
	"context"
	"math"
	"sort"
)

type NodeMoveRequest struct {
	Nodes     []NodeRevision
	Target    NodeRevision
	Placement string
}

// NodeMoveStore borrows callbacks synchronously within its transaction. They
// must not reenter the store, retain inputs, or publish external side effects.
// verify authenticates every live node before planning; seal signs each updated
// placement with a new revision without changing its field manifest.
type NodeMoveStore interface {
	NodeStore
	MoveNodes(context.Context, NodeMoveRequest, func(Node) error, func(Node) (Node, error)) (uint64, error)
}

// planNodeMove works only on an authenticated, live snapshot. It preserves the
// visible tree order and rejects overlapping selections, as the legacy move does.
func planNodeMove(ctx context.Context, nodes []Node, q NodeMoveRequest) ([]Node, error) {
	if len(q.Nodes) == 0 || len(q.Nodes) > 1000 || (q.Placement != "inside" && q.Placement != "before" && q.Placement != "after") {
		return nil, ErrFormat
	}
	byID := make(map[string]Node, len(nodes))
	children := make(map[string][]string)
	parentID := func(n Node) string {
		if n.ParentID == nil {
			return ""
		}
		return *n.ParentID
	}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	selected := make(map[string]bool, len(q.Nodes))
	for _, r := range append(append([]NodeRevision{}, q.Nodes...), q.Target) {
		if !validID(r.ID) || r.RowVersion == 0 || r.RowVersion >= math.MaxInt64 || selected[r.ID] {
			return nil, ErrFormat
		}
		n, ok := byID[r.ID]
		if !ok || n.Deleted || n.RowVersion != r.RowVersion {
			return nil, ErrConflict
		}
		selected[r.ID] = true
	}
	delete(selected, q.Target.ID)
	target := byID[q.Target.ID]
	destination := parentID(target)
	if q.Placement == "inside" {
		if target.Kind != 0 {
			return nil, ErrConflict
		}
		destination = target.ID
	}
	// Check all original ancestry, including descendants: reparenting cannot hide
	// a corrupt cycle or push a previously valid subtree beyond the depth bound.
	for _, n := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		seen := map[string]bool{n.ID: true}
		for p := parentID(n); p != ""; {
			a, ok := byID[p]
			if !ok || a.Kind != 0 || seen[p] || len(seen) >= MaxNodeDepth || (selected[n.ID] && selected[p]) {
				return nil, ErrConflict
			}
			seen[p] = true
			p = parentID(a)
		}
	}
	for p := destination; p != ""; p = parentID(byID[p]) {
		if selected[p] {
			return nil, ErrConflict
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if a.SortOrder != b.SortOrder {
			return a.SortOrder < b.SortOrder
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	siblings := []string{}
	for _, n := range nodes {
		p := parentID(n)
		children[p] = append(children[p], n.ID)
		if p == destination && !selected[n.ID] {
			siblings = append(siblings, n.ID)
		}
	}
	moved := []string{}
	var visit func(string)
	visit = func(parent string) {
		for _, id := range children[parent] {
			if selected[id] {
				moved = append(moved, id)
			} else {
				visit(id)
			}
		}
	}
	visit("")
	index := len(siblings)
	if q.Placement != "inside" {
		for i, id := range siblings {
			if id == target.ID {
				index = i
				if q.Placement == "after" {
					index++
				}
				break
			}
		}
	}
	ordered := append(append(append([]string{}, siblings[:index]...), moved...), siblings[index:]...)
	changes := []Node{}
	for i, id := range ordered {
		n := byID[id]
		if parentID(n) == destination && n.SortOrder == int64(i) {
			continue
		}
		if n.RowVersion >= math.MaxInt64 {
			return nil, ErrConflict
		}
		n.ParentID = nil
		if destination != "" {
			p := destination
			n.ParentID = &p
		}
		n.SortOrder = int64(i)
		byID[id] = n
		changes = append(changes, n)
	}
	for _, n := range nodes {
		depth := 1
		for p := parentID(byID[n.ID]); p != ""; p = parentID(byID[p]) {
			depth++
			if depth > MaxNodeDepth {
				return nil, ErrConflict
			}
		}
	}
	return changes, nil
}

// MoveNodes reads, authenticates, plans and writes within one transaction. No
// plaintext fields are loaded; changing placement preserves encrypted field IDs.
func (s *SQLite) MoveNodes(ctx context.Context, q NodeMoveRequest, verify func(Node) error, seal func(Node) (Node, error)) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if verify == nil || seal == nil {
		return 0, ErrFormat
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, storeError(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+nodeColumns+` FROM Nodes WHERE Deleted=0 LIMIT 50001;`)
	if err != nil {
		return 0, storeError(err)
	}
	defer rows.Close()
	nodes := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return 0, err
		}
		if err := verify(n); err != nil {
			return 0, err
		}
		nodes = append(nodes, n)
		if len(nodes) > 50000 {
			return 0, ErrFormat
		}
	}
	if err := rows.Err(); err != nil {
		return 0, storeError(err)
	}
	if err := rows.Close(); err != nil {
		return 0, storeError(err)
	}
	changes, err := planNodeMove(ctx, nodes, q)
	if err != nil {
		return 0, err
	}
	for _, n := range changes {
		value, err := seal(n)
		if err != nil {
			return 0, err
		}
		if value.ID != n.ID {
			return 0, ErrFormat
		}
		if err := s.writeNode(ctx, tx, value, nil, n.RowVersion); err != nil {
			return 0, err
		}
	}
	if len(changes) != 0 {
		// A folder's descendants may inherit a different protocol after moving.
		// Check their resulting references before committing any sibling reorder.
		children := make(map[string][]Node)
		for _, n := range nodes {
			if n.ParentID != nil {
				children[*n.ParentID] = append(children[*n.ParentID], n)
			}
		}
		stack := []Node{}
		for _, root := range q.Nodes {
			stack = append(stack, children[root.ID]...)
		}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if err := validateNodeReferences(ctx, tx, n, n); err != nil {
				return 0, err
			}
			stack = append(stack, children[n.ID]...)
		}
		if err := commitChange(ctx, tx); err != nil {
			return 0, err
		}
	}
	return uint64(len(changes)), nil
}
