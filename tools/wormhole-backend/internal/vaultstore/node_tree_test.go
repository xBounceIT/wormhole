package vaultstore

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func treeFixture(t *testing.T, s *SQLite) []Node {
	t.Helper()
	values := []Node{node(s), node(s), node(s), node(s)}
	values[1].ParentID = &values[0].ID
	values[2].ParentID = &values[1].ID
	values[2].Kind = 1
	values[3].ParentID = &values[0].ID
	for _, n := range values {
		if err := s.WriteNode(context.Background(), n, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	return values
}

func treeTombstone(n Node, _ SecretReader) (Node, []Secret, error) {
	n.RowVersion++
	n.Deleted = true
	return n, nil, nil
}

func treeSequence(t *testing.T, s *SQLite) uint64 {
	t.Helper()
	var seq uint64
	if err := s.db.QueryRowContext(context.Background(), `SELECT ChangeSeq FROM WorkspaceMeta;`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	return seq
}

func assertTreeUnchanged(t *testing.T, s *SQLite, nodes []Node, seq uint64) {
	t.Helper()
	for _, n := range nodes {
		got, err := s.ReadNode(context.Background(), n.ID)
		if err != nil || !reflect.DeepEqual(got, n) {
			t.Fatal("partial tree mutation", err)
		}
	}
	if treeSequence(t, s) != seq {
		t.Fatal("partial sequence change")
	}
}

func TestNodeTreeAtomicPostorderAndScope(t *testing.T) {
	s, _ := database(t)
	nodes := treeFixture(t, s)
	outside := node(s)
	ctx := context.Background()
	if err := s.WriteNode(ctx, outside, nil, 0); err != nil {
		t.Fatal(err)
	}
	seq := treeSequence(t, s)
	seen := map[string]bool{}
	count, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, func(n Node, read SecretReader) (Node, []Secret, error) {
		for _, child := range nodes {
			if child.ParentID != nil && *child.ParentID == n.ID && !seen[child.ID] {
				t.Fatal("parent prepared before child")
			}
		}
		seen[n.ID] = true
		for _, ref := range []SecretRef{{"credential", n.ID, "password"}, {"node", outside.ID, "notes"}, {"node", n.ID, "password"}} {
			if _, err := read(ctx, ref); err != ErrFormat {
				t.Fatal("transaction reader escaped node", err)
			}
		}
		if _, err := read(ctx, SecretRef{"node", n.ID, "notes"}); err != ErrMissing {
			t.Fatal(err)
		}
		return treeTombstone(n, read)
	})
	if err != nil || count != 4 || treeSequence(t, s) != seq+1 {
		t.Fatal(count, err)
	}
	for _, n := range nodes {
		got, err := s.ReadNode(ctx, n.ID)
		if err != nil || !got.Deleted || got.RowVersion != 2 {
			t.Fatal(err)
		}
	}
	if got, err := s.ReadNode(ctx, outside.ID); err != nil || !reflect.DeepEqual(got, outside) {
		t.Fatal("escaped subtree", err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 2, treeTombstone); err != ErrConflict {
		t.Fatal("repeated delete", err)
	}
}

func TestNodeTreeRollbackOnLateCallbackAndWriteFailure(t *testing.T) {
	for _, failure := range []string{"callback", "cancel", "wrong-id", "not-deleted", "stale", "abort", "ignore", "sequence"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := database(t)
			nodes := treeFixture(t, s)
			seq := treeSequence(t, s)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "abort" || failure == "ignore" {
				action := "ABORT, 'forced'"
				if failure == "ignore" {
					action = "IGNORE"
				}
				if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_tree BEFORE UPDATE ON Nodes WHEN OLD.Id='`+nodes[0].ID+`' BEGIN SELECT RAISE(`+action+`); END;`); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "sequence" {
				if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_seq BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE(IGNORE); END;`); err != nil {
					t.Fatal(err)
				}
			}
			visited := 0
			count, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, func(n Node, read SecretReader) (Node, []Secret, error) {
				visited++
				n, values, err := treeTombstone(n, read)
				if n.ID == nodes[0].ID {
					if visited != 4 {
						t.Fatal("failure did not follow child writes")
					}
					switch failure {
					case "callback":
						return Node{}, nil, errors.New("rejected")
					case "cancel":
						cancel()
					case "wrong-id":
						n.ID = uuid.NewString()
					case "not-deleted":
						n.Deleted = false
					case "stale":
						n.RowVersion++
					}
				}
				return n, values, err
			})
			if err == nil || count != 0 {
				t.Fatal("partial delete reported success", count, err)
			}
			assertTreeUnchanged(t, s, nodes, seq)
		})
	}
}

func TestNodeTreeInputsAndDamagedGraph(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	nodes := treeFixture(t, s)
	for _, input := range []struct {
		id       string
		revision uint64
		prepare  NodeDeletion
	}{{"bad", 1, treeTombstone}, {nodes[0].ID, 0, treeTombstone}, {nodes[0].ID, math.MaxInt64, treeTombstone}, {nodes[0].ID, 1, nil}} {
		if _, err := s.DeleteNodeTree(ctx, input.id, input.revision, input.prepare); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteNodeTree(ctx, uuid.NewString(), 1, treeTombstone); err != ErrMissing {
		t.Fatal(err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 2, treeTombstone); err != ErrConflict {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE Nodes SET ParentId=? WHERE Id=?;`, nodes[1].ID, nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, treeTombstone); err != ErrConflict {
		t.Fatal("cycle", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE Nodes SET ParentId=NULL,Kind=1 WHERE Id=?;`, nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, treeTombstone); err != ErrConflict {
		t.Fatal("connection parent", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE Nodes SET Kind=0 WHERE Id=?; UPDATE Nodes SET Notes=X'01' WHERE Id=?;`, nodes[0].ID, nodes[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, treeTombstone); err != ErrFormat {
		t.Fatal("corrupt child", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNodeTree(ctx, nodes[0].ID, 1, treeTombstone); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestNodeTreeInsertRaceNeverLeavesOrphan(t *testing.T) {
	ctx := context.Background()
	s, _ := database(t)
	nodes := treeFixture(t, s)
	child := node(s)
	child.ParentID = &nodes[0].ID
	var wg sync.WaitGroup
	wg.Add(2)
	var deleteErr, insertErr error
	var count uint64
	go func() { defer wg.Done(); count, deleteErr = s.DeleteNodeTree(ctx, nodes[0].ID, 1, treeTombstone) }()
	go func() { defer wg.Done(); insertErr = s.WriteNode(ctx, child, nil, 0) }()
	wg.Wait()
	if deleteErr != nil {
		t.Fatal(deleteErr)
	}
	if insertErr == nil {
		got, err := s.ReadNode(ctx, child.ID)
		if err != nil || !got.Deleted || count != 5 {
			t.Fatal("concurrent child escaped", err, count)
		}
	} else if insertErr != ErrConflict || count != 4 {
		t.Fatal(insertErr, count)
	}
}

func TestNodeTreeDepthBoundary(t *testing.T) {
	s, _ := database(t)
	ctx := context.Background()
	chain := make([]Node, MaxNodeDepth+1)
	// Build a deliberately too-deep database directly; the public write API
	// rejects it. The tree walker must independently reject damaged input.
	for i := range chain {
		chain[i] = node(s)
		if i > 0 {
			chain[i].ParentID = &chain[i-1].ID
		}
		n := chain[i]
		manifest, _ := json.Marshal(n.Fields)
		args := append(nodeMetadataTargets(&n), n.CreatedAt, n.UpdatedAt, n.RowVersion, n.Deleted, manifest, n.SealSuite, n.SealSignerKeyID, n.SealSignerKeyVersion, n.SealCapabilityID, n.Seal)
		if _, err := s.db.ExecContext(ctx, writeNodeSQL, args...); err != nil {
			t.Fatal(err)
		}
	}
	seq := treeSequence(t, s)
	if count, err := s.DeleteNodeTree(ctx, chain[0].ID, 1, treeTombstone); count != 0 || err != ErrConflict {
		t.Fatal("accepted depth overflow", count, err)
	}
	assertTreeUnchanged(t, s, chain, seq)
	if _, err := s.db.ExecContext(ctx, `UPDATE Nodes SET ParentId=NULL WHERE Id=?;`, chain[MaxNodeDepth].ID); err != nil {
		t.Fatal(err)
	}
	if count, err := s.DeleteNodeTree(ctx, chain[0].ID, 1, treeTombstone); err != nil || count != MaxNodeDepth {
		t.Fatal("rejected valid depth", count, err)
	}
	if remaining, err := s.ReadNode(ctx, chain[MaxNodeDepth].ID); err != nil || remaining.Deleted {
		t.Fatal("deleted detached node", err)
	}
}
