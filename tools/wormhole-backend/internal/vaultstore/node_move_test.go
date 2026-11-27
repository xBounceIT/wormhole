package vaultstore

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"math"
	"reflect"
	"testing"
)

func moveSeal(n Node) (Node, error) { n.RowVersion++; return n, nil }
func moveVerify(Node) error         { return nil }
func TestMoveNodesAtomicOrdering(t *testing.T) {
	for _, placement := range []string{"inside", "before", "after"} {
		t.Run(placement, func(t *testing.T) {
			s, _ := database(t)
			a, b := treeFixture(t, s), treeFixture(t, s)
			ctx := context.Background()
			seq := treeSequence(t, s)
			q := NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b[1].ID, 1}, placement}
			count, err := s.MoveNodes(ctx, q, moveVerify, moveSeal)
			if err != nil || count == 0 || treeSequence(t, s) != seq+1 {
				t.Fatal(count, err)
			}
			got, err := s.ReadNode(ctx, a[1].ID)
			want := b[0].ID
			if placement == "inside" {
				want = b[1].ID
			}
			if err != nil || got.ParentID == nil || *got.ParentID != want || got.RowVersion != 2 {
				t.Fatal(got, err)
			}
			leaf, err := s.ReadNode(ctx, a[2].ID)
			if err != nil || !reflect.DeepEqual(leaf, a[2]) {
				t.Fatal("descendant changed", err)
			}
			dest, err := s.ReadNode(ctx, b[1].ID)
			if err != nil {
				t.Fatal(err)
			}
			if placement == "before" && got.SortOrder >= dest.SortOrder || placement == "after" && got.SortOrder <= dest.SortOrder {
				t.Fatal("wrong placement")
			}
			if _, err = s.MoveNodes(ctx, q, moveVerify, moveSeal); err != ErrConflict {
				t.Fatal("stale move", err)
			}
		})
	}
}
func TestMoveNodesFailureRollsBack(t *testing.T) {
	for _, mode := range []string{"authenticate", "seal", "wrong-id", "write", "commit", "cancel", "inheritance"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := database(t)
			a, b := treeFixture(t, s), treeFixture(t, s)
			ctx := context.Background()
			if mode == "inheritance" {
				b[0].Protocol = ptr(5)
				b[0].RowVersion++
				if err := s.WriteNode(ctx, b[0], nil, 1); err != nil {
					t.Fatal(err)
				}
				a[2].TunnelEnabled = ptr(true)
				a[2].RowVersion++
				if err := s.WriteNode(ctx, a[2], nil, 1); err != nil {
					t.Fatal(err)
				}
			}
			seq := treeSequence(t, s)
			calls := 0
			verify := moveVerify
			seal := func(n Node) (Node, error) {
				calls++
				if mode == "seal" && calls == 2 {
					return Node{}, ErrAuthenticationFixture
				}
				if mode == "wrong-id" {
					n.ID = uuid.NewString()
				}
				return moveSeal(n)
			}
			if mode == "authenticate" {
				verify = func(Node) error { return ErrAuthenticationFixture }
			}
			if mode == "write" {
				if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_move BEFORE UPDATE ON Nodes WHEN NEW.RowVersion>OLD.RowVersion BEGIN SELECT RAISE(IGNORE); END;`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "commit" {
				if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_move BEFORE UPDATE ON WorkspaceMeta BEGIN SELECT RAISE(ABORT,'fixture'); END;`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			count, err := s.MoveNodes(ctx, NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b[1].ID, 1}, "before"}, verify, seal)
			if err == nil || count != 0 {
				t.Fatal(count, err)
			}
			assertTreeUnchanged(t, s, append(a, b...), seq)
		})
	}
}
func TestMoveNodesPlannerBoundaries(t *testing.T) {
	s, _ := database(t)
	a := treeFixture(t, s)
	b := node(s)
	base := append(append([]Node{}, a...), b)
	good := NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b.ID, 1}, "inside"}
	for _, mode := range []string{"empty", "many", "placement", "id", "zero", "max", "duplicate", "self", "missing", "stale-target", "leaf-target", "overlap", "cycle", "bad-parent", "existing-cycle", "max-sibling", "too-deep"} {
		t.Run(mode, func(t *testing.T) {
			q := good
			q.Nodes = append([]NodeRevision{}, good.Nodes...)
			nodes := append([]Node{}, base...)
			switch mode {
			case "empty":
				q.Nodes = nil
			case "many":
				q.Nodes = make([]NodeRevision, 1001)
			case "placement":
				q.Placement = "bad"
			case "id":
				q.Nodes[0].ID = "bad"
			case "zero":
				q.Nodes[0].RowVersion = 0
			case "max":
				q.Nodes[0].RowVersion = math.MaxInt64
			case "duplicate":
				q.Nodes = append(q.Nodes, q.Nodes[0])
			case "self":
				q.Target = q.Nodes[0]
			case "missing":
				q.Target.ID = uuid.NewString()
			case "stale-target":
				q.Target.RowVersion++
			case "leaf-target":
				q.Target.ID = a[2].ID
			case "overlap":
				q.Nodes = append(q.Nodes, NodeRevision{a[0].ID, 1})
			case "cycle":
				q.Nodes[0].ID = a[0].ID
				q.Target.ID = a[1].ID
			case "bad-parent":
				nodes[0].ParentID = ptr(uuid.NewString())
			case "existing-cycle":
				nodes[0].ParentID = &a[1].ID
			case "max-sibling":
				nodes[3].ParentID = &b.ID
				nodes[3].SortOrder = 9
				nodes[3].RowVersion = math.MaxInt64
			case "too-deep":
				parent := b.ID
				for i := 0; i < MaxNodeDepth-2; i++ {
					n := node(s)
					n.ParentID = ptr(parent)
					nodes = append(nodes, n)
					parent = n.ID
				}
				q.Target = NodeRevision{parent, 1}
			}
			if _, err := planNodeMove(context.Background(), nodes, q); err == nil {
				t.Fatal("accepted", mode)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := planNodeMove(ctx, base, good); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, callbacks := range []bool{true, false} {
		var verify func(Node) error
		var seal func(Node) (Node, error)
		if callbacks {
			verify = moveVerify
		} else {
			seal = moveSeal
		}
		if _, err := s.MoveNodes(context.Background(), good, verify, seal); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MoveNodes(context.Background(), good, moveVerify, moveSeal); err != ErrClosed {
		t.Fatal(err)
	}
}
func TestMoveNodesNoopAndVisibleOrder(t *testing.T) {
	s, _ := database(t)
	a, b := treeFixture(t, s), treeFixture(t, s)
	ctx := context.Background()
	// Select roots in reverse request order: the earlier visible folder wins.
	a[0].SortOrder = 10
	a[0].RowVersion++
	b[0].SortOrder = 20
	b[0].RowVersion++
	for _, n := range []Node{a[0], b[0]} {
		if err := s.WriteNode(ctx, n, nil, 1); err != nil {
			t.Fatal(err)
		}
	}
	q := NodeMoveRequest{[]NodeRevision{{b[2].ID, 1}, {a[2].ID, 1}}, NodeRevision{a[3].ID, 1}, "inside"}
	count, err := s.MoveNodes(ctx, q, moveVerify, moveSeal)
	if err != nil || count != 2 {
		t.Fatal(count, err)
	}
	for i, id := range []string{a[2].ID, b[2].ID} {
		got, err := s.ReadNode(ctx, id)
		if err != nil || got.SortOrder != int64(i) || !sameOptionalID(got.ParentID, &a[3].ID) {
			t.Fatal("visible ordering", got, err)
		}
	}
	seq := treeSequence(t, s)
	q.Nodes = []NodeRevision{{b[2].ID, 2}}
	if count, err = s.MoveNodes(ctx, q, moveVerify, moveSeal); err != nil || count != 0 || treeSequence(t, s) != seq {
		t.Fatal("no-op", count, err)
	}
}

func TestMoveNodesConcurrentStaleIntent(t *testing.T) {
	s, _ := database(t)
	a, b := treeFixture(t, s), treeFixture(t, s)
	q := NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b[1].ID, 1}, "inside"}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := s.MoveNodes(context.Background(), q, moveVerify, moveSeal); results <- err }()
	}
	first, second := <-results, <-results
	if !((first == nil && second == ErrConflict) || (second == nil && first == ErrConflict)) {
		t.Fatal(first, second)
	}
}

func TestMoveNodesBackToRoot(t *testing.T) {
	s, _ := database(t)
	a, b := treeFixture(t, s), treeFixture(t, s)
	ctx := context.Background()
	q := NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b[0].ID, 1}, "after"}
	if _, err := s.MoveNodes(ctx, q, moveVerify, moveSeal); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadNode(ctx, a[1].ID)
	if err != nil || got.ParentID != nil {
		t.Fatal("root placement", err)
	}
	target, err := s.ReadNode(ctx, b[0].ID)
	if err != nil || got.SortOrder != target.SortOrder+1 {
		t.Fatal("root order", err)
	}
	leaf, err := s.ReadNode(ctx, a[2].ID)
	if err != nil || !reflect.DeepEqual(leaf, a[2]) {
		t.Fatal("subtree changed", err)
	}
}

func TestMoveNodesBoundsAuthenticatedProjectionBeforeWriting(t *testing.T) {
	s, _ := database(t)
	a, b := treeFixture(t, s), treeFixture(t, s)
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `WITH RECURSIVE entries(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM entries WHERE i<50001)
 INSERT INTO Nodes(Id,Name,Kind,SortOrder,CreatedAt,UpdatedAt,RowVersion,Deleted,SecretManifest,SealSuite,SealSignerKeyId,SealSignerKeyVersion,Seal)
 SELECT printf('00000000-0000-4000-8000-%012d',i),'Bounded fixture',0,0,CreatedAt,UpdatedAt,1,0,SecretManifest,SealSuite,SealSignerKeyId,SealSignerKeyVersion,Seal
 FROM entries CROSS JOIN Nodes WHERE Nodes.Id=?;`, a[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	seq := treeSequence(t, s)
	reads, writes := 0, 0
	_, err = s.MoveNodes(ctx, NodeMoveRequest{[]NodeRevision{{a[1].ID, 1}}, NodeRevision{b[1].ID, 1}, "inside"}, func(Node) error { reads++; return nil }, func(n Node) (Node, error) { writes++; return moveSeal(n) })
	if err != ErrFormat || reads != 50001 || writes != 0 || treeSequence(t, s) != seq {
		t.Fatal("unbounded or partial oversized move", reads, writes, err)
	}
}
