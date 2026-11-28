package vaultstore

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestNodeTreesUnionAndAtomicFailure(t *testing.T) {
	for _, mode := range []string{"ancestor-first", "descendant-first", "stale", "late-failure"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := database(t)
			a, b := treeFixture(t, s), treeFixture(t, s)
			targets := []NodeRevision{{a[0].ID, 1}, {a[2].ID, 1}, {b[0].ID, 1}}
			if mode == "descendant-first" {
				targets[0], targets[1] = targets[1], targets[0]
			}
			if mode == "stale" {
				targets[2].RowVersion = 2
			}
			sequence := treeSequence(t, s)
			visited := map[string]bool{}
			count, err := s.DeleteNodeTrees(context.Background(), targets, func(n Node, read SecretReader) (Node, []Secret, error) {
				if visited[n.ID] {
					t.Fatal("duplicate deletion")
				}
				visited[n.ID] = true
				if mode == "late-failure" && n.ID == b[0].ID {
					return Node{}, nil, ErrAuthenticationFixture
				}
				return treeTombstone(n, read)
			})
			if mode == "stale" || mode == "late-failure" {
				if err == nil || count != 0 {
					t.Fatal(count, err)
				}
				assertTreeUnchanged(t, s, append(a, b...), sequence)
				if mode == "stale" && len(visited) != 0 {
					t.Fatal("stale selection entered mutation")
				}
				return
			}
			if err != nil || count != 8 || len(visited) != 8 || treeSequence(t, s) != sequence+1 {
				t.Fatal(count, err)
			}
		})
	}
}

var ErrAuthenticationFixture = errors.New("fixture authentication failure")

func TestNodeTreesRejectInvalidSelections(t *testing.T) {
	s, _ := database(t)
	nodes := treeFixture(t, s)
	good := NodeRevision{nodes[0].ID, 1}
	for _, targets := range [][]NodeRevision{nil, {}, {good, good}, {{"bad", 1}}, {{good.ID, 0}}, {{good.ID, math.MaxInt64}}, make([]NodeRevision, MaxNodeDeleteRoots+1)} {
		if _, err := s.DeleteNodeTrees(context.Background(), targets, treeTombstone); err != ErrFormat {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteNodeTrees(context.Background(), []NodeRevision{good}, nil); err != ErrFormat {
		t.Fatal(err)
	}
}
