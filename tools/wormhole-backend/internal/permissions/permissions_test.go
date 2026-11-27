package permissions

import (
	"github.com/google/uuid"
	"testing"
)

func TestEffective(t *testing.T) {
	user, other, root, leaf, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	chain := []Node{{ID: leaf, Parent: root, Kind: 1}, {ID: root}}
	for mask := Mask(1); mask <= All; mask++ {
		grants := []Grant{{Node: root, User: user, Permissions: mask}, {Node: leaf, Group: group, Permissions: Use}, {Node: leaf, User: other, Permissions: All}}
		got, err := Effective(user, chain, []uuid.UUID{group, group}, grants)
		if err != nil || got != mask|Use {
			t.Fatal(mask, got, err)
		}
		got, err = Effective(user, chain, nil, grants)
		if err != nil || got != mask {
			t.Fatal("non-member acquired group grant", got, err)
		}
	}
	own := append([]Node(nil), chain...)
	own[1].Owner = user
	if got, err := Effective(user, own, nil, []Grant{{Node: leaf, User: user, Permissions: All}}); err != nil || got != All {
		t.Fatal(got, err)
	}
	own[1].Owner = other
	if got, err := Effective(user, own, nil, []Grant{{Node: leaf, User: user, Permissions: All}}); err != nil || got != 0 {
		t.Fatal("personal scope escaped", got, err)
	}
	if got, err := Effective(user, chain, nil, []Grant{{Node: uuid.New(), User: user, Permissions: All}}); err != nil || got != 0 {
		t.Fatal(got, err)
	}
	if got, err := Effective(user, chain, nil, nil); err != nil || got != 0 {
		t.Fatal(got, err)
	}
	invalidChains := [][]Node{nil, make([]Node, 129), {{ID: leaf, Parent: root}}, {{ID: leaf, Parent: root}, {ID: root, Kind: 1}}, {{ID: leaf, Kind: 2}}, {{ID: leaf, Parent: root}, {ID: leaf}}, {{ID: leaf, Parent: other}, {ID: root}}, {{}}}
	for _, chain := range invalidChains {
		if got, err := Effective(user, chain, nil, nil); err != ErrSnapshot || got != 0 {
			t.Fatal("invalid chain accepted")
		}
	}
	for _, grant := range []Grant{{Node: leaf, User: user}, {Node: leaf, Permissions: View}, {Node: leaf, User: user, Group: group, Permissions: View}, {User: user, Permissions: View}, {Node: leaf, User: user, Permissions: 32}} {
		if got, err := Effective(user, chain, nil, []Grant{grant}); err != ErrSnapshot || got != 0 {
			t.Fatal("invalid grant accepted")
		}
	}
	for _, groups := range [][]uuid.UUID{{uuid.Nil}, make([]uuid.UUID, MaxEntries+1)} {
		if _, err := Effective(user, chain, groups, nil); err != ErrSnapshot {
			t.Fatal(err)
		}
	}
	if _, err := Effective(uuid.Nil, chain, nil, nil); err != ErrSnapshot {
		t.Fatal(err)
	}
	if _, err := Effective(user, chain, nil, make([]Grant, MaxEntries+1)); err != ErrSnapshot {
		t.Fatal(err)
	}
	deep := make([]Node, MaxDepth)
	for i := range deep {
		deep[i].ID = uuid.New()
		if i > 0 {
			deep[i-1].Parent = deep[i].ID
		}
	}
	if _, err := Effective(user, deep, nil, nil); err != nil {
		t.Fatal(err)
	}
}
