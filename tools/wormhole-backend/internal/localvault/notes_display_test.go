package localvault

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestNotesDisplayAuthenticatesBeforeRelease(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	public := key.PublicKey().Bytes()
	node, err := o.PutNode(ctx, nodeDraft(), []SecretChange{{Field: "notes", Value: []byte("protected")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := uuid.NewString()
	if _, err = o.SealNodeNotes(ctx, node.ID, request, 1, public); err != nil {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	for _, mutate := range []func(*vaultstore.Node){func(n *vaultstore.Node) { n.ID = uuid.NewString() }, func(n *vaultstore.Node) { n.Seal = nil }, func(n *vaultstore.Node) { n.Fields = nil }, func(n *vaultstore.Node) { n.Name = "changed" }} {
		o.store = nodeFilter{completeNodeStore: store, read: func(n vaultstore.Node) (vaultstore.Node, error) { mutate(&n); return n, nil }}
		if _, err = o.SealNodeNotes(ctx, node.ID, request, 1, public); err == nil {
			t.Fatal("tampered note display")
		}
	}
	o.store = store
	newer, err := o.PutNode(ctx, node.NodeMetadata, []SecretChange{{Field: "notes", Value: []byte("new")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, read: func(vaultstore.Node) (vaultstore.Node, error) { return node, nil }}
	if _, err = o.SealNodeNotes(ctx, node.ID, request, 1, public); err == nil {
		t.Fatal("replayed note display")
	}
	o.store = store
	if _, err = o.SealNodeNotes(ctx, node.ID, request, newer.RowVersion, nil); err == nil {
		t.Fatal("invalid recipient")
	}
	empty, err := o.PutNode(ctx, nodeDraft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.SealNodeNotes(ctx, empty.ID, request, 1, nil); err == nil {
		t.Fatal("empty note recipient bypass")
	}
	if result, err := o.SealNodeNotes(ctx, empty.ID, request, 1, public); err != nil || len(result.Bundle.Ciphertext) != 16 {
		t.Fatal("empty notes", err)
	}
}
