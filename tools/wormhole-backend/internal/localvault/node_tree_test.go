package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func ownerTree(t *testing.T, o *Owner) []vaultstore.Node {
	t.Helper()
	ctx := context.Background()
	root := nodeDraft()
	root.Kind = 0
	folder, err := o.PutNode(ctx, root, []SecretChange{{Field: "notes", Value: []byte("folder private notes")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	child := nodeDraft()
	child.ParentID = &folder.ID
	child.UseInlinePassword = nodePtr(true)
	leaf, err := o.PutNode(ctx, child, []SecretChange{{Field: "inlinePassword", Value: []byte("leaf private password")}, {Field: "notes", Value: []byte("leaf private notes")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return []vaultstore.Node{folder, leaf}
}

func TestNodeTreeOwnerDeletesEncryptedFieldsAndReopens(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	nodes := ownerTree(t, o)
	outside, err := o.PutNode(ctx, nodeDraft(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A previously removed notes field keeps its tombstone version on deletion.
	if _, err := o.PutNode(ctx, nodes[1].NodeMetadata, []SecretChange{{Field: "notes", Remove: true}}, 1); err != nil {
		t.Fatal(err)
	}
	if count, err := o.DeleteNodeTree(ctx, nodes[0].ID, 1); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	store := o.store.(vaultstore.NodeStore)
	for _, n := range nodes {
		got, err := store.ReadNode(ctx, n.ID)
		if err != nil || !got.Deleted || o.verifyNode(got) != nil {
			t.Fatal("invalid tombstone", err)
		}
		for _, f := range got.Fields {
			if f.Present || f.Version != 2 {
				t.Fatal("field tombstone", f)
			}
			value, err := store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: n.ID, Field: f.Field})
			if err != nil || len(value.Envelope.Ciphertext) != 16 || value.DEK.Version != 2 {
				t.Fatal("secret not replaced", err)
			}
		}
		if err := o.WithNodeField(ctx, n.ID, "notes", 0, func([]byte) error { t.Fatal("deleted secret released"); return nil }); err != vaultstore.ErrMissing {
			t.Fatal(err)
		}
	}
	if _, err := o.ReadNode(ctx, outside.ID, 1); err != nil {
		t.Fatal("unrelated node removed", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.ReadNode(ctx, nodes[0].ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if page, err := reopened.ListNodes(ctx, "", 128); err != nil || len(page) != 1 || page[0].ID != outside.ID {
		t.Fatal("reopened tree", err)
	}
	if _, err := o.DeleteNodeTree(ctx, nodes[0].ID, 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

type treeFilter struct {
	vaultstore.NodeTreeStore
	filter func(vaultstore.Node, vaultstore.SecretReader, vaultstore.NodeDeletion) (vaultstore.Node, []vaultstore.Secret, error)
}

func (s treeFilter) DeleteNodeTree(ctx context.Context, id string, version uint64, prepare vaultstore.NodeDeletion) (uint64, error) {
	return s.NodeTreeStore.DeleteNodeTree(ctx, id, version, func(n vaultstore.Node, read vaultstore.SecretReader) (vaultstore.Node, []vaultstore.Secret, error) {
		return s.filter(n, read, prepare)
	})
}

func TestNodeTreeOwnerRejectsTamperingAndRollsBackSecrets(t *testing.T) {
	for _, attack := range []string{"parent-mac", "child-mac", "secret-mac", "wrong-field", "secret-version", "exhausted-row", "deleted-row", "cancel"} {
		t.Run(attack, func(t *testing.T) {
			o, _, _, _ := owner(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			nodes := ownerTree(t, o)
			real := o.store.(vaultstore.NodeTreeStore)
			visited := 0
			o.store = treeFilter{NodeTreeStore: real, filter: func(n vaultstore.Node, read vaultstore.SecretReader, prepare vaultstore.NodeDeletion) (vaultstore.Node, []vaultstore.Secret, error) {
				visited++
				if (attack == "parent-mac" && n.ID == nodes[0].ID) || (attack == "child-mac" && n.ID == nodes[1].ID) {
					n.Name = "forged"
				}
				if attack == "exhausted-row" || attack == "deleted-row" {
					n.RowVersion = math.MaxInt64
					if attack == "deleted-row" {
						n.Deleted = true
						n.Fields = nil
						n.UseInlinePassword = nil
					}
					if err := o.root.With(func(key []byte) error { var err error; n.Seal, err = nodeMAC(key, real.Identity(), n); return err }); err != nil {
						t.Fatal(err)
					}
				}
				if attack == "cancel" && n.ID == nodes[0].ID {
					cancel()
				}
				wrapped := func(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
					s, err := read(ctx, ref)
					if err != nil {
						return s, err
					}
					switch attack {
					case "secret-mac":
						s.Copy.Signature[0] ^= 1
					case "wrong-field":
						s.Ref.Field = "other"
					case "secret-version":
						s.RowVersion++
					}
					return s, nil
				}
				return prepare(n, wrapped)
			}}
			count, err := o.DeleteNodeTree(ctx, nodes[0].ID, 1)
			o.store = real
			if err == nil || count != 0 {
				t.Fatal("tampered tree deleted", err, count)
			}
			if (attack == "parent-mac" || attack == "cancel") && visited != 2 {
				t.Fatal("did not test late rollback")
			}
			for _, n := range nodes {
				got, err := o.ReadNode(context.Background(), n.ID, n.RowVersion)
				if err != nil || !reflect.DeepEqual(got, n) {
					t.Fatal("partial owner deletion", err)
				}
			}
			if err := o.WithNodeField(context.Background(), nodes[1].ID, "inlinePassword", 1, func(value []byte) error {
				if !bytes.Equal(value, []byte("leaf private password")) {
					t.Fatal("lost original password")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeTreeOwnerUnsupportedStoreAndStaleRoot(t *testing.T) {
	o, _, _, _ := owner(t)
	nodes := ownerTree(t, o)
	if _, err := o.DeleteNodeTree(context.Background(), nodes[0].ID, 2); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	real := o.store
	o.store = struct{ vaultstore.NodeStore }{real.(vaultstore.NodeStore)}
	if _, err := o.DeleteNodeTree(context.Background(), nodes[0].ID, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = real
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.DeleteNodeTree(ctx, nodes[0].ID, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.WithNodeField(context.Background(), nodes[1].ID, "notes", 1, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
