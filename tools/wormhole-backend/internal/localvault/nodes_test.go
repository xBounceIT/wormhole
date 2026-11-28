package localvault

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func nodePtr[T any](v T) *T { return &v }
func nodeDraft() vaultstore.NodeMetadata {
	return vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Node", Kind: 1, Protocol: nodePtr(0), Host: nodePtr("host.example")}
}

func TestNodeOwnerEncryptedFieldsAndReopen(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	metadata := nodeDraft()
	metadata.UseInlinePassword = nodePtr(true)
	password := []byte("unique-inline-password-not-on-disk")
	notes := []byte("unique-private-notes-not-on-disk")
	original, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "inlinePassword", Value: password}, {Field: "notes", Value: notes}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.ReadNode(ctx, metadata.ID, 1)
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal(err)
	}
	if page, err := o.ListNodes(ctx, "", 1); err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	var borrowed []byte
	sentinel := errors.New("callback failure")
	if err := o.WithNodeField(ctx, metadata.ID, "inlinePassword", 1, func(value []byte) error {
		borrowed = value
		if !bytes.Equal(value, password) {
			t.Fatal("password changed")
		}
		return sentinel
	}); err != sentinel {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed value retained")
	}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 1, func(value []byte) error {
		if !bytes.Equal(value, notes) {
			t.Fatal("notes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	metadata.Name = "Renamed"
	renamed, err := o.PutNode(ctx, metadata, nil, 1)
	if err != nil || renamed.Fields[0].Version != 1 || renamed.CreatedAt != original.CreatedAt {
		t.Fatal(err)
	}
	if _, err := o.Put(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: metadata.ID, Field: "notes"}, []byte("bypass"), 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	metadata.UseInlinePassword = nodePtr(false)
	if _, err := o.PutNode(ctx, metadata, nil, 2); err != vault.ErrFormat {
		t.Fatal("manifest/inline mismatch allowed", err)
	}
	removed, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "inlinePassword", Remove: true}}, 2)
	if err != nil || removed.Fields[0].Version != 2 || removed.Fields[0].Present {
		t.Fatal(err)
	}
	if err := o.WithNodeField(ctx, metadata.ID, "inlinePassword", 0, func([]byte) error { t.Fatal("removed field released"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	metadata.UseInlinePassword = nodePtr(true)
	restored, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "inlinePassword", Value: password}}, 3)
	if err != nil || restored.Fields[0].Version != 3 {
		t.Fatal(err)
	}
	if _, err := o.ReadNode(ctx, metadata.ID, 5); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 5, func([]byte) error { return nil }); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, password) || bytes.Contains(raw, notes) {
		t.Fatal("plaintext persisted", err)
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.WithNodeField(ctx, metadata.ID, "notes", 4, func(value []byte) error {
		if !bytes.Equal(value, notes) {
			t.Fatal("reopen lost notes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteNode(ctx, metadata.ID, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ReadNode(ctx, metadata.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := reopened.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { t.Fatal("deleted notes released"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if _, err := reopened.PutNode(ctx, metadata, nil, 0); err != vaultstore.ErrConflict {
		t.Fatal("deleted ID reused", err)
	}
}

type completeNodeStore interface {
	vaultstore.NodeStore
	vaultstore.CredentialStore
	vaultstore.TunnelStore
}
type nodeFilter struct {
	completeNodeStore
	read       func(vaultstore.Node) (vaultstore.Node, error)
	list       func([]vaultstore.Node) ([]vaultstore.Node, error)
	credential func(vaultstore.Credential) (vaultstore.Credential, error)
	tunnel     func(vaultstore.Tunnel) (vaultstore.Tunnel, error)
	secret     func(vaultstore.Secret) (vaultstore.Secret, error)
	writeErr   error
}

func (s nodeFilter) ReadNode(ctx context.Context, id string) (vaultstore.Node, error) {
	n, err := s.completeNodeStore.ReadNode(ctx, id)
	if err == nil && s.read != nil {
		return s.read(n)
	}
	return n, err
}
func (s nodeFilter) ListNodes(ctx context.Context, after string, limit int) ([]vaultstore.Node, error) {
	ns, err := s.completeNodeStore.ListNodes(ctx, after, limit)
	if err == nil && s.list != nil {
		return s.list(ns)
	}
	return ns, err
}
func (s nodeFilter) ReadCredential(ctx context.Context, id string) (vaultstore.Credential, error) {
	c, err := s.completeNodeStore.ReadCredential(ctx, id)
	if err == nil && s.credential != nil {
		return s.credential(c)
	}
	return c, err
}
func (s nodeFilter) ReadTunnel(ctx context.Context, id string) (vaultstore.Tunnel, error) {
	v, err := s.completeNodeStore.ReadTunnel(ctx, id)
	if err == nil && s.tunnel != nil {
		return s.tunnel(v)
	}
	return v, err
}
func (s nodeFilter) ReadSecret(ctx context.Context, ref vaultstore.SecretRef) (vaultstore.Secret, error) {
	v, err := s.completeNodeStore.ReadSecret(ctx, ref)
	if err == nil && s.secret != nil {
		return s.secret(v)
	}
	return v, err
}
func (s nodeFilter) WriteNode(ctx context.Context, n vaultstore.Node, secrets []vaultstore.Secret, expected uint64) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	return s.completeNodeStore.WriteNode(ctx, n, secrets, expected)
}

func TestNodeOwnerRejectsTamperingAndFieldSubstitution(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := nodeDraft()
	original, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "notes", Value: []byte("notes")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	for _, mutate := range []func(*vaultstore.Node){func(n *vaultstore.Node) { n.Host = nodePtr("redirected") }, func(n *vaultstore.Node) { n.ID = uuid.NewString() }, func(n *vaultstore.Node) { n.ParentID = nodePtr(uuid.NewString()) }, func(n *vaultstore.Node) { n.Seal = nil }, func(n *vaultstore.Node) { n.SealSignerKeyID = uuid.NewString() }, func(n *vaultstore.Node) { n.SealSignerKeyVersion++ }, func(n *vaultstore.Node) { n.RDPGatewayUseSameCreds = nodePtr(false) }, func(n *vaultstore.Node) { n.Fields = nil }} {
		o.store = nodeFilter{completeNodeStore: store, read: func(n vaultstore.Node) (vaultstore.Node, error) { mutate(&n); return n, nil }, list: func(ns []vaultstore.Node) ([]vaultstore.Node, error) { mutate(&ns[0]); return ns, nil }}
		if _, err := o.ReadNode(ctx, metadata.ID, 0); err == nil {
			t.Fatal("read tampered node")
		}
		if _, err := o.ListNodes(ctx, "", 1); err == nil {
			t.Fatal("listed tampered node")
		}
		if _, err := o.PutNode(ctx, metadata, nil, 1); err == nil {
			t.Fatal("re-signed tampered node")
		}
		if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { t.Fatal("tampered release"); return nil }); err == nil {
			t.Fatal("unverified field")
		}
	}
	o.store = store
	if _, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "notes", Value: []byte("new")}}, 1); err != nil {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, read: func(vaultstore.Node) (vaultstore.Node, error) { return original, nil }}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { t.Fatal("mixed revisions"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = store
	other := nodeDraft()
	otherNode, err := o.PutNode(ctx, other, []SecretChange{{Field: "notes", Value: []byte("other")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: other.ID, Field: "notes"})
	if err != nil {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, secret: func(vaultstore.Secret) (vaultstore.Secret, error) { return otherSecret, nil }}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { t.Fatal("substitution"); return nil }); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, metadata, []SecretChange{{Field: "notes", Value: []byte("updated")}}, 2); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, read: func(vaultstore.Node) (vaultstore.Node, error) { return otherNode, nil }}
	if _, err := o.ReadNode(ctx, metadata.ID, 0); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
	o.store = store
	if err := o.DeleteNode(ctx, other.ID, 1); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ReadNode(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, list: func([]vaultstore.Node) ([]vaultstore.Node, error) { return []vaultstore.Node{deleted}, nil }}
	if _, err := o.ListNodes(ctx, "", 1); err != vault.ErrAuthentication {
		t.Fatal(err)
	}
}

func TestNodeOwnerAuthenticatesReferencedRecords(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	parent := nodeDraft()
	parent.Kind = 0
	if _, err := o.PutNode(ctx, parent, nil, 0); err != nil {
		t.Fatal(err)
	}
	c := draft()
	if _, err := o.PutCredential(ctx, c, nil, 0); err != nil {
		t.Fatal(err)
	}
	tunnel := tunnelDraft()
	if _, err := o.PutTunnel(ctx, tunnel, []byte("configuration"), 0); err != nil {
		t.Fatal(err)
	}
	metadata := nodeDraft()
	metadata.ParentID = &parent.ID
	metadata.CredentialID = &c.ID
	metadata.TunnelConfigID = &tunnel.ID
	if _, err := o.PutNode(ctx, metadata, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := o.DeleteNode(ctx, parent.ID, 1); err != vaultstore.ErrConflict {
		t.Fatal("nonempty folder deleted", err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	for _, filter := range []nodeFilter{
		{completeNodeStore: store, read: func(n vaultstore.Node) (vaultstore.Node, error) {
			if n.ID == parent.ID {
				n.Name = "changed"
			}
			return n, nil
		}},
		{completeNodeStore: store, read: func(n vaultstore.Node) (vaultstore.Node, error) {
			if n.ID == parent.ID {
				n.ID = uuid.NewString()
			}
			return n, nil
		}},
		{completeNodeStore: store, credential: func(c vaultstore.Credential) (vaultstore.Credential, error) { c.Username = "changed"; return c, nil }},
		{completeNodeStore: store, credential: func(c vaultstore.Credential) (vaultstore.Credential, error) { c.ID = uuid.NewString(); return c, nil }},
		{completeNodeStore: store, tunnel: func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { v.Kind = 2; return v, nil }},
		{completeNodeStore: store, tunnel: func(v vaultstore.Tunnel) (vaultstore.Tunnel, error) { v.ID = uuid.NewString(); return v, nil }},
	} {
		o.store = filter
		if _, err := o.PutNode(ctx, metadata, nil, 1); !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("signed unverified dependency", err)
		}
	}
	o.store = store
	folder := nodeDraft()
	folder.Kind = 0
	folder.ParentID = &parent.ID
	if _, err := o.PutNode(ctx, folder, nil, 0); err != nil {
		t.Fatal(err)
	}
	parent.ParentID = &folder.ID
	if _, err := o.PutNode(ctx, parent, nil, 1); err != vaultstore.ErrConflict {
		t.Fatal("cycle", err)
	}
}

func TestNodeOwnerValidationAndFailurePaths(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	metadata := nodeDraft()
	if err := o.DeleteNode(ctx, metadata.ID, 0); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, metadata, nil, 1); err != vaultstore.ErrConflict {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, metadata, nil, math.MaxInt64); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.ReadNode(ctx, metadata.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, nil); err != vault.ErrFormat {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.PutNode(cancelled, metadata, nil, 0); err != context.Canceled {
		t.Fatal(err)
	}
	for _, changes := range [][]SecretChange{{{Field: "password"}}, {{Field: "notes", Remove: true}}, {{Field: "notes"}, {Field: "notes"}}, {{Field: "notes"}, {Field: "inlinePassword"}, {Field: "other"}}, {{Field: "notes", Value: []byte("\xff")}}, {{Field: "notes", Value: []byte("a\x00b")}}, {{Field: "notes", Value: []byte(strings.Repeat("a", 16385))}}} {
		if _, err := o.PutNode(ctx, metadata, changes, 0); err != vault.ErrFormat {
			t.Fatal("invalid change", err)
		}
	}
	if !ValidNodeNotes([]byte(strings.Repeat("😀", 8192))) || ValidNodeNotes([]byte(strings.Repeat("😀", 8193))) || ValidNodeNotes(make([]byte, 65537)) {
		t.Fatal("UTF-16 note bound")
	}
	bad := metadata
	bad.Name = ""
	if _, err := o.PutNode(ctx, bad, nil, 0); err != vault.ErrFormat {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, metadata, nil, 0); err != nil {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	o.store = nodeFilter{completeNodeStore: store, writeErr: vaultstore.ErrStorage}
	if _, err := o.PutNode(ctx, metadata, nil, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = nodeFilter{completeNodeStore: store, read: func(vaultstore.Node) (vaultstore.Node, error) { return vaultstore.Node{}, vaultstore.ErrStorage }, list: func([]vaultstore.Node) ([]vaultstore.Node, error) { return nil, vaultstore.ErrStorage }}
	if _, err := o.PutNode(ctx, metadata, nil, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.ListNodes(ctx, "", 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = struct{ vaultstore.Store }{store}
	if _, err := o.ReadNode(ctx, metadata.ID, 0); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.ListNodes(ctx, "", 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if _, err := o.PutNode(ctx, metadata, nil, 1); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	if err := o.WithNodeField(ctx, metadata.ID, "notes", 0, func([]byte) error { return nil }); err != vaultstore.ErrStorage {
		t.Fatal(err)
	}
	o.store = store
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := o.PutNode(ctx, metadata, nil, 1); results <- err }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal(winners)
	}
	o.Close()
	if _, err := o.ReadNode(ctx, metadata.ID, 0); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
	if _, err := nodeMAC(nil, store.Identity(), vaultstore.Node{}); err == nil {
		t.Fatal("invalid MAC key")
	}
}
