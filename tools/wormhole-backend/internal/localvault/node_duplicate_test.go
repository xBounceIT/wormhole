package localvault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDuplicateConnectionReencryptsFieldsAndPreservesSource(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	nodes := ownerTree(t, o)
	source := nodes[1]
	source.NodeMetadata.Name = strings.Repeat("🪱", 256)
	source.SshKnownHostFingerprint = nodePtr(hostFingerprint(1))
	source, err := o.PutNode(ctx, source.NodeMetadata, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	sibling := nodeDraft()
	sibling.ParentID = source.ParentID
	sibling.SortOrder = 40
	if _, err := o.PutNode(ctx, sibling, nil, 0); err != nil {
		t.Fatal(err)
	}
	copy, err := o.DuplicateConnection(ctx, source.ID, source.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if copy.ID == source.ID || copy.RowVersion != 1 || copy.SortOrder != 41 || *copy.ParentID != *source.ParentID || copy.SshKnownHostFingerprint != nil || utf8.RuneCountInString(copy.Name) != 256 || !strings.HasSuffix(copy.Name, " (copy)") {
		t.Fatal("copy metadata", copy)
	}
	for _, field := range []string{"inlinePassword", "notes"} {
		before, err := o.store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: source.ID, Field: field})
		if err != nil {
			t.Fatal(err)
		}
		after, err := o.store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: copy.ID, Field: field})
		if err != nil {
			t.Fatal(err)
		}
		if before.DEK.ID == after.DEK.ID || bytes.Equal(before.Envelope.Ciphertext, after.Envelope.Ciphertext) || after.RowVersion != 1 {
			t.Fatal("old encryption reused")
		}
		var expected []byte
		if err := o.WithNodeField(ctx, source.ID, field, source.RowVersion, func(value []byte) error { expected = append([]byte{}, value...); return nil }); err != nil {
			t.Fatal(err)
		}
		if err := o.WithNodeField(ctx, copy.ID, field, 1, func(value []byte) error {
			if !bytes.Equal(value, expected) {
				t.Fatal("copied secret changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		vault.Wipe(expected)
	}
	original, err := o.ReadNode(ctx, source.ID, source.RowVersion)
	if err != nil || !reflect.DeepEqual(original, source) {
		t.Fatal("source changed", err)
	}
	if o.nodeFloors[copy.ID] != 1 {
		t.Fatal("missing new checkpoint")
	}
}
func TestDuplicateConnectionRetainsMigrationChoicesAndProvenance(t *testing.T) {
	for _, choice := range []string{"keep", "new"} {
		t.Run(choice, func(t *testing.T) {
			ctx := context.Background()
			o, _, _, _ := owner(t)
			n, _, plan := nodeMigrationFixture(t, o)
			for i := range plan.Entries {
				plan.Entries[i].Choice = choice
			}
			n, err := o.ImportResolverMigration(ctx, n.ID, plan, n.RowVersion)
			if err != nil {
				t.Fatal(err)
			}
			copy, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion)
			if err != nil {
				t.Fatal(err)
			}
			copied, err := o.ReadResolverMigration(ctx, copy.ID, 1)
			if err != nil || copied.Fingerprint != plan.Fingerprint || len(copied.Entries) != len(plan.Entries) {
				t.Fatal("lost provenance", err)
			}
			for i, e := range copied.Entries {
				if e.Legacy.NodeID != copy.ID || e.Candidate.NodeID != copy.ID || e.Candidate.CredentialID != copy.ID || e.Choice != plan.Entries[i].Choice {
					t.Fatal("unrebound identity", e)
				}
			}
			for _, path := range []string{"ssh", "sftp", "reveal"} {
				before, err := o.ResolveConnectionPath(ctx, n.ID, "", path)
				if err != nil {
					t.Fatal(err)
				}
				after, err := o.ResolveConnectionPath(ctx, copy.ID, "", path)
				if err != nil {
					t.Fatal(err)
				}
				if before.Account.Username != after.Account.Username || before.Account.SourceKind != after.Account.SourceKind {
					t.Fatal("changed account")
				}
				if err := o.WithConnectionSecret(ctx, copy.ID, "", path, "password", func(_ Resolution, value []byte) error {
					want := "pinned-secret"
					if choice == "new" {
						want = "candidate-secret"
					}
					if string(value) != want {
						t.Fatal("wrong copied credential")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	// The retained legacy inline account also needs its owner ID rebound.
	o, _, _, _ := owner(t)
	ctx := context.Background()
	c, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("saved")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.CredentialID = &c.ID
	m.UseInlinePassword = nodePtr(true)
	n, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("old inline")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = installAccountMigration(t, o, n, map[string]resolver.EffectiveCredentialSnapshot{"ssh": {SourceKind: "inline", CredentialID: n.ID, Username: "old"}})
	copy, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WithConnectionSecret(ctx, copy.ID, "", "ssh", "password", func(_ Resolution, value []byte) error {
		if string(value) != "old inline" {
			t.Fatal("legacy inline lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestDuplicateConnectionRejectsInvalidOrStaleSource(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	nodes := ownerTree(t, o)
	for _, q := range []struct {
		id      string
		version uint64
	}{{nodes[0].ID, 1}, {nodes[1].ID, 0}, {nodes[1].ID, 2}, {nodes[1].ID, math.MaxInt64}, {uuid.NewString(), 1}, {"invalid", 1}} {
		if _, err := o.DuplicateConnection(ctx, q.id, q.version); err == nil {
			t.Fatal("accepted invalid source")
		}
	}
	o.nodeFloors[nodes[1].ID] = 2
	if _, err := o.DuplicateConnection(ctx, nodes[1].ID, 1); err != vault.ErrRollback {
		t.Fatal(err)
	}
	o.nodeFloors[nodes[1].ID] = 1
	m := nodes[1].NodeMetadata
	m.SortOrder = math.MaxInt64
	n, err := o.PutNode(ctx, m, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion); err != vaultstore.ErrConflict {
		t.Fatal("order overflow", err)
	}
	if err := o.DeleteNode(ctx, n.ID, n.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	o.Close()
	if _, err := o.DuplicateConnection(ctx, n.ID, 1); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}
func TestDuplicateConnectionRejectsAuthenticatedInputDrift(t *testing.T) {
	for _, mode := range []string{"read-error", "read-mac", "list-error", "list-mac", "repeated-page", "empty-list", "large-page", "list-version", "secret", "missing-secret"} {
		t.Run(mode, func(t *testing.T) {
			o, _, _, _ := owner(t)
			ctx := context.Background()
			nodes := ownerTree(t, o)
			original := o.store
			real := original.(completeNodeStore)
			source := nodes[1]
			f := nodeFilter{completeNodeStore: real}
			if mode == "read-error" {
				f.read = func(vaultstore.Node) (vaultstore.Node, error) { return vaultstore.Node{}, vaultstore.ErrStorage }
			}
			if mode == "read-mac" {
				f.read = func(n vaultstore.Node) (vaultstore.Node, error) { n.Name = "tampered"; return n, nil }
			}
			if strings.HasPrefix(mode, "list") || mode == "repeated-page" || mode == "empty-list" || mode == "large-page" {
				f.list = func(page []vaultstore.Node) ([]vaultstore.Node, error) {
					switch mode {
					case "list-error":
						return nil, vaultstore.ErrStorage
					case "list-mac":
						if len(page) > 0 {
							page[0].Name = "tampered"
						}
					case "empty-list":
						return nil, nil
					case "large-page":
						return make([]vaultstore.Node, 129), nil
					case "repeated-page":
						return []vaultstore.Node{source, source}, nil
					case "list-version":
						for i := range page {
							if page[i].ID == source.ID {
								page[i].RowVersion++
								o.root.With(func(key []byte) error { page[i].Seal, _ = nodeMAC(key, real.Identity(), page[i]); return nil })
							}
						}
					}
					return page, nil
				}
			}
			if mode == "secret" {
				f.secret = func(v vaultstore.Secret) (vaultstore.Secret, error) {
					v.Envelope.Ciphertext = append([]byte{}, v.Envelope.Ciphertext...)
					v.Envelope.Ciphertext[0] ^= 1
					return v, nil
				}
			}
			if mode == "missing-secret" {
				f.secret = func(vaultstore.Secret) (vaultstore.Secret, error) { return vaultstore.Secret{}, vaultstore.ErrMissing }
			}
			o.store = f
			_, err := o.DuplicateConnection(ctx, source.ID, source.RowVersion)
			o.store = original
			if err == nil {
				t.Fatal("accepted", mode)
			}
			page, err := o.ListNodes(ctx, "", 128)
			if err != nil || len(page) != 2 {
				t.Fatal("partial publication", err)
			}
		})
	}
}

type failDuplicateWrite struct {
	completeNodeStore
	created *vaultstore.Node
}

func (s failDuplicateWrite) WriteNode(ctx context.Context, n vaultstore.Node, fields []vaultstore.Secret, expected uint64) error {
	*s.created = n
	if len(fields) < 2 {
		return errors.New("fixture needs two fields")
	}
	fields[len(fields)-1].Ref.OwnerID = uuid.NewString()
	return s.completeNodeStore.WriteNode(ctx, n, fields, expected)
}
func TestDuplicateConnectionLateWriteFailurePublishesNothing(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	nodes := ownerTree(t, o)
	original := o.store
	real := original.(completeNodeStore)
	var attempted vaultstore.Node
	o.store = failDuplicateWrite{real, &attempted}
	_, err := o.DuplicateConnection(ctx, nodes[1].ID, 1)
	o.store = original
	if err == nil || attempted.ID == "" {
		t.Fatal("write failure not exercised", err)
	}
	if _, err := real.ReadNode(ctx, attempted.ID); err != vaultstore.ErrMissing {
		t.Fatal("partial node", err)
	}
	for _, field := range []string{"inlinePassword", "notes"} {
		if _, err := real.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: attempted.ID, Field: field}); err != vaultstore.ErrMissing {
			t.Fatal("partial secret", err)
		}
	}
	if _, ok := o.nodeFloors[attempted.ID]; ok {
		t.Fatal("failed copy published checkpoint")
	}
}

func TestDuplicateConnectionMigrationFailuresPublishNothing(t *testing.T) {
	for _, mode := range []string{"migration-json", "migration-mac", "kept-credential"} {
		t.Run(mode, func(t *testing.T) {
			o, _, _, _ := owner(t)
			ctx := context.Background()
			n, _, plan := nodeMigrationFixture(t, o)
			n, err := o.ImportResolverMigration(ctx, n.ID, plan, n.RowVersion)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "migration-json" {
				o.mu.Lock()
				n, err = o.writeNode(ctx, n.NodeMetadata, []SecretChange{{Field: vaultstore.NodeResolverMigrationField, Value: []byte("{")}}, n.RowVersion, false, nil)
				o.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			original := o.store
			real := original.(completeNodeStore)
			f := nodeFilter{completeNodeStore: real}
			if mode == "migration-mac" {
				f.secret = func(v vaultstore.Secret) (vaultstore.Secret, error) {
					if v.Ref.Field == vaultstore.NodeResolverMigrationField {
						v.Copy.Signature = append([]byte{}, v.Copy.Signature...)
						v.Copy.Signature[0] ^= 1
					}
					return v, nil
				}
			}
			if mode == "kept-credential" {
				f.credential = func(c vaultstore.Credential) (vaultstore.Credential, error) { c.Username = "tampered"; return c, nil }
			}
			floorCount := len(o.nodeFloors)
			o.store = f
			_, err = o.DuplicateConnection(ctx, n.ID, n.RowVersion)
			o.store = original
			if err == nil {
				t.Fatal("accepted", mode)
			}
			nodes, err := o.ListNodes(ctx, "", 128)
			if err != nil || len(nodes) != 1 || len(o.nodeFloors) != floorCount {
				t.Fatal("partial duplicate", err)
			}
		})
	}
}

type duplicateCatalog struct {
	completeNodeStore
	o      *Owner
	source vaultstore.Node
	total  int
}

func (s duplicateCatalog) ListNodes(ctx context.Context, after string, limit int) ([]vaultstore.Node, error) {
	offset := 0
	if after != "" {
		offset, _ = strconv.Atoi(after[len(after)-12:])
	}
	page := []vaultstore.Node{}
	err := s.o.root.With(func(key []byte) error {
		for i := offset + 1; i <= s.total && len(page) < limit; i++ {
			n := s.source
			n.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			var err error
			n.Seal, err = nodeMAC(key, s.Identity(), n)
			if err != nil {
				return err
			}
			page = append(page, n)
		}
		return ctx.Err()
	})
	return page, err
}
func TestDuplicateConnectionCannotOutgrowProjection(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	m := nodeDraft()
	m.ID = "00000000-0000-4000-8000-000000000001"
	n, err := o.PutNode(ctx, m, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := o.store
	real := original.(completeNodeStore)
	for _, total := range []int{50000, 50001} {
		o.store = duplicateCatalog{real, o, n, total}
		_, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion)
		o.store = original
		want := vaultstore.ErrConflict
		if total > 50000 {
			want = vault.ErrFormat
		}
		if err != want {
			t.Fatal(total, err)
		}
		nodes, err := o.ListNodes(ctx, "", 128)
		if err != nil || len(nodes) != 1 || len(o.nodeFloors) != 1 {
			t.Fatal("capacity failure published", err)
		}
	}
}

func TestDuplicateConnectionDoesNotReviveRemovedFields(t *testing.T) {
	o, _, _, _ := owner(t)
	ctx := context.Background()
	n, err := o.PutNode(ctx, nodeDraft(), []SecretChange{{Field: "notes", Value: []byte("removed note")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err = o.PutNode(ctx, n.NodeMetadata, []SecretChange{{Field: "notes", Remove: true}}, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := o.DuplicateConnection(ctx, n.ID, n.RowVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(copy.Fields) != 0 || copy.ParentID != nil {
		t.Fatal("tombstone or parent copied incorrectly")
	}
	if err := o.WithNodeField(ctx, copy.ID, "notes", 1, func([]byte) error { t.Fatal("removed note revived"); return nil }); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if _, err := o.store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: copy.ID, Field: "notes"}); err != vaultstore.ErrMissing {
		t.Fatal("removed field key copied", err)
	}
}
