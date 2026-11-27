package localvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func nodeMigrationFixture(t *testing.T, o *Owner) (vaultstore.Node, vaultstore.Credential, resolver.MigrationPlan) {
	t.Helper()
	ctx := context.Background()
	c, err := o.PutCredential(ctx, draft(), []SecretChange{{Field: "password", Value: []byte("pinned-secret")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeDraft()
	m.ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	m.UseInlinePassword = nodePtr(true)
	n, err := o.PutNode(ctx, m, []SecretChange{{Field: "inlinePassword", Value: []byte("candidate-secret")}, {Field: "notes", Value: []byte("private-notes")}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var old, next []resolver.EffectiveCredentialSnapshot
	for _, path := range []string{"ssh", "sftp", "reveal"} {
		a := resolver.EffectiveCredentialSnapshot{NodeID: n.ID, ProtocolPath: path, CredentialID: c.ID, Username: "old-identity-never-write-clear", SourceKind: "saved"}
		b := a
		b.CredentialID, b.SourceKind, b.Username, b.ResolverVersion = n.ID, "inline", "new-identity-never-write-clear", resolver.Version
		old, next = append(old, a), append(next, b)
	}
	plan, err := resolver.BuildMigration(o.store.Identity().WorkspaceID, old, next)
	if err != nil {
		t.Fatal(err)
	}
	return n, c, plan
}

func TestResolverMigrationEncryptedPersistenceChoicesAndRetirement(t *testing.T) {
	ctx := context.Background()
	o, path, opts, key := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	stored, err := o.ImportResolverMigration(ctx, n.ID, plan, n.RowVersion)
	if err != nil || stored.RowVersion != 2 || len(stored.Fields) != 3 {
		t.Fatal(stored, err)
	}
	if stored.CreatedAt != n.CreatedAt || stored.UpdatedAt != n.UpdatedAt {
		t.Fatal("imported provenance changed while sealing resolver choices")
	}
	read, err := o.ReadResolverMigration(ctx, n.ID, 2)
	if err != nil || !reflect.DeepEqual(read, plan) {
		t.Fatal("plan changed", err)
	}
	if _, err := o.PutNode(ctx, n.NodeMetadata, []SecretChange{{Field: vaultstore.NodeResolverMigrationField, Remove: true}}, 2); err != vault.ErrFormat {
		t.Fatal("editor removed pin", err)
	}
	if err := o.WithNodeField(ctx, n.ID, vaultstore.NodeResolverMigrationField, 0, func([]byte) error { t.Fatal("private plan released as ordinary field"); return nil }); err != vault.ErrFormat {
		t.Fatal(err)
	}
	for _, override := range []string{"", c.ID} {
		wantUser := "old-identity-never-write-clear"
		if override != "" {
			wantUser = c.Username
		}
		if resolved, err := o.ResolveConnection(ctx, n.ID, override); err != nil || resolved.Plan.Credential.ID != c.ID || resolved.Plan.Username != wantUser {
			t.Fatal("pin or explicit override ignored", err)
		}
	}
	if err := o.WithConnectionSecret(ctx, n.ID, "", "ssh", "password", func(r Resolution, value []byte) error {
		if r.Account.ResolverVersion != 0 || r.Plan.Username != "old-identity-never-write-clear" || string(value) != "pinned-secret" {
			t.Fatal("wrong pinned account")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := o.DeleteCredential(ctx, c.ID, c.RowVersion); err != vaultstore.ErrConflict {
		t.Fatal("pinned credential deleted", err)
	}
	metadata := c.CredentialMetadata
	metadata.Protocol = "rdp"
	if _, err := o.PutCredential(ctx, metadata, nil, c.RowVersion); err != vaultstore.ErrConflict {
		t.Fatal("pinned protocol changed", err)
	}
	if _, err := o.PutCredential(ctx, c.CredentialMetadata, []SecretChange{{Field: "password", Value: []byte("rotated")}}, c.RowVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 2); err != vaultstore.ErrConflict {
		t.Fatal("pin provenance replaced", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{path, path + "-wal"} {
		contents, err := os.ReadFile(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte("identity-never-write-clear")) || bytes.Contains(contents, []byte("pinned-secret")) {
			t.Fatal("cleartext identity or secret on disk")
		}
	}
	opts.Create = false
	reopened, err := Open(ctx, path, opts, bytes.Clone(key))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	read, err = reopened.ReadResolverMigration(ctx, n.ID, 2)
	if err != nil || !reflect.DeepEqual(read, plan) {
		t.Fatal("lost plan on reopen", err)
	}
	var decisions []resolver.MigrationDecision
	for _, entry := range plan.Entries {
		decisions = append(decisions, resolver.MigrationDecision{NodeID: n.ID, ProtocolPath: entry.Legacy.ProtocolPath, Choice: "new"})
	}
	changed, err := reopened.DecideResolverMigration(ctx, n.ID, 2, plan.Fingerprint, decisions)
	if err != nil || changed.RowVersion != 3 {
		t.Fatal(err)
	}
	if _, err := reopened.DecideResolverMigration(ctx, n.ID, 2, plan.Fingerprint, decisions); err != vaultstore.ErrConflict {
		t.Fatal("lost-update check bypassed", err)
	}
	if err := reopened.DeleteCredential(ctx, c.ID, 2); err != nil {
		t.Fatal("inactive pin still blocks deletion", err)
	}
	if _, err := reopened.DecideResolverMigration(ctx, n.ID, 3, plan.Fingerprint, []resolver.MigrationDecision{{NodeID: n.ID, ProtocolPath: "ssh", Choice: "keep"}}); err != vaultstore.ErrMissing {
		t.Fatal("restored a pin to a deleted credential", err)
	}
	if current, err := reopened.ReadNode(ctx, n.ID, 3); err != nil || current.RowVersion != 3 {
		t.Fatal("failed choice partially updated node", err)
	}
	if err := reopened.DeleteNode(ctx, n.ID, 3); err != nil {
		t.Fatal("three-field deletion failed", err)
	}
	deleted, err := reopened.store.(vaultstore.NodeStore).ReadNode(ctx, n.ID)
	if err != nil || !deleted.Deleted || len(deleted.Fields) != 3 {
		t.Fatal(err)
	}
	for _, field := range deleted.Fields {
		if field.Present {
			t.Fatal("deleted field remains live")
		}
	}
	if _, err := reopened.ReadResolverMigration(ctx, n.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
}

func TestResolverMigrationValidationAndAtomicFailures(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	for _, expected := range []uint64{0, 2} {
		if _, err := o.ImportResolverMigration(ctx, n.ID, plan, expected); err != vaultstore.ErrConflict {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*resolver.MigrationPlan){
		func(p *resolver.MigrationPlan) { p.Version++ },
		func(p *resolver.MigrationPlan) { p.WorkspaceID = uuid.NewString() },
		func(p *resolver.MigrationPlan) { p.Entries = nil },
		func(p *resolver.MigrationPlan) {
			for i := range p.Entries {
				p.Entries[i].Legacy.NodeID = uuid.NewString()
			}
		},
	} {
		bad := plan
		bad.Entries = append([]resolver.MigrationEntry{}, plan.Entries...)
		mutate(&bad)
		if _, err := o.ImportResolverMigration(ctx, n.ID, bad, 1); err == nil {
			t.Fatal("bad plan accepted")
		}
	}
	folder := nodeDraft()
	folder.Kind = 0
	if _, err := o.PutNode(ctx, folder, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, folder.ID, plan, 1); err != resolver.ErrMigration {
		t.Fatal(err)
	}
	if _, err := o.ReadResolverMigration(ctx, n.ID, 2); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if _, err := o.ReadResolverMigration(ctx, uuid.NewString(), 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	failure := errors.New("synthetic write failure")
	o.store = nodeFilter{completeNodeStore: store, writeErr: failure}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != failure {
		t.Fatal(err)
	}
	o.store = store
	if current, err := o.ReadNode(ctx, n.ID, 1); err != nil || current.RowVersion != 1 || len(current.Fields) != 2 {
		t.Fatal("partial pin write", err)
	}
	if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err != vaultstore.ErrMissing {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != nil {
		t.Fatal(err)
	}
	for _, choices := range [][]resolver.MigrationDecision{{{NodeID: n.ID, ProtocolPath: "ssh", Choice: "new"}, {NodeID: n.ID, ProtocolPath: "ssh", Choice: "keep"}}, {{NodeID: n.ID, ProtocolPath: "vnc", Choice: "new"}}} {
		if _, err := o.DecideResolverMigration(ctx, n.ID, 2, plan.Fingerprint, choices); err != resolver.ErrMigration {
			t.Fatal(err)
		}
	}
	if _, err := o.DecideResolverMigration(ctx, n.ID, 2, strings.Repeat("0", 64), nil); err != resolver.ErrMigrationStale {
		t.Fatal(err)
	}
	if current, err := o.ReadNode(ctx, n.ID, 2); err != nil || current.RowVersion != 2 {
		t.Fatal("partial choice mutation", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := o.ReadResolverMigration(cancelled, n.ID, 0); err == nil {
		t.Fatal("canceled read")
	}
	if err := o.DeleteCredential(cancelled, c.ID, c.RowVersion); err == nil {
		t.Fatal("canceled delete")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err != vaultstore.ErrClosed {
		t.Fatal(err)
	}
}

func TestResolverMigrationAuthenticatesManifestAndEncryptedRecord(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	for _, mutate := range []func(vaultstore.Credential) (vaultstore.Credential, error){
		func(c vaultstore.Credential) (vaultstore.Credential, error) { c.ID = uuid.NewString(); return c, nil },
		func(c vaultstore.Credential) (vaultstore.Credential, error) { c.Username = "tampered"; return c, nil },
		func(c vaultstore.Credential) (vaultstore.Credential, error) { return c, vaultstore.ErrMissing },
	} {
		o.store = nodeFilter{completeNodeStore: store, credential: mutate}
		if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err == nil {
			t.Fatal("unverified pinned credential")
		}
	}
	o.store = store
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(vaultstore.Node) (vaultstore.Node, error){
		func(n vaultstore.Node) (vaultstore.Node, error) { n.ID = uuid.NewString(); return n, nil },
		func(n vaultstore.Node) (vaultstore.Node, error) { n.Fields = n.Fields[:2]; return n, nil },
	} {
		o.store = nodeFilter{completeNodeStore: store, read: mutate}
		if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err == nil {
			t.Fatal("unauthenticated manifest")
		}
	}
	for _, mutate := range []func(vaultstore.Secret) (vaultstore.Secret, error){
		func(s vaultstore.Secret) (vaultstore.Secret, error) { return s, vaultstore.ErrMissing },
		func(s vaultstore.Secret) (vaultstore.Secret, error) { s.Ref.OwnerID = uuid.NewString(); return s, nil },
		func(s vaultstore.Secret) (vaultstore.Secret, error) {
			s.Envelope.Ciphertext = bytes.Clone(s.Envelope.Ciphertext)
			s.Envelope.Ciphertext[0] ^= 1
			return s, nil
		},
	} {
		o.store = nodeFilter{completeNodeStore: store, secret: mutate}
		if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err == nil {
			t.Fatal("unauthenticated pin data")
		}
		if err := o.DeleteCredential(ctx, c.ID, 1); err == nil {
			t.Fatal("invalid pin allowed credential deletion")
		}
	}
	o.store = store
	o.nodeFloors[n.ID] = 3
	if _, err := o.ReadResolverMigration(ctx, n.ID, 0); err != vault.ErrRollback {
		t.Fatal(err)
	}
	if err := o.DeleteCredential(ctx, c.ID, 1); err == nil {
		t.Fatal("rolled-back node allowed deletion")
	}
}

func TestResolverMigrationReferenceScanCrossesPagesAndRejectsBadLists(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	for i := 1; i <= 128; i++ {
		m := nodeDraft()
		m.ID = fmt.Sprintf("%08x-0000-4000-8000-000000000001", i)
		if _, err := o.PutNode(ctx, m, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 1); err != nil {
		t.Fatal(err)
	}
	store := o.store.(completeNodeStore)
	defer func() { o.store = store }()
	pages := 0
	o.store = nodeFilter{completeNodeStore: store, list: func(nodes []vaultstore.Node) ([]vaultstore.Node, error) { pages++; return nodes, nil }}
	if err := o.DeleteCredential(ctx, c.ID, 1); err != vaultstore.ErrConflict || pages != 2 {
		t.Fatal("missed pin on later page", pages, err)
	}
	for _, mutate := range []func([]vaultstore.Node) ([]vaultstore.Node, error){
		func(ns []vaultstore.Node) ([]vaultstore.Node, error) { return ns, vaultstore.ErrStorage },
		func(ns []vaultstore.Node) ([]vaultstore.Node, error) { ns[0].Name = "tampered"; return ns, nil },
		func(ns []vaultstore.Node) ([]vaultstore.Node, error) { return append(ns[:1], ns[0]), nil },
	} {
		o.store = nodeFilter{completeNodeStore: store, list: mutate}
		if err := o.DeleteCredential(ctx, c.ID, 1); err == nil {
			t.Fatal("invalid list allowed credential deletion")
		}
	}
}

func TestResolverMigrationRejectsAuthenticatedMalformedPayload(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"invalid", "unknown", "duplicate", "oversized", "wrong-node"} {
		t.Run(kind, func(t *testing.T) {
			o, _, _, _ := owner(t)
			n, _, plan := nodeMigrationFixture(t, o)
			encoded, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "invalid":
				encoded = []byte("null")
			case "unknown":
				encoded = append([]byte(`{"unknown":true,`), encoded[1:]...)
			case "duplicate":
				encoded = append([]byte(`{"version":1,`), encoded[1:]...)
			case "oversized":
				encoded = bytes.Repeat([]byte(" "), 256*1024+1)
			case "wrong-node":
				for i := range plan.Entries {
					plan.Entries[i].Legacy.NodeID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
					plan.Entries[i].Candidate.NodeID = plan.Entries[i].Legacy.NodeID
					plan.Entries[i].Candidate.CredentialID = plan.Entries[i].Legacy.NodeID
				}
				encoded, _ = json.Marshal(plan)
			}
			// A valid AEAD/manifest does not excuse a malformed domain payload.
			if _, err := o.writeNode(ctx, n.NodeMetadata, []SecretChange{{Field: vaultstore.NodeResolverMigrationField, Value: encoded}}, 1, false, nil); err != nil {
				t.Fatal(err)
			}
			if got, err := o.ReadResolverMigration(ctx, n.ID, 0); err != resolver.ErrMigration || !reflect.DeepEqual(got, resolver.MigrationPlan{}) {
				t.Fatal("malformed authenticated plan returned", err)
			}
		})
	}
}

func TestResolverMigrationNodeTreeDeletionRetiresAllFields(t *testing.T) {
	ctx := context.Background()
	o, _, _, _ := owner(t)
	n, c, plan := nodeMigrationFixture(t, o)
	folder := nodeDraft()
	folder.Kind = 0
	if _, err := o.PutNode(ctx, folder, nil, 0); err != nil {
		t.Fatal(err)
	}
	n.ParentID = &folder.ID
	if _, err := o.PutNode(ctx, n.NodeMetadata, nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ImportResolverMigration(ctx, n.ID, plan, 2); err != nil {
		t.Fatal(err)
	}
	if count, err := o.DeleteNodeTree(ctx, folder.ID, 1); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	deleted, err := o.store.(vaultstore.NodeStore).ReadNode(ctx, n.ID)
	if err != nil || !deleted.Deleted || len(deleted.Fields) != 3 {
		t.Fatal(err)
	}
	for _, field := range deleted.Fields {
		stored, err := o.store.ReadSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: n.ID, Field: field.Field})
		if err != nil || field.Present || stored.RowVersion != field.Version || len(stored.Envelope.Ciphertext) != 16 {
			t.Fatal("incomplete subtree retirement", err)
		}
	}
	if err := o.DeleteCredential(ctx, c.ID, 1); err != nil {
		t.Fatal("deleted pin still blocks credential", err)
	}
}
