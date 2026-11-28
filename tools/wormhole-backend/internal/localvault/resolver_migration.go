package localvault

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// ImportResolverMigration accepts only this node's changed paths, encrypted and bound
// to the node's authenticated field manifest in the same transaction. The native
// importer must first recheck the complete plan against its reserved source and
// stage all imported nodes/secrets; this API does not authorize publication.
// The full-source fingerprint remains provenance, not a digest of this subset.
func (o *Owner) ImportResolverMigration(ctx context.Context, id string, plan resolver.MigrationPlan, expected uint64) (vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.migrationNode(ctx, id, 0)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if n.RowVersion != expected {
		return vaultstore.Node{}, vaultstore.ErrConflict
	}
	if !validNodeMigration(plan, o.store.Identity().WorkspaceID, id) {
		return vaultstore.Node{}, resolver.ErrMigration
	}
	for _, f := range n.Fields {
		if f.Field == vaultstore.NodeResolverMigrationField {
			return vaultstore.Node{}, vaultstore.ErrConflict
		}
	}
	return o.writeResolverMigration(ctx, n, plan, &ImportTimes{CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt})
}

// ReadResolverMigration returns native identity metadata, never a renderer DTO.
// A report must use MigrationPlan.Report to project IDs and flags only.
func (o *Owner) ReadResolverMigration(ctx context.Context, id string, minimum uint64) (resolver.MigrationPlan, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.migrationNode(ctx, id, minimum)
	if err != nil {
		return resolver.MigrationPlan{}, err
	}
	return o.readResolverMigration(ctx, n)
}

// DecideResolverMigration changes only existing path choices. The node revision
// prevents lost updates even when two choices share the same source fingerprint.
func (o *Owner) DecideResolverMigration(ctx context.Context, id string, expected uint64, fingerprint string, choices []resolver.MigrationDecision) (vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.migrationNode(ctx, id, 0)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if n.RowVersion != expected {
		return vaultstore.Node{}, vaultstore.ErrConflict
	}
	plan, err := o.readResolverMigration(ctx, n)
	if err != nil {
		return vaultstore.Node{}, err
	}
	plan, err = plan.Decide(fingerprint, choices)
	if err != nil {
		return vaultstore.Node{}, err
	}
	return o.writeResolverMigration(ctx, n, plan, nil)
}

func (o *Owner) migrationNode(ctx context.Context, id string, minimum uint64) (vaultstore.Node, error) {
	s, err := o.nodeStore()
	if err != nil {
		return vaultstore.Node{}, err
	}
	n, err := s.ReadNode(ctx, id)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if n.ID != id {
		return vaultstore.Node{}, vault.ErrAuthentication
	}
	if err := o.verifyNode(n); err != nil {
		return vaultstore.Node{}, err
	}
	if n.RowVersion < minimum || n.RowVersion < o.nodeFloors[id] {
		return vaultstore.Node{}, vault.ErrRollback
	}
	if n.Deleted {
		return vaultstore.Node{}, vaultstore.ErrMissing
	}
	if n.Kind != 1 {
		return vaultstore.Node{}, resolver.ErrMigration
	}
	return n, nil
}

func validNodeMigration(plan resolver.MigrationPlan, workspace, node string) bool {
	if len(plan.Entries) == 0 || len(plan.Entries) > 3 || plan.Validate() != nil || plan.WorkspaceID != workspace {
		return false
	}
	for _, entry := range plan.Entries {
		if entry.Legacy.NodeID != node {
			return false
		}
	}
	return true
}

func (o *Owner) readResolverMigration(ctx context.Context, n vaultstore.Node) (resolver.MigrationPlan, error) {
	var plan resolver.MigrationPlan
	for _, f := range n.Fields {
		if f.Field != vaultstore.NodeResolverMigrationField || !f.Present {
			continue
		}
		err := o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: n.ID, Field: f.Field}, f.Version, true, func(value []byte) error {
			if len(value) > 256*1024 || json.Unmarshal(value, &plan) != nil || !validNodeMigration(plan, o.store.Identity().WorkspaceID, n.ID) {
				return resolver.ErrMigration
			}
			canonical, _ := json.Marshal(plan)
			defer vault.Wipe(canonical)
			if !bytes.Equal(canonical, value) {
				return resolver.ErrMigration
			}
			return nil
		})
		if err != nil {
			return resolver.MigrationPlan{}, err
		}
		return plan, nil
	}
	return resolver.MigrationPlan{}, vaultstore.ErrMissing
}

func (o *Owner) writeResolverMigration(ctx context.Context, n vaultstore.Node, plan resolver.MigrationPlan, times *ImportTimes) (vaultstore.Node, error) {
	if !validNodeMigration(plan, o.store.Identity().WorkspaceID, n.ID) {
		return vaultstore.Node{}, resolver.ErrMigration
	}
	for _, entry := range plan.Entries {
		if entry.Choice != "keep" || entry.Legacy.SourceKind != "saved" {
			continue
		}
		s, err := o.credentialStore()
		if err != nil {
			return vaultstore.Node{}, err
		}
		c, err := s.ReadCredential(ctx, entry.Legacy.CredentialID)
		if err != nil {
			return vaultstore.Node{}, err
		}
		if c.ID != entry.Legacy.CredentialID {
			return vaultstore.Node{}, vault.ErrAuthentication
		}
		if err := o.verifyCredential(c); err != nil {
			return vaultstore.Node{}, err
		}
		if c.Deleted {
			return vaultstore.Node{}, vaultstore.ErrMissing
		}
	}
	value, err := json.Marshal(plan)
	if err != nil {
		return vaultstore.Node{}, resolver.ErrMigration
	}
	defer vault.Wipe(value)
	return o.writeNode(ctx, n.NodeMetadata, []SecretChange{{Field: vaultstore.NodeResolverMigrationField, Value: value}}, n.RowVersion, false, times)
}

// Native credential mutations cannot invalidate a retained migration choice.
// IDs inside the encrypted record are not usable as a plaintext SQL index.
func (o *Owner) checkMigrationCredentialReferences(ctx context.Context, id string) error {
	s, ok := o.store.(vaultstore.NodeStore)
	if !ok {
		return nil
	} // A store without nodes cannot hold migration records.
	after := ""
	for {
		nodes, err := s.ListNodes(ctx, after, 128)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := o.verifyNode(n); err != nil {
				return err
			}
			if n.ID <= after || n.Deleted || n.RowVersion < o.nodeFloors[n.ID] {
				return vault.ErrAuthentication
			}
			after = n.ID
			for _, f := range n.Fields {
				if f.Field != vaultstore.NodeResolverMigrationField || !f.Present {
					continue
				}
				plan, err := o.readResolverMigration(ctx, n)
				if err != nil {
					return err
				}
				for _, entry := range plan.Entries {
					if entry.Choice == "keep" && entry.Legacy.SourceKind == "saved" && entry.Legacy.CredentialID == id {
						return vaultstore.ErrConflict
					}
				}
			}
		}
		if len(nodes) < 128 {
			return nil
		}
	}
}
