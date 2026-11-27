package localvault

import (
	"context"
	"encoding/json"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// DuplicateConnection creates a fresh identity and key graph in one aggregate
// transaction. The source's plaintext is borrowed only inside this native owner;
// neither encrypted records nor decrypted fields are a renderer result.
func (o *Owner) DuplicateConnection(ctx context.Context, id string, expected uint64) (vaultstore.Node, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.migrationNode(ctx, id, 0)
	if err != nil {
		return vaultstore.Node{}, err
	}
	if expected == 0 || expected >= math.MaxInt64 || n.RowVersion != expected {
		return vaultstore.Node{}, vaultstore.ErrConflict
	}
	s, err := o.nodeStore()
	if err != nil {
		return vaultstore.Node{}, err
	}
	// Authenticate the exact siblings used to allocate an append position. The
	// paginated scan also checks observed revisions, with the app's catalog bound.
	pending := map[string]uint64{}
	after := ""
	maximum := n.SortOrder
	found := false
	for {
		page, err := s.ListNodes(ctx, after, 128)
		if err != nil {
			return vaultstore.Node{}, err
		}
		if len(page) > 128 {
			return vaultstore.Node{}, vault.ErrFormat
		}
		if len(page) == 0 {
			break
		}
		for _, v := range page {
			if v.ID <= after || len(pending) >= 50000 {
				return vaultstore.Node{}, vault.ErrFormat
			}
			if err := o.verifyNode(v); err != nil {
				return vaultstore.Node{}, err
			}
			if v.Deleted || v.RowVersion < o.nodeFloors[v.ID] {
				return vaultstore.Node{}, vault.ErrRollback
			}
			pending[v.ID] = v.RowVersion
			after = v.ID
			if v.ID == id {
				if v.RowVersion != expected {
					return vaultstore.Node{}, vaultstore.ErrConflict
				}
				found = true
			}
			sameParent := (v.ParentID == nil && n.ParentID == nil) || (v.ParentID != nil && n.ParentID != nil && *v.ParentID == *n.ParentID)
			if sameParent && v.SortOrder > maximum {
				maximum = v.SortOrder
			}
		}
	}
	if !found {
		return vaultstore.Node{}, vault.ErrAuthentication
	}
	if maximum == math.MaxInt64 || len(pending) >= 50000 {
		return vaultstore.Node{}, vaultstore.ErrConflict
	}
	metadata := n.NodeMetadata
	metadata.ID = uuid.NewString()
	name := []rune(n.Name)
	if len(name) > 249 {
		name = name[:249]
	}
	metadata.Name = string(name) + " (copy)"
	metadata.SortOrder = maximum + 1
	metadata.SshKnownHostFingerprint = nil
	changes := []SecretChange{}
	defer func() {
		for _, change := range changes {
			vault.Wipe(change.Value)
		}
	}()
	for _, field := range n.Fields {
		if !field.Present {
			continue
		}
		if field.Field == vaultstore.NodeResolverMigrationField {
			plan, err := o.readResolverMigration(ctx, n)
			if err != nil {
				return vaultstore.Node{}, err
			}
			for i := range plan.Entries {
				entry := &plan.Entries[i]
				if entry.Choice == "keep" && entry.Legacy.SourceKind == "saved" {
					if _, err := o.resolutionCredential(ctx, entry.Legacy.CredentialID, ""); err != nil {
						return vaultstore.Node{}, err
					}
				}
				entry.Legacy.NodeID, entry.Candidate.NodeID = metadata.ID, metadata.ID
				if entry.Legacy.SourceKind == "inline" {
					entry.Legacy.CredentialID = metadata.ID
				}
				if entry.Candidate.SourceKind == "inline" {
					entry.Candidate.CredentialID = metadata.ID
				}
			}
			// Fingerprint is the original full-source provenance, not a digest of this
			// per-node subset. Retain it along with every explicit keep/new decision.
			if !validNodeMigration(plan, s.Identity().WorkspaceID, metadata.ID) {
				return vaultstore.Node{}, vault.ErrFormat
			}
			encoded, err := json.Marshal(plan)
			if err != nil {
				return vaultstore.Node{}, vault.ErrFormat
			}
			changes = append(changes, SecretChange{Field: field.Field, Value: encoded})
			continue
		}
		err := o.withSecret(ctx, vaultstore.SecretRef{OwnerKind: "node", OwnerID: id, Field: field.Field}, field.Version, true, func(value []byte) error {
			changes = append(changes, SecretChange{Field: field.Field, Value: append([]byte{}, value...)})
			return nil
		})
		if err != nil {
			return vaultstore.Node{}, err
		}
	}
	result, err := o.writeNode(ctx, metadata, changes, 0, false, nil)
	if err != nil {
		return vaultstore.Node{}, err
	}
	for id, revision := range pending {
		o.nodeFloors[id] = revision
	}
	return result, nil
}
