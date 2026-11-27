package sharedpg

import (
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// AdvanceBoundary authenticates against the independently pinned organisation,
// not a signer chosen by the response. Persist any nonzero state even on error,
// especially inactive manifests or escrow-policy conflicts. Root-version floors
// are separate from the manifest revision, preventing a newer manifest from
// silently rolling an already observed current root back to an older version.
func (s TrustState) AdvanceBoundary(expected uuid.UUID, m vault.BoundaryManifest) (TrustState, error) {
	if !s.valid() || expected == uuid.Nil {
		return TrustState{}, ErrTrustState
	}
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	key := "boundary/" + expected.String()
	if err = vault.VerifyBoundaryManifest(m, vault.BoundaryTrust{WorkspaceID: s.WorkspaceID, BoundaryID: expected, Signer: pin.Signer, Organisation: pin.Organisation, MinimumRevision: s.Catalog[key].Revision}); err != nil {
		return cloneTrustState(s), err
	}
	entries := []catalogFloorObservation{{key, m.Revision, m}}
	var resultErr error
	policy, _ := s.Policy()
	if !m.Active || (policy.OrgEscrow && !m.OrgEscrow) {
		resultErr = vault.ErrPolicy
	}
	for _, root := range []struct {
		kind  string
		value vault.BoundaryKey
	}{{"boundary-view", m.View}, {"boundary-secret", m.Secret}} {
		key := root.kind + "/" + expected.String()
		if uint64(root.value.Key.Version) < s.Catalog[key].Revision {
			resultErr = vault.ErrRollback
			continue
		}
		entries = append(entries, catalogFloorObservation{key, uint64(root.value.Key.Version), root.value})
	}
	// No user-author observation is supplied: this manifest is org-signed directly.
	return s.mergeCatalogObservations(vault.UserKeyState{}, CatalogFloor{}, 0, resultErr, entries...)
}
