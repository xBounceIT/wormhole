package sharedpg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"strings"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxCatalogFloors = 8192

var ErrCatalogEquivocation = errors.New("catalog record changed without a revision advance")

type CatalogFloor struct {
	Revision uint64 `json:"revision"`
	Digest   []byte `json:"digest"`
}

func validCatalogFloors(floors map[string]CatalogFloor) bool {
	if len(floors) > MaxCatalogFloors {
		return false
	}
	for key, floor := range floors {
		parts := strings.Split(key, "/")
		if len(parts) < 2 || len(parts) > 5 || floor.Revision == 0 || floor.Revision > math.MaxInt64 || len(floor.Digest) != sha256.Size {
			return false
		}
		if _, ok := treeID([]byte(parts[1])); !ok {
			return false
		}
		switch parts[0] {
		case "author", "node", "node-fields", "tunnel", "credential", "slot", "boundary":
			if len(parts) != 2 {
				return false
			}
		case "boundary-view", "boundary-secret", "group-key":
			if len(parts) != 2 || floor.Revision > math.MaxInt32 {
				return false
			}
		case "slot-value", "override":
			if len(parts) != 3 {
				return false
			}
			if _, ok := treeID([]byte(parts[2])); !ok {
				return false
			}
		case "enrollment":
			if len(parts) != 5 {
				return false
			}
			if _, ok := treeNumber([]byte(parts[2]), 1, math.MaxInt32); !ok {
				return false
			}
			if _, ok := treeID([]byte(parts[3])); !ok {
				return false
			}
			if _, ok := treeNumber([]byte(parts[4]), 1, math.MaxInt32); !ok {
				return false
			}
		case "key":
			if len(parts) != 3 {
				return false
			}
			if _, ok := treeNumber([]byte(parts[2]), 1, math.MaxInt32); !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func cloneCatalogFloors(floors map[string]CatalogFloor) map[string]CatalogFloor {
	if floors == nil {
		return nil
	}
	copy := make(map[string]CatalogFloor, len(floors))
	for key, value := range floors {
		value.Digest = bytes.Clone(value.Digest)
		copy[key] = value
	}
	return copy
}

func catalogFloorsAdvance(previous, next map[string]CatalogFloor) bool {
	for key, old := range previous {
		value, ok := next[key]
		if !ok || value.Revision < old.Revision || ((value.Revision == old.Revision || strings.HasPrefix(key, "enrollment/")) && !bytes.Equal(value.Digest, old.Digest)) {
			return false
		}
	}
	return true
}

// AdvanceCatalog authenticates before recording any floor. A nonzero returned
// TrustState must be durably persisted even alongside a verification error,
// because it may contain a newly observed revocation. Only err==nil permits the
// owner to publish the metadata, and only after persistence succeeds.
func (s TrustState) AdvanceCatalog(node UnverifiedTreeNode, author UnverifiedNodeAuthor) (TrustState, error) {
	if !s.valid() || author.State == nil {
		return TrustState{}, ErrTrustState
	}
	pin, err := s.accountTrust()
	if err != nil {
		return TrustState{}, err
	}
	id, err := uuid.Parse(node.Metadata.ID)
	if err != nil || id == uuid.Nil {
		return TrustState{}, ErrAdmissionResponse
	}
	m := s.catalogAuthorMaterial(author)
	nodeKey := "node/" + id.String()
	authorFloor := s.catalogAuthorFloor(author.State.UserID)
	observed, verifyErr := node.VerifyCurrentMetadata(m.certificate, *author.State, sharedcatalog.CurrentNodeTrust{Workspace: s.WorkspaceID, Node: id, Boundary: node.Boundary, Author: author.State.UserID, OrganisationKey: pin.Signer, Organisation: pin.Organisation, MinimumStateSequence: authorFloor.Revision, MinimumCertificateRevision: m.minimum, MinimumNodeRevision: s.Catalog[nodeKey].Revision}, m.enrollment...)
	return s.mergeCatalogAuthor(author, m, authorFloor, observed.StateSequence, observed.CertificateRevision, verifyErr,
		catalogFloorObservation{nodeKey, observed.NodeRevision, node.Seal})
}

func (s TrustState) catalogAuthorFloor(author uuid.UUID) CatalogFloor {
	floor := s.Catalog["author/"+author.String()]
	if s.Account != nil && author == s.UserID && s.Account.Sequence >= floor.Revision {
		raw, _ := json.Marshal(s.Account)
		digest := sha256.Sum256(raw)
		floor = CatalogFloor{s.Account.Sequence, digest[:]}
	}
	return floor
}

type catalogFloorObservation struct {
	key      string
	revision uint64
	value    any
}

// Both node and credential observations use the same durable advancement rules.
func (s TrustState) mergeCatalogObservations(state vault.UserKeyState, authorFloor CatalogFloor, stateSequence uint64, verifyErr error, entries ...catalogFloorObservation) (TrustState, error) {
	var err error
	authorKey := "author/" + state.UserID.String()
	next := cloneTrustState(s)
	changed := false
	// An observation about the logged-in account must also advance the unlock
	// anchor, otherwise a later login could ignore a revocation learned here.
	if stateSequence > 0 && s.Account != nil && state.UserID == s.UserID {
		next, err = s.AdvanceAccount(state, s.WrappingRevision)
		if err != nil {
			return TrustState{}, err
		}
		changed = next.Revision != s.Revision
		next.Revision = s.Revision
	}
	if next.Catalog == nil {
		next.Catalog = make(map[string]CatalogFloor)
	}
	finish := func(resultErr error) (TrustState, error) {
		if !changed {
			return cloneTrustState(s), resultErr
		}
		if next.Revision == math.MaxUint64 || !validCatalogFloors(next.Catalog) {
			return TrustState{}, ErrTrustState
		}
		next.Revision++
		return next, resultErr
	}
	for _, entry := range entries {
		if entry.revision == 0 {
			continue
		}
		raw, e := json.Marshal(entry.value)
		if e != nil {
			return TrustState{}, ErrTrustState
		}
		digest := sha256.Sum256(raw)
		old := next.Catalog[entry.key]
		if entry.key == authorKey && authorFloor.Revision >= old.Revision {
			old = authorFloor
		}
		if strings.HasPrefix(entry.key, "enrollment/") {
			if old.Revision > entry.revision {
				return finish(ErrTrustRollback)
			}
			if old.Revision > 0 && !bytes.Equal(old.Digest, digest[:]) {
				return finish(ErrCatalogEquivocation)
			}
			next.FormatVersion = max(next.FormatVersion, 6)
		}
		if old.Revision == entry.revision {
			if !bytes.Equal(old.Digest, digest[:]) {
				return finish(ErrCatalogEquivocation)
			}
			continue
		}
		// Keep already authenticated account/author observations persistable even
		// when there is no capacity for a new record. Never evict an old floor.
		if _, exists := next.Catalog[entry.key]; !exists && len(next.Catalog) >= MaxCatalogFloors {
			return finish(ErrTrustState)
		}
		next.Catalog[entry.key] = CatalogFloor{entry.revision, bytes.Clone(digest[:])}
		changed = true
	}
	return finish(verifyErr)
}
