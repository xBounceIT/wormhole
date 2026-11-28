package sharedpg

import (
	"context"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// UnverifiedChainRecord contains a node and its current author material from the
// same server snapshot. Neither the record nor the resulting plan authorizes use.
type UnverifiedChainRecord struct {
	Node   UnverifiedTreeNode
	Author UnverifiedNodeAuthor
}

// ResolveCatalogChain authenticates every steering field before resolving the
// complete leaf-to-root chain. A nonzero returned trust state must be persisted
// even on error (it can contain a revocation). Publish the plan only after that
// persistence succeeds. Secret release additionally needs a committed use ticket,
// current permissions, authenticated credential/slot/key material and HPKE handoff.
func (s TrustState) ResolveCatalogChain(ctx context.Context, node uuid.UUID, chain []UnverifiedChainRecord, override string) (observed TrustState, plan resolver.Plan, err error) {
	return s.resolveCatalogChain(ctx, node, chain, override, false)
}

func (s TrustState) resolveCatalogChain(ctx context.Context, node uuid.UUID, chain []UnverifiedChainRecord, override string, resolveImport bool) (observed TrustState, plan resolver.Plan, err error) {
	if ctx == nil || node == uuid.Nil || len(chain) == 0 || len(chain) > vaultstore.MaxNodeDepth {
		return TrustState{}, resolver.Plan{}, ErrConfiguration
	}
	if !s.valid() || s.Account == nil || !s.Account.Active {
		return TrustState{}, resolver.Plan{}, ErrTrustState
	}
	if chain[0].Node.Metadata.ID != node.String() {
		return TrustState{}, resolver.Plan{}, ErrAdmissionResponse
	}
	changed := false
	defer func() {
		if observed.Revision != 0 && changed {
			// Publish one atomic trust update for the whole chain, including failures.
			observed.Revision = s.Revision + 1
		}
	}()
	next := cloneTrustState(s)
	metadata := make([]vaultstore.NodeMetadata, 0, len(chain))
	authors := make(map[uuid.UUID]uint64)
	inconsistent := false
	for _, record := range chain {
		if err := ctx.Err(); err != nil {
			return next, resolver.Plan{}, err
		}
		advanced, err := next.AdvanceCatalog(record.Node, record.Author)
		if advanced.Revision != 0 {
			changed = changed || advanced.Revision != next.Revision
			advanced.Revision = s.Revision
			next = advanced
		}
		if err != nil {
			return next, resolver.Plan{}, err
		}
		// Independently valid states from different moments are not a coherent chain.
		// Keep observing first, so a newer authenticated state is not discarded merely
		// because another record carried the previous state for that same author.
		// AdvanceCatalog already rejects differing signed states at equal sequence.
		user := record.Author.State.UserID
		if previous, ok := authors[user]; ok && previous != record.Author.State.Sequence {
			inconsistent = true
		}
		authors[user] = record.Author.State.Sequence
		metadata = append(metadata, record.Node.Metadata)
	}
	if err := ctx.Err(); err != nil {
		return next, resolver.Plan{}, err
	}
	if inconsistent {
		return next, resolver.Plan{}, ErrTreeSnapshotChanged
	}
	if next.Account.Signing != s.Account.Signing || next.Account.Encryption != s.Account.Encryption {
		return next, resolver.Plan{}, vault.ErrAuthentication
	}
	if resolveImport {
		plan, err = resolver.ResolveImportedCandidate(metadata, override)
	} else {
		plan, err = resolver.Resolve(metadata, override)
	}
	return next, plan, err
}
