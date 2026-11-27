package main

import (
	"context"
	"math"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

type sharedChangesSession interface {
	ChangesSince(context.Context, uint64, uint64) (*sharedpg.CatalogChanges, error)
}

// CatalogChanges authenticates the owner and publishes any newer account trust
// before returning invalidation hints. It does not authorize use of node data.
func (c *sharedAdmissionController) CatalogChanges(ctx context.Context, epoch, since uint64) (*sharedpg.CatalogChanges, error) {
	if ctx == nil || epoch > math.MaxInt64 || since > math.MaxInt64 || (epoch == 0 && since != 0) {
		return nil, sharedpg.ErrConfiguration
	}
	session, ok := c.session.(sharedChangesSession)
	if !ok {
		return nil, sharedpg.ErrConfiguration
	}
	var result *sharedpg.CatalogChanges
	err := c.withCatalogTrust(ctx, func(ctx context.Context, _ sharedpg.TrustState, _ *sharedpg.TrustState) error {
		changes, err := session.ChangesSince(ctx, epoch, since)
		if err != nil {
			return err
		}
		if changes == nil || changes.Epoch == 0 || changes.Epoch > math.MaxInt64 || changes.ChangeSeq > math.MaxInt64 ||
			changes.Epoch < epoch || (changes.Epoch == epoch && changes.ChangeSeq < since) ||
			(changes.Epoch != epoch && !changes.Reset) || len(changes.Nodes) > sharedpg.MaxTreePage ||
			(len(changes.Nodes) != 0 && (changes.Reset || (changes.Epoch == epoch && changes.ChangeSeq == since))) {
			return sharedpg.ErrAdmissionResponse
		}
		previous := ""
		for _, id := range changes.Nodes {
			if id == uuid.Nil || id.String() <= previous {
				return sharedpg.ErrAdmissionResponse
			}
			previous = id.String()
		}
		result = &sharedpg.CatalogChanges{Epoch: changes.Epoch, ChangeSeq: changes.ChangeSeq, Reset: changes.Reset, Nodes: append([]uuid.UUID(nil), changes.Nodes...)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
