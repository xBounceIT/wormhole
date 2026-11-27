package localvault

import (
	"context"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Renderer-safe projection. Identity snapshots and decrypted account names must
// stay inside the native owner; only IDs, change flags and choices leave it.
type ResolverMigrationReport struct {
	NodeID      string                     `json:"nodeId"`
	RowVersion  string                     `json:"rowVersion"`
	Fingerprint *string                    `json:"fingerprint"`
	Entries     []resolver.MigrationReport `json:"entries"`
}

func (o *Owner) ReadResolverMigrationReport(ctx context.Context, id string, expected uint64) (ResolverMigrationReport, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.migrationNode(ctx, id, 0)
	if err != nil {
		return ResolverMigrationReport{}, err
	}
	if n.RowVersion != expected {
		return ResolverMigrationReport{}, vaultstore.ErrConflict
	}
	result := ResolverMigrationReport{NodeID: id, RowVersion: strconv.FormatUint(n.RowVersion, 10), Entries: []resolver.MigrationReport{}}
	for _, field := range n.Fields {
		if field.Field != vaultstore.NodeResolverMigrationField || !field.Present {
			continue
		}
		plan, err := o.readResolverMigration(ctx, n)
		if err != nil {
			return ResolverMigrationReport{}, err
		}
		result.Entries, err = plan.Report()
		if err != nil {
			return ResolverMigrationReport{}, err
		}
		result.Fingerprint = &plan.Fingerprint
		break
	}
	return result, nil
}
