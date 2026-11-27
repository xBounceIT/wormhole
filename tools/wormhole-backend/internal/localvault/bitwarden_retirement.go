package localvault

import (
	"context"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const bitwardenMaxRetiredInstallations = 64

// Version three records carry only database-scoped retired IDs. Legacy shared
// directories are never inferred to belong to the current database. The journal
// is part of the same authenticated CAS as the active installation.
func (r bitwardenInstallationRecord) valid() bool {
	if !r.Installation.valid() || len(r.Retired) > bitwardenMaxRetiredInstallations {
		return false
	}
	if len(r.Retired) == 0 {
		return r.Version == 1+r.Installation.Layout
	}
	if r.Version != 3 {
		return false
	}
	seen := make(map[string]bool, len(r.Retired))
	for _, id := range r.Retired {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id || id == r.Installation.InstallationID || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// CleanupBitwardenInstallations requires prior action authorization. The native
// remover is called only for authenticated retired IDs, while the owner lock bars
// installation changes and profile/transfer admission. It must not call the owner.
// Partial deletion leaves the journal retryable. If the final CAS acknowledgement
// is lost, either record state is safe: all listed removals already succeeded.
func (o *Owner) CleanupBitwardenInstallations(ctx context.Context, expected uint64, remove func(context.Context, string) error) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if remove == nil {
		return 0, vault.ErrFormat
	}
	if o.bitwardenInstallationBusy() {
		return 0, vault.ErrPolicy
	}
	record, revision, err := o.readBitwardenInstallationRecord(ctx, expected)
	if err != nil {
		return 0, err
	}
	if revision != expected {
		return 0, vaultstore.ErrConflict
	}
	for _, id := range record.Retired {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		if err = remove(ctx, id); err != nil {
			return 0, err
		}
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	record.Retired = nil
	return o.writeBitwardenInstallationRecord(ctx, record, expected)
}
