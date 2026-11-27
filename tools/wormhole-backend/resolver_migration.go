package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

func prepareLegacyResolverMigration(ctx context.Context, database *sql.DB, workspaceID string) (resolver.MigrationPlan, error) {
	baseline, err := captureLegacyResolverBaseline(ctx, database)
	if err != nil {
		return resolver.MigrationPlan{}, err
	}
	return resolver.BuildMigration(workspaceID, baseline.Snapshots, baseline.Candidates)
}

// Recheck immediately before native migration work while reserving the source
// writer lock. apply receives the current source reader and coherent metadata;
// it must use that reader, not reenter the pool, or publish before import/pin sealing
// and its recovery journal are complete. No source rows are written here.
// A plan fingerprint is a drift check, not authentication or full-content hash.
func withLegacyResolverMigration(ctx context.Context, database *sql.DB, workspaceID string, plan resolver.MigrationPlan, apply func(resolverCaptureReader, legacyResolverBaseline) error) (resultErr error) {
	if database == nil || apply == nil || plan.Validate() != nil || plan.WorkspaceID != workspaceID {
		return resolver.ErrMigration
	}
	return withReservedLegacySource(ctx, database, func(reader resolverCaptureReader) error {
		baseline, err := readLegacyResolverBaseline(reader)
		if err != nil {
			return err
		}
		if err := plan.Recheck(workspaceID, baseline.Snapshots, baseline.Candidates); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return errResolverSnapshot
		}
		return apply(reader, baseline)
	})
}

// Share one reserved, read-only source view across copy and retirement. A native
// retirement journal changes the destination only; the legacy SQL rows stay
// intact until the final database cutover.
func withReservedLegacySource(ctx context.Context, database *sql.DB, apply func(resolverCaptureReader) error) (resultErr error) {
	if database == nil || apply == nil {
		return errResolverSnapshot
	}
	connection, release, err := resolverObservationConnection(ctx, database)
	if err != nil {
		return err
	}
	defer release()
	var queryOnly int
	if connection.QueryRowContext(ctx, "PRAGMA query_only;").Scan(&queryOnly) != nil {
		return errResolverSnapshot
	}
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE;"); err != nil {
		// The driver can report cancellation after SQLite has executed BEGIN.
		// Its transaction state is ambiguous; Close alone would recycle it.
		_ = connection.Raw(func(any) error { return driver.ErrBadConn })
		return errResolverSnapshot
	}
	defer func() {
		_, rollbackErr := connection.ExecContext(context.Background(), "ROLLBACK;")
		_, restoreErr := connection.ExecContext(context.Background(), "PRAGMA query_only="+strconv.Itoa(queryOnly)+";")
		if rollbackErr != nil || restoreErr != nil {
			// Never put a connection with an indeterminate transaction back in the
			// caller's pool. The native destination remains subject to its journal.
			_ = connection.Raw(func(any) error { return driver.ErrBadConn })
			if resultErr == nil {
				resultErr = errResolverSnapshot
			}
		}
	}()
	if _, err := connection.ExecContext(ctx, "PRAGMA query_only=ON;"); err != nil {
		return errResolverSnapshot
	}
	reader := resolverCaptureReader{ctx, connection}
	if ctx.Err() != nil {
		return errResolverSnapshot
	}
	if err := apply(reader); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errResolverSnapshot
	}
	return nil
}
