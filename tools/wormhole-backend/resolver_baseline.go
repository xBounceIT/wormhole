package main

import (
	"context"
	"database/sql"
	"runtime"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

// Native metadata for migration planning, never a renderer DTO or a release
// capability. It describes one past database snapshot; applying migration pins
// must still bind/recheck the source state and authenticate all imported secrets.
type legacyResolverBaseline struct {
	Snapshots   []resolver.EffectiveCredentialSnapshot
	Candidates  []resolver.EffectiveCredentialSnapshot
	Differences []resolver.SnapshotDifference
}

func captureLegacyResolverBaseline(ctx context.Context, database *sql.DB) (legacyResolverBaseline, error) {
	if database == nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	connection, release, err := resolverObservationConnection(ctx, database)
	if err != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	defer release()
	tx, err := connection.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	defer tx.Rollback()
	result, err := readLegacyResolverBaseline(resolverCaptureReader{ctx, tx})
	if err != nil {
		return legacyResolverBaseline{}, err
	}
	if ctx.Err() != nil || tx.Commit() != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	return result, nil
}

func readLegacyResolverBaseline(reader resolverCaptureReader) (legacyResolverBaseline, error) {
	snapshots, err := readLegacyResolverSnapshots(reader)
	if err != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	candidates, err := resolveCapturedCandidates(reader, snapshots)
	if err != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	differences, err := resolverSnapshotDifferences(snapshots, candidates)
	if err != nil {
		return legacyResolverBaseline{}, errResolverSnapshot
	}
	return legacyResolverBaseline{Snapshots: snapshots, Candidates: candidates, Differences: differences}, nil
}

func compareCapturedResolverSnapshots(reader resolverCaptureReader, snapshots []resolver.EffectiveCredentialSnapshot) ([]resolver.SnapshotDifference, error) {
	candidates, err := resolveCapturedCandidates(reader, snapshots)
	if err != nil {
		return nil, err
	}
	return resolverSnapshotDifferences(snapshots, candidates)
}

func resolveCapturedCandidates(reader resolverCaptureReader, snapshots []resolver.EffectiveCredentialSnapshot) ([]resolver.EffectiveCredentialSnapshot, error) {
	candidates := make([]resolver.EffectiveCredentialSnapshot, 0, len(snapshots))
	for first := 0; first < len(snapshots); {
		last := first + 1
		for last < len(snapshots) && snapshots[last].NodeID == snapshots[first].NodeID {
			last++
		}
		group, err := candidateSnapshotsInTransaction(reader.ctx, reader.tx, snapshots[first:last], runtime.GOOS)
		if err != nil {
			return nil, errResolverSnapshot
		}
		candidates = append(candidates, group...)
		first = last
	}
	if reader.ctx.Err() != nil {
		return nil, errResolverSnapshot
	}
	return candidates, nil
}
