package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

const resolverSnapshotSchema = `CREATE TABLE IF NOT EXISTS EffectiveCredentialSnapshot (
 NodeId TEXT NOT NULL,
 ProtocolPath TEXT NOT NULL CHECK (ProtocolPath IN ('ssh','sftp','vnc','rdp','rdp-gateway','reveal')),
 CredentialId TEXT NOT NULL,
 Username TEXT NOT NULL,
 Domain TEXT NOT NULL,
 SourceKind TEXT NOT NULL CHECK (SourceKind IN ('none','inline','saved','system')),
 ResolverVersion INTEGER NOT NULL CHECK (ResolverVersion=0),
 ObservedAtUtc TEXT NOT NULL,
 PRIMARY KEY (NodeId,ProtocolPath)
);`

var errResolverSnapshot = errors.New("resolver_snapshot_unavailable")

func legacyResolutionSnapshot(nodeID, path, credentialID, username, domain, source string) resolver.EffectiveCredentialSnapshot {
	return resolver.EffectiveCredentialSnapshot{NodeID: normalizeID(nodeID), ProtocolPath: path, CredentialID: normalizeID(credentialID), Username: username, Domain: domain, SourceKind: source, ResolverVersion: 0}
}

// Observation failures must not change a legacy connection's behavior. Runtime
// recording is bounded, metadata-only and does not create tables. A later full
// baseline/pinning transaction must require complete, fresh snapshots explicitly;
// these best-effort observations cannot certify that migration is safe.
func observeLegacyResolution(database *sql.DB, values ...resolver.EffectiveCredentialSnapshot) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if writeLegacyResolutionSnapshots(ctx, database, values) == nil {
		observeResolverShadow(ctx, database, values)
	}
}

func writeLegacyResolutionSnapshots(ctx context.Context, database *sql.DB, values []resolver.EffectiveCredentialSnapshot) error {
	if database == nil || len(values) == 0 || len(values) > 6 {
		return errResolverSnapshot
	}
	seen := map[string]bool{}
	for _, s := range values {
		key := s.NodeID + ":" + s.ProtocolPath
		if s.Validate() != nil || s.ResolverVersion != 0 || seen[key] {
			return errResolverSnapshot
		}
		seen[key] = true
	}
	connection, release, err := resolverObservationConnection(ctx, database)
	if err != nil {
		return errResolverSnapshot
	}
	defer release()
	// SQLite's busy handler can outlast a Go context deadline. Observations must
	// not wait on a database writer. Keep this pinned transaction alive until our
	// explicit rollback so cancellation cannot discard the connection before its
	// original busy policy is restored. Every statement still uses ctx.
	tx, err := connection.BeginTx(context.WithoutCancel(ctx), nil)
	if err != nil {
		return errResolverSnapshot
	}
	defer tx.Rollback()
	observed := time.Now().UTC().Format(time.RFC3339Nano)
	for _, s := range values {
		result, err := tx.ExecContext(ctx, `INSERT INTO EffectiveCredentialSnapshot(NodeId,ProtocolPath,CredentialId,Username,Domain,SourceKind,ResolverVersion,ObservedAtUtc) VALUES(?,?,?,?,?,?,0,?) ON CONFLICT(NodeId,ProtocolPath) DO UPDATE SET CredentialId=excluded.CredentialId,Username=excluded.Username,Domain=excluded.Domain,SourceKind=excluded.SourceKind,ResolverVersion=excluded.ResolverVersion,ObservedAtUtc=excluded.ObservedAtUtc;`, s.NodeID, s.ProtocolPath, s.CredentialID, s.Username, s.Domain, s.SourceKind, observed)
		if err != nil {
			return errResolverSnapshot
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errResolverSnapshot
		}
	}
	if ctx.Err() != nil {
		return errResolverSnapshot
	}
	if err := tx.Commit(); err != nil {
		return errResolverSnapshot
	}
	return nil
}

// Both the observation writer and shadow reader must skip SQLite lock waits.
// Their transactions use WithoutCancel plus explicit rollback so this connection
// remains usable until its original busy policy has been restored.
func resolverObservationConnection(ctx context.Context, database *sql.DB) (*sql.Conn, func(), error) {
	connection, err := database.Conn(ctx)
	if err != nil {
		return nil, nil, errResolverSnapshot
	}
	var busyTimeout int
	if err := connection.QueryRowContext(ctx, "PRAGMA busy_timeout;").Scan(&busyTimeout); err != nil {
		connection.Close()
		return nil, nil, errResolverSnapshot
	}
	if _, err := connection.ExecContext(ctx, "PRAGMA busy_timeout=0;"); err != nil {
		// A canceled statement may already have changed the connection policy.
		_ = connection.Raw(func(any) error { return driver.ErrBadConn })
		connection.Close()
		return nil, nil, errResolverSnapshot
	}
	return connection, func() {
		if _, err := connection.ExecContext(context.Background(), "PRAGMA busy_timeout="+strconv.Itoa(busyTimeout)+";"); err != nil {
			_ = connection.Raw(func(any) error { return driver.ErrBadConn })
		}
		connection.Close()
	}, nil
}

// Reveal deliberately retains its query-only reader. Its observation writer
// opens only an existing legacy file (mode=rw), never creates a missing database
// or a table, and closes immediately. It disappears with the single-owner cutover.
func observeLegacyResolutionPath(databasePath string, value resolver.EffectiveCredentialSnapshot) {
	if requireLegacyWorkspace(databasePath) != nil {
		return
	}
	absolute, err := filepath.Abs(databasePath)
	if err != nil {
		return
	}
	path := filepath.ToSlash(absolute)
	if filepath.VolumeName(absolute) != "" && path[0] != '/' {
		path = "/" + path
	}
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	database, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	observeLegacyResolution(database, value)
}

func observeLegacyReveal(databasePath string, nodeID, credentialID, source string, value workspaceCredentialRevealResponse) workspaceCredentialRevealResponse {
	observeLegacyResolutionPath(databasePath, legacyResolutionSnapshot(nodeID, "reveal", credentialID, value.Username, value.Domain, source))
	return value
}

func observeLegacyRDP(database *sql.DB, nodeID, credentialID string, inline bool, profile rdpProfile, settings workspaceRdpSettings) {
	observeLegacyResolution(database, legacyRDPSnapshots(nodeID, credentialID, inline, profile, settings)...)
}

func legacyRDPSnapshots(nodeID, credentialID string, inline bool, profile rdpProfile, settings workspaceRdpSettings) []resolver.EffectiveCredentialSnapshot {
	source, selected := "none", ""
	if profile.UseExternalClient {
		source = "system"
	} else if inline {
		source, selected = "inline", nodeID
	} else if credentialID != "" {
		source, selected = "saved", credentialID
	}
	main := legacyResolutionSnapshot(nodeID, "rdp", selected, profile.Username, profile.Domain, source)
	gateway := legacyResolutionSnapshot(nodeID, "rdp-gateway", "", profile.GatewayUsername, "", "none")
	if profile.UseExternalClient {
		gateway.SourceKind = "system"
	} else if settings.GatewayUsageMethod != 0 {
		if settings.GatewayUseSameCreds {
			gateway.SourceKind = source
			gateway.CredentialID = main.CredentialID
		} else if settings.GatewayCredentialID != "" {
			gateway.SourceKind = "saved"
			gateway.CredentialID = normalizeID(settings.GatewayCredentialID)
		}
	}
	return []resolver.EffectiveCredentialSnapshot{main, gateway}
}

// Compare against observations without returning account names to diagnostics.
// The caller still has to establish baseline freshness/completeness before a
// migration. Missing/corrupt rows reject the complete comparison, never a subset.
func compareLegacyResolutionSnapshots(ctx context.Context, database *sql.DB, next []resolver.EffectiveCredentialSnapshot) ([]resolver.SnapshotDifference, error) {
	if database == nil || len(next) == 0 || len(next) > 6 {
		return nil, errResolverSnapshot
	}
	seen := map[string]bool{}
	for _, s := range next {
		key := s.NodeID + ":" + s.ProtocolPath
		if s.Validate() != nil || s.ResolverVersion != resolver.Version || seen[key] {
			return nil, errResolverSnapshot
		}
		seen[key] = true
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errResolverSnapshot
	}
	defer tx.Rollback()
	differences := make([]resolver.SnapshotDifference, 0, len(next))
	for _, s := range next {
		old := resolver.EffectiveCredentialSnapshot{NodeID: s.NodeID, ProtocolPath: s.ProtocolPath}
		var notNull bool
		// BLOB slicing bounds bytes and preserves embedded NUL for validation;
		// SQLite text substr would silently hide everything after the first NUL.
		err := tx.QueryRowContext(ctx, `SELECT
 CAST(COALESCE(substr(CAST(CredentialId AS BLOB),1,37),X'') AS TEXT),
 CAST(COALESCE(substr(CAST(Username AS BLOB),1,2049),X'') AS TEXT),
 CAST(COALESCE(substr(CAST(Domain AS BLOB),1,2049),X'') AS TEXT),
 CAST(COALESCE(substr(CAST(SourceKind AS BLOB),1,7),X'') AS TEXT),
 ResolverVersion,CredentialId IS NOT NULL AND Username IS NOT NULL AND Domain IS NOT NULL AND SourceKind IS NOT NULL
 FROM EffectiveCredentialSnapshot WHERE NodeId=? AND ProtocolPath=?;`, s.NodeID, s.ProtocolPath).Scan(&old.CredentialID, &old.Username, &old.Domain, &old.SourceKind, &old.ResolverVersion, &notNull)
		if err != nil || !notNull {
			return nil, errResolverSnapshot
		}
		difference, err := resolver.CompareSnapshots(old, s)
		if err != nil {
			return nil, errResolverSnapshot
		}
		if difference != nil {
			differences = append(differences, *difference)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, errResolverSnapshot
	}
	return differences, nil
}
