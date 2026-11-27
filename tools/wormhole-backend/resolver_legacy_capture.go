package main

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Query surface shared by the existing metadata loaders and a capture
// transaction. Those loaders issue only SELECT and schema-inspection PRAGMAs.
type sqlMetadataReader interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

type resolverCaptureReader struct {
	ctx context.Context
	tx  resolverSnapshotReader
}

type resolverSnapshotReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (r resolverCaptureReader) Query(query string, args ...any) (*sql.Rows, error) {
	return r.tx.QueryContext(r.ctx, query, args...)
}

func (r resolverCaptureReader) QueryRow(query string, args ...any) *sql.Row {
	return r.tx.QueryRowContext(r.ctx, query, args...)
}

// Capture the applicable legacy credential paths for every current connection,
// including connections never opened since upgrade. Each protocol uses its
// existing runtime walk through metadata-only readers in one source snapshot.
// It neither reads secrets nor proves their availability. The migration must
// authenticate/import all secret material before activating the destination.
// Results are native metadata only and must not be sent to diagnostics or React.
func captureLegacyResolverSnapshots(ctx context.Context, database *sql.DB) ([]resolver.EffectiveCredentialSnapshot, error) {
	if database == nil {
		return nil, errResolverSnapshot
	}
	connection, release, err := resolverObservationConnection(ctx, database)
	if err != nil {
		return nil, errResolverSnapshot
	}
	defer release()
	tx, err := connection.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errResolverSnapshot
	}
	defer tx.Rollback()
	reader := resolverCaptureReader{ctx, tx}
	result, err := readLegacyResolverSnapshots(reader)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, errResolverSnapshot
	}
	if tx.Commit() != nil {
		return nil, errResolverSnapshot
	}
	return result, nil
}

func readLegacyResolverSnapshots(reader resolverCaptureReader) ([]resolver.EffectiveCredentialSnapshot, error) {
	ctx := reader.ctx
	sshNodes, err := loadSSHNodes(reader)
	if err != nil {
		return nil, errResolverSnapshot
	}
	revealNodes, err := loadWorkspaceCredentialNodes(reader)
	if err != nil {
		return nil, errResolverSnapshot
	}
	var storedCount int
	if reader.QueryRow("SELECT count(*) FROM Nodes;").Scan(&storedCount) != nil || storedCount != len(revealNodes) {
		return nil, errResolverSnapshot
	}
	// Normalize/order once; do not make a fresh DB read for each ancestor or path.
	ids := make([]string, 0, len(revealNodes))
	for id, n := range revealNodes {
		if legacyResolutionSnapshot(id, "reveal", "", "", "", "none").Validate() != nil {
			return nil, errResolverSnapshot
		}
		if !n.kind.Valid || (n.kind.Int64 != 0 && n.kind.Int64 != 1) {
			return nil, errResolverSnapshot
		}
		if n.kind.Int64 == 1 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	type profileResult struct {
		value workspaceCredentialProfile
		found bool
	}
	profiles := map[string]profileResult{}
	profile := func(id string) (workspaceCredentialProfile, bool, error) {
		if cached, ok := profiles[id]; ok {
			return cached.value, cached.found, nil
		}
		value, found, err := loadWorkspaceCredentialProfile(reader, id)
		if err == nil {
			profiles[id] = profileResult{value, found}
		}
		return value, found, err
	}
	result := make([]resolver.EffectiveCredentialSnapshot, 0, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			return nil, errResolverSnapshot
		}
		// Legacy walks tolerate a missing parent; a migration may not silently
		// certify that truncated history as a complete captured connection chain.
		seen := map[string]bool{}
		for current := id; current != ""; {
			n := revealNodes[current]
			if n == nil || seen[current] || len(seen) >= vaultstore.MaxNodeDepth || (current != id && (!n.kind.Valid || n.kind.Int64 != 0)) {
				return nil, errResolverSnapshot
			}
			seen[current] = true
			current = n.parentID
		}
		choice, err := resolveLegacyRevealChoice(revealNodes, id)
		if err != nil {
			return nil, errResolverSnapshot
		}
		reveal, err := resolveLegacyRevealMetadata(revealNodes, id, profile)
		if err != nil {
			return nil, errResolverSnapshot
		}
		snapshots := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "reveal", reveal.ownerID, reveal.response.Username, reveal.response.Domain, reveal.source)}
		expectedPaths := 1
		if choice.protocol == 0 || choice.protocol == 7 {
			expectedPaths = 3
			target, inline, err := resolveLegacySSHMetadata(sshNodes, id)
			if err != nil {
				return nil, errResolverSnapshot
			}
			source, selected := "none", ""
			if inline {
				source, selected = "inline", id
			} else if target.credentialID != "" {
				c, found, err := profile(target.credentialID)
				if err != nil || !found || (c.protocol.Valid && c.protocol.Int64 != 0) || (c.secretProvider.Valid && c.secretProvider.Int64 != 0) {
					return nil, errResolverSnapshot
				}
				if target.username == "" {
					target.username = strings.TrimSpace(nullableString(c.username))
				}
				source, selected = "saved", target.credentialID
			}
			if target.username == "" {
				return nil, errResolverSnapshot
			}
			for _, path := range []string{"ssh", "sftp"} {
				snapshots = append(snapshots, legacyResolutionSnapshot(id, path, selected, target.username, "", source))
			}
		}
		if choice.protocol == 6 {
			expectedPaths = 2
			_, err := resolveLegacyVNCTarget(reader, id, "", true, func(credential string) (string, bool, error) {
				if _, _, err := profile(credential); err != nil {
					return "", false, err
				}
				eligible, err := legacyVNCCredentialEligible(reader, credential)
				if err != nil || !eligible {
					return "", false, err
				}
				present, err := capturedSecretPresent(reader, credential)
				return "", present, err
			}, func(snapshot resolver.EffectiveCredentialSnapshot) { snapshots = append(snapshots, snapshot) })
			if err != nil {
				return nil, errResolverSnapshot
			}
		}
		if choice.protocol == 1 {
			expectedPaths = 3
			_, err := resolveLegacyRDPProfile(reader, id, nil, false, "", func(credential string) (bitwardenResolvedCredential, error) {
				c, found, err := profile(credential)
				if err != nil || !found || !c.protocol.Valid || c.protocol.Int64 != 1 || (c.kind.Valid && c.kind.Int64 != 0) || (c.secretProvider.Valid && c.secretProvider.Int64 != 0) {
					return bitwardenResolvedCredential{}, errResolverSnapshot
				}
				return bitwardenResolvedCredential{Username: strings.TrimSpace(nullableString(c.username)), Domain: strings.TrimSpace(nullableString(c.domain))}, nil
			}, func(string) (string, bool, error) { return "", false, nil },
				func(nodeID, credential string, inline bool, p rdpProfile, settings workspaceRdpSettings) {
					snapshots = append(snapshots, legacyRDPSnapshots(nodeID, credential, inline, p, settings)...)
				})
			if err != nil {
				return nil, errResolverSnapshot
			}
		}
		if len(snapshots) != expectedPaths {
			return nil, errResolverSnapshot
		}
		for _, snapshot := range snapshots {
			if snapshot.Validate() != nil {
				return nil, errResolverSnapshot
			}
		}
		result = append(result, snapshots...)
	}
	if ctx.Err() != nil {
		return nil, errResolverSnapshot
	}
	return result, nil
}

// VNC's legacy choice distinguishes an absent secret record from an empty
// password. Read only row presence; authentication and plaintext length checks
// belong to secret import and must succeed before the destination is activated.
func capturedSecretPresent(database sqlMetadataReader, id string) (bool, error) {
	exists, err := tableExists(database, "CredentialSecrets")
	if err != nil || !exists {
		return false, err
	}
	var present int
	err = database.QueryRow("SELECT 1 FROM CredentialSecrets WHERE lower(Id)=? LIMIT 1;", normalizeID(id)).Scan(&present)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}
