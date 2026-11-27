package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Shadow resolution reads metadata only. It is diagnostic, never a capability,
// a source of credentials for a connection, or authority to migrate a workspace.
// The candidate inputs share one read transaction; the earlier legacy request
// may have raced an edit, so a difference still needs a coherent migration capture.
func compareLiveResolver(ctx context.Context, database *sql.DB, old []resolver.EffectiveCredentialSnapshot, operatingSystem string) ([]resolver.SnapshotDifference, error) {
	if database == nil || len(old) == 0 || len(old) > 6 {
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
	differences, err := compareResolverSnapshotsInTransaction(ctx, tx, old, operatingSystem)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, errResolverSnapshot
	}
	if err := tx.Commit(); err != nil {
		return nil, errResolverSnapshot
	}
	return differences, nil
}

// Compare one node's bounded path group inside an existing source snapshot.
// Migration capture uses this to compare old and new without a second read state.
func compareResolverSnapshotsInTransaction(ctx context.Context, tx resolverSnapshotReader, old []resolver.EffectiveCredentialSnapshot, operatingSystem string) ([]resolver.SnapshotDifference, error) {
	next, err := candidateSnapshotsInTransaction(ctx, tx, old, operatingSystem)
	if err != nil {
		return nil, err
	}
	return resolverSnapshotDifferences(old, next)
}

func candidateSnapshotsInTransaction(ctx context.Context, tx resolverSnapshotReader, old []resolver.EffectiveCredentialSnapshot, operatingSystem string) ([]resolver.EffectiveCredentialSnapshot, error) {
	if tx == nil || len(old) == 0 || len(old) > 6 {
		return nil, errResolverSnapshot
	}
	seen := map[string]bool{}
	for _, value := range old {
		key := value.NodeID + ":" + value.ProtocolPath
		if value.Validate() != nil || value.ResolverVersion != 0 || seen[key] {
			return nil, errResolverSnapshot
		}
		seen[key] = true
	}
	plans := map[string]resolver.Plan{}
	credentials := map[string]vaultstore.CredentialMetadata{}
	readCredential := func(id string) (vaultstore.CredentialMetadata, error) {
		if c, ok := credentials[id]; ok {
			return c, nil
		}
		c, err := readShadowCredential(ctx, tx, id)
		if err == nil {
			credentials[id] = c
		}
		return c, err
	}
	candidates := make([]resolver.EffectiveCredentialSnapshot, 0, len(old))
	for _, value := range old {
		plan, ok := plans[value.NodeID]
		if !ok {
			chain, err := readShadowChain(ctx, tx, value.NodeID)
			if err != nil {
				return nil, errResolverSnapshot
			}
			plan, err = resolver.Resolve(chain, "")
			if err != nil || plan.Credential.Kind == "slot" {
				return nil, errResolverSnapshot
			}
			if plan.Credential.Kind == "saved" {
				c, err := readCredential(plan.Credential.ID)
				if err != nil {
					return nil, errResolverSnapshot
				}
				plan, err = resolver.ApplyCredential(plan, c)
				if err != nil {
					return nil, errResolverSnapshot
				}
			}
			plans[value.NodeID] = plan
		}
		next, err := shadowCredentialSnapshot(plan, value.ProtocolPath, operatingSystem, readCredential)
		if err != nil {
			return nil, errResolverSnapshot
		}
		candidates = append(candidates, next)
	}
	if ctx.Err() != nil {
		return nil, errResolverSnapshot
	}
	return candidates, nil
}

func resolverSnapshotDifferences(old, next []resolver.EffectiveCredentialSnapshot) ([]resolver.SnapshotDifference, error) {
	if len(old) != len(next) {
		return nil, errResolverSnapshot
	}
	differences := make([]resolver.SnapshotDifference, 0)
	for i := range old {
		difference, err := resolver.CompareSnapshots(old[i], next[i])
		if err != nil {
			return nil, errResolverSnapshot
		}
		if difference != nil {
			differences = append(differences, *difference)
		}
	}
	return differences, nil
}

func observeResolverShadow(ctx context.Context, database *sql.DB, values []resolver.EffectiveCredentialSnapshot) {
	differences, err := compareLiveResolver(ctx, database, values, runtime.GOOS)
	if err != nil {
		// Neither raw SQL errors nor input metadata belong in diagnostics.
		logDebug("resolver_shadow_unavailable")
		return
	}
	for _, difference := range differences {
		encoded, _ := json.Marshal(difference) // Fixed ID/boolean-only DTO.
		logInfo("resolver_shadow_difference %s", encoded)
	}
}

func shadowCredentialSnapshot(p resolver.Plan, path, operatingSystem string, credential func(string) (vaultstore.CredentialMetadata, error)) (resolver.EffectiveCredentialSnapshot, error) {
	snapshot, err := resolver.AccountSnapshot(p, path, operatingSystem, credential)
	if err != nil {
		return resolver.EffectiveCredentialSnapshot{}, errResolverSnapshot
	}
	return snapshot, nil
}

// Static column names only. Slice bytes, retaining NULL, empty and embedded NUL
// distinctly; the extra byte makes oversized values fail metadata validation.
func shadowText(column string, limit int) string {
	return "CASE WHEN " + column + " IS NULL THEN NULL ELSE CAST(COALESCE(substr(CAST(" + column + " AS BLOB),1," + strconv.Itoa(limit+1) + "),X'') AS TEXT) END"
}

func readShadowChain(ctx context.Context, tx resolverSnapshotReader, id string) ([]vaultstore.NodeMetadata, error) {
	chain := make([]vaultstore.NodeMetadata, 0, 8)
	seen := map[string]bool{}
	for id != "" {
		if seen[id] || len(chain) >= vaultstore.MaxNodeDepth {
			return nil, errResolverSnapshot
		}
		seen[id] = true
		// No secrets, notes, provider payloads or private-key files are read.
		columns := []string{shadowText("Id", 36), shadowText("ParentId", 36), shadowText("Name", 1024), "Kind", "Protocol", shadowText("Host", 16384), "Port", shadowText("Username", 2048), shadowText("CredentialId", 36), "CredentialMode", "UseInlinePassword", shadowText("RdpDomain", 2048), "TunnelEnabled", shadowText("TunnelConfigId", 36), "RdpGatewayUsageMethod", shadowText("RdpGatewayHostname", 4096), shadowText("RdpGatewayCredentialId", 36), "RdpGatewayUseSameCreds", "RdpUseExternalClient"}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(columns, ",")+" FROM Nodes WHERE lower(Id)=? LIMIT 2;", id)
		if err != nil {
			return nil, errResolverSnapshot
		}
		var n vaultstore.NodeMetadata
		if !rows.Next() || rows.Scan(&n.ID, &n.ParentID, &n.Name, &n.Kind, &n.Protocol, &n.Host, &n.Port, &n.Username, &n.CredentialID, &n.CredentialMode, &n.UseInlinePassword, &n.RDPDomain, &n.TunnelEnabled, &n.TunnelConfigID, &n.RDPGatewayUsageMethod, &n.RDPGatewayHostname, &n.RDPGatewayCredentialID, &n.RDPGatewayUseSameCreds, &n.RDPUseExternalClient) != nil {
			rows.Close()
			return nil, errResolverSnapshot
		}
		duplicate := rows.Next()
		readErr := rows.Err()
		rows.Close()
		n.ID = strings.ToLower(n.ID)
		for _, ref := range []*string{n.ParentID, n.CredentialID, n.TunnelConfigID, n.RDPGatewayCredentialID} {
			if ref != nil {
				*ref = strings.ToLower(*ref)
			}
		}
		if duplicate || readErr != nil || n.ID != id || n.Validate() != nil {
			return nil, errResolverSnapshot
		}
		chain = append(chain, n)
		id = ""
		if n.ParentID != nil {
			id = *n.ParentID
		}
	}
	return chain, nil
}

func readShadowCredential(ctx context.Context, tx resolverSnapshotReader, id string) (vaultstore.CredentialMetadata, error) {
	c := vaultstore.CredentialMetadata{}
	rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join([]string{shadowText("Id", 36), shadowText("Username", 2048), shadowText("Domain", 2048), "Protocol", "Kind", "SecretProvider"}, ",")+" FROM CredentialProfiles WHERE lower(Id)=? LIMIT 2;", id)
	if err != nil {
		return c, errResolverSnapshot
	}
	defer rows.Close()
	var username, domain sql.NullString
	var protocol, kind, provider int
	if !rows.Next() || rows.Scan(&c.ID, &username, &domain, &protocol, &kind, &provider) != nil {
		return c, errResolverSnapshot
	}
	// A dynamic provider identity cannot be inferred from cached metadata. Do not
	// contact Bitwarden or read/decrypt secrets as a side effect of shadowing.
	if rows.Next() || rows.Err() != nil || provider != 0 || (kind != 0 && kind != 1) || (kind == 1 && protocol != 0) {
		return c, errResolverSnapshot
	}
	c.ID, c.Protocol, c.Username, c.Domain = strings.ToLower(c.ID), resolver.CredentialProtocol(protocol), username.String, domain.String
	check := resolver.EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: "reveal", CredentialID: c.ID, SourceKind: "saved", Username: c.Username, Domain: c.Domain}
	if c.ID != id || c.Protocol == "" || check.Validate() != nil {
		return c, errResolverSnapshot
	}
	return c, nil
}
