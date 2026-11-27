package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func snapshotDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func readObservedSnapshot(t *testing.T, db *sql.DB, id, path string) resolver.EffectiveCredentialSnapshot {
	t.Helper()
	var s resolver.EffectiveCredentialSnapshot
	var timestamp string
	err := db.QueryRow(`SELECT NodeId,ProtocolPath,CredentialId,Username,Domain,SourceKind,ResolverVersion,ObservedAtUtc FROM EffectiveCredentialSnapshot WHERE NodeId=? AND ProtocolPath=?;`, id, path).Scan(&s.NodeID, &s.ProtocolPath, &s.CredentialID, &s.Username, &s.Domain, &s.SourceKind, &s.ResolverVersion, &timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if s.Validate() != nil {
		t.Fatal("invalid stored snapshot")
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolverSnapshotAtomicWriteAndRollback(t *testing.T) {
	db, _ := snapshotDatabase(t)
	ctx := context.Background()
	id := uuid.NewString()
	main := legacyResolutionSnapshot(id, "rdp", uuid.NewString(), "observed-user", "DOMAIN", "saved")
	gateway := legacyResolutionSnapshot(id, "rdp-gateway", uuid.NewString(), "gateway-user", "", "saved")
	old := []resolver.EffectiveCredentialSnapshot{main, gateway}
	if err := writeLegacyResolutionSnapshots(ctx, db, old); err != nil {
		t.Fatal(err)
	}
	main.Username = "new-user"
	gateway.Username = "new-gateway"
	for _, action := range []string{"IGNORE", "ABORT,'synthetic'"} {
		if _, err := db.Exec(`CREATE TRIGGER reject_snapshot BEFORE UPDATE ON EffectiveCredentialSnapshot WHEN OLD.ProtocolPath='rdp-gateway' BEGIN SELECT RAISE(` + action + `); END;`); err != nil {
			t.Fatal(err)
		}
		if err := writeLegacyResolutionSnapshots(ctx, db, []resolver.EffectiveCredentialSnapshot{main, gateway}); err != errResolverSnapshot {
			t.Fatal(err)
		}
		for _, s := range old {
			if got := readObservedSnapshot(t, db, s.NodeID, s.ProtocolPath); !reflect.DeepEqual(got, s) {
				t.Fatal("partial observation committed")
			}
		}
		if _, err := db.Exec(`DROP TRIGGER reject_snapshot;`); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeLegacyResolutionSnapshots(ctx, db, []resolver.EffectiveCredentialSnapshot{main, gateway}); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, id, "rdp"); got.Username != "new-user" {
		t.Fatal("upsert did not refresh observation")
	}
}

func TestResolverSnapshotInvalidInputsAndUnavailableStorage(t *testing.T) {
	db, path := snapshotDatabase(t)
	ctx := context.Background()
	valid := legacyResolutionSnapshot(uuid.NewString(), "ssh", "", "user", "", "none")
	for _, values := range [][]resolver.EffectiveCredentialSnapshot{nil, {valid, valid}, make([]resolver.EffectiveCredentialSnapshot, 7), {{NodeID: "bad"}}, {{NodeID: valid.NodeID, ProtocolPath: "ssh", SourceKind: "none", ResolverVersion: 1}}} {
		if err := writeLegacyResolutionSnapshots(ctx, db, values); err != errResolverSnapshot {
			t.Fatal(err)
		}
	}
	if err := writeLegacyResolutionSnapshots(ctx, nil, []resolver.EffectiveCredentialSnapshot{valid}); err != errResolverSnapshot {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := writeLegacyResolutionSnapshots(cancelled, db, []resolver.EffectiveCredentialSnapshot{valid}); err != errResolverSnapshot {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE EffectiveCredentialSnapshot;`); err != nil {
		t.Fatal(err)
	}
	observeLegacyResolution(db, valid)
	if exists, err := tableExists(db, "EffectiveCredentialSnapshot"); err != nil || exists {
		t.Fatal("observer created schema", err)
	}
	if err := ensureElectronWorkspaceSchema(path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeLegacyResolutionSnapshots(ctx, db, []resolver.EffectiveCredentialSnapshot{valid}); err != errResolverSnapshot {
		t.Fatal(err)
	}
}

func TestResolverSnapshotsFromActualLegacyPaths(t *testing.T) {
	db, path := snapshotDatabase(t)
	for _, protocol := range []string{"ssh", "sftp", "vnc", "rdp"} {
		t.Run(protocol, func(t *testing.T) {
			credentialProtocol := protocol
			if protocol == "sftp" {
				credentialProtocol = "ssh"
			}
			domain := ""
			if protocol == "rdp" {
				domain = "DOMAIN"
			}
			credential, err := createCredential(path, credentialCreateRequest{Name: "Account " + protocol, Protocol: credentialProtocol, Username: "account-user", Domain: domain, Password: "synthetic-secret-" + protocol})
			if err != nil {
				t.Fatal(err)
			}
			id, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Connection " + protocol, Kind: "connection", Protocol: protocol, Host: "host.example", CredentialMode: 2, CredentialID: credential.ID})
			if err != nil {
				t.Fatal(err)
			}
			wantUsername := "account-user"
			switch protocol {
			case "ssh", "sftp":
				target, err := loadSSHTarget(path, id)
				if err != nil || target.username != "account-user" {
					t.Fatal(err)
				}
			case "vnc":
				wantUsername = ""
				target, err := readVncTargetFromDatabase(db, id, "", true)
				if err != nil || target.password != "synthetic-secret-vnc" {
					t.Fatal(err)
				}
			case "rdp":
				manager := &vncManager{database: db, databasePath: path}
				target, err := manager.resolveRdpRuntimeProfileWithCredential(id, nil, "")
				if err != nil || target.Username != "account-user" {
					t.Fatal(err)
				}
				gateway := readObservedSnapshot(t, db, id, "rdp-gateway")
				if gateway.SourceKind != "none" {
					t.Fatal("disabled gateway snapshot")
				}
			}
			got := readObservedSnapshot(t, db, id, protocol)
			if got.CredentialID != credential.ID || got.SourceKind != "saved" || got.Username != wantUsername {
				t.Fatal("observed account differs from actual legacy walk")
			}
			if protocol == "ssh" || protocol == "sftp" {
				other := "ssh"
				if protocol == "ssh" {
					other = "sftp"
				}
				if alias := readObservedSnapshot(t, db, id, other); alias.CredentialID != got.CredentialID || alias.Username != got.Username {
					t.Fatal("SSH/SFTP shared walk drift")
				}
			}
			value, err := showWorkspaceNodeCredentials(path, workspaceNodeRequest{NodeID: id}, filepath.Dir(path))
			if err != nil || !value.Found {
				t.Fatal(err)
			}
			reveal := readObservedSnapshot(t, db, id, "reveal")
			if reveal.CredentialID != credential.ID || reveal.Username != wantUsername || reveal.SourceKind != "saved" {
				t.Fatal("reveal snapshot")
			}
			observed := []resolver.EffectiveCredentialSnapshot{got, reveal}
			if protocol == "rdp" {
				observed = append(observed, readObservedSnapshot(t, db, id, "rdp-gateway"))
			}
			if differences, err := compareLiveResolver(context.Background(), db, observed, runtime.GOOS); err != nil || len(differences) != 0 {
				t.Fatal("live candidate differs from ordinary legacy path", differences, err)
			}
		})
	}
	captured, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != nil || len(captured) != 11 {
		t.Fatal("six-path capture incomplete", len(captured), err)
	}
	baseline, err := captureLegacyResolverBaseline(context.Background(), db)
	if err != nil || !reflect.DeepEqual(baseline.Snapshots, captured) || len(baseline.Differences) != 0 {
		t.Fatal("ordinary six-path baseline changed", baseline, err)
	}
	for _, snapshot := range captured {
		if actual := readObservedSnapshot(t, db, snapshot.NodeID, snapshot.ProtocolPath); actual != snapshot {
			t.Fatal("capture differs from actual legacy path", actual, snapshot)
		}
	}
}

func TestResolverSnapshotsInlineOverrideAndGateway(t *testing.T) {
	db, path := snapshotDatabase(t)
	sshID, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Inline SSH", Kind: "connection", Protocol: "ssh", Host: "host.example", Username: "inline-user", CredentialMode: 1, InlinePasswordAction: "set", InlinePassword: "inline-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSSHTarget(path, sshID); err != nil {
		t.Fatal(err)
	}
	old := readObservedSnapshot(t, db, sshID, "ssh")
	if old.SourceKind != "inline" || old.CredentialID != sshID {
		t.Fatal("inline choice missing")
	}
	if _, err := loadSSHTargetWithOverrides(path, sshID, "manual-user", "manual-secret", true, true); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, sshID, "ssh"); !reflect.DeepEqual(got, old) {
		t.Fatal("manual attempt replaced configured observation")
	}
	if _, err := showWorkspaceNodeCredentials(path, workspaceNodeRequest{NodeID: sshID}, filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, sshID, "reveal"); got.SourceKind != "inline" {
		t.Fatal("inline reveal missing")
	}
	gatewayCredential, err := createCredential(path, credentialCreateRequest{Name: "Gateway", Protocol: "rdp", Username: "gateway-user", Domain: "EDGE", Password: "gateway-secret"})
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultWorkspaceRdpSettings()
	settings.GatewayUsageMethod = 1
	settings.GatewayHostname = "gateway.example"
	settings.GatewayCredentialID = gatewayCredential.ID
	rdpID, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Inline RDP", Kind: "connection", Protocol: "rdp", Host: "rdp.example", Username: "inline-user", CredentialMode: 1, InlinePasswordAction: "set", InlinePassword: "inline-rdp-secret", RDP: &settings})
	if err != nil {
		t.Fatal(err)
	}
	manager := &vncManager{database: db, databasePath: path}
	assertLiveGateway := func() {
		t.Helper()
		old := []resolver.EffectiveCredentialSnapshot{readObservedSnapshot(t, db, rdpID, "rdp"), readObservedSnapshot(t, db, rdpID, "rdp-gateway")}
		if d, err := compareLiveResolver(context.Background(), db, old, runtime.GOOS); err != nil || len(d) != 0 {
			t.Fatal("shadow disagrees with actual RDP/gateway identity", d, err)
		}
		captured, err := captureLegacyResolverSnapshots(context.Background(), db)
		if err != nil {
			t.Fatal(err)
		}
		for _, snapshot := range captured {
			if snapshot.NodeID == rdpID && snapshot.ProtocolPath != "reveal" {
				if actual := readObservedSnapshot(t, db, rdpID, snapshot.ProtocolPath); actual != snapshot {
					t.Fatal("captured gateway choice differs", actual, snapshot)
				}
			}
		}
	}
	if _, err := manager.resolveRdpRuntimeProfileWithCredential(rdpID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, rdpID, "rdp-gateway"); got.CredentialID != gatewayCredential.ID || got.Username != "EDGE\\gateway-user" {
		t.Fatal("gateway identity not captured")
	}
	assertLiveGateway()
	if _, err := db.Exec(`UPDATE Nodes SET RdpGatewayUseSameCreds=1 WHERE Id=?;`, rdpID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.resolveRdpRuntimeProfileWithCredential(rdpID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, rdpID, "rdp-gateway"); got.SourceKind != "inline" || got.CredentialID != rdpID || got.Username != "inline-user" {
		t.Fatal("same inline gateway snapshot")
	}
	assertLiveGateway()
	if _, err := db.Exec(`UPDATE Nodes SET RdpUseExternalClient=1 WHERE Id=?;`, rdpID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.resolveRdpRuntimeProfileWithCredential(rdpID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := readObservedSnapshot(t, db, rdpID, "rdp"); (got.SourceKind == "system") != (runtime.GOOS == "windows") {
		t.Fatal("system client snapshot platform mismatch")
	}
	assertLiveGateway()
}

func TestResolverSnapshotPathNeverCreatesOrOpensVault(t *testing.T) {
	s := legacyResolutionSnapshot(uuid.NewString(), "reveal", "", "user", "", "none")
	missing := filepath.Join(t.TempDir(), "missing.db")
	observeLegacyResolutionPath(missing, s)
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("observer created missing database", err)
	}
	db, path := snapshotDatabase(t)
	if err := os.WriteFile(path+".slots", []byte("untrusted-slot-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	observeLegacyResolutionPath(path, s)
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM EffectiveCredentialSnapshot;`).Scan(&count); err != nil || count != 0 {
		t.Fatal("observer opened a vault-marked path", err)
	}
}

func TestResolverSnapshotContentionDoesNotDelayConnection(t *testing.T) {
	db, path := snapshotDatabase(t)
	blocker, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	conn, err := blocker.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE;`); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), `ROLLBACK;`)
	s := legacyResolutionSnapshot(uuid.NewString(), "ssh", "", "user", "", "none")
	started := time.Now()
	observeLegacyResolution(db, s)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("observation delayed connection for %v", elapsed)
	}
	var timeout int
	if err := db.QueryRow(`PRAGMA busy_timeout;`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Fatal("observation changed legacy connection policy", timeout, err)
	}
}

func TestResolverSnapshotComparisonRejectsIncompleteAndCorruptBaseline(t *testing.T) {
	db, _ := snapshotDatabase(t)
	ctx := context.Background()
	id := uuid.NewString()
	old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "rdp", uuid.NewString(), "old-user", "DOMAIN", "saved"), legacyResolutionSnapshot(id, "rdp-gateway", "", "", "", "none")}
	if err := writeLegacyResolutionSnapshots(ctx, db, old); err != nil {
		t.Fatal(err)
	}
	next := append([]resolver.EffectiveCredentialSnapshot{}, old...)
	for i := range next {
		next[i].ResolverVersion = resolver.Version
	}
	if differences, err := compareLegacyResolutionSnapshots(ctx, db, next); err != nil || len(differences) != 0 {
		t.Fatal(differences, err)
	}
	next[0].Username = "new-user"
	if differences, err := compareLegacyResolutionSnapshots(ctx, db, next); err != nil || len(differences) != 1 || !differences[0].UsernameChanged {
		t.Fatal(differences, err)
	}
	for _, values := range [][]resolver.EffectiveCredentialSnapshot{nil, old, {next[0], next[0]}, make([]resolver.EffectiveCredentialSnapshot, 7)} {
		if _, err := compareLegacyResolutionSnapshots(ctx, db, values); err != errResolverSnapshot {
			t.Fatal(err)
		}
	}
	if _, err := compareLegacyResolutionSnapshots(ctx, nil, next); err != errResolverSnapshot {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE EffectiveCredentialSnapshot SET Username=char(0) WHERE ProtocolPath='rdp-gateway';`); err != nil {
		t.Fatal(err)
	}
	if differences, err := compareLegacyResolutionSnapshots(ctx, db, next); err != errResolverSnapshot || differences != nil {
		t.Fatal("partial comparison escaped", differences, err)
	}
	if _, err := db.Exec(`DELETE FROM EffectiveCredentialSnapshot WHERE ProtocolPath='rdp-gateway';`); err != nil {
		t.Fatal(err)
	}
	if differences, err := compareLegacyResolutionSnapshots(ctx, db, next); err != errResolverSnapshot || differences != nil {
		t.Fatal("missing baseline accepted", differences, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := compareLegacyResolutionSnapshots(cancelled, db, next); err != errResolverSnapshot {
		t.Fatal(err)
	}
}

func TestResolverSnapshotGoldenDetectsInlineIdentityDrift(t *testing.T) {
	db, path := snapshotDatabase(t)
	parent, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Folder", Kind: "folder", Username: "ancestor-user"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Inline", Kind: "connection", ParentID: parent, Protocol: "ssh", Host: "host.example", CredentialMode: 1, InlinePasswordAction: "set", InlinePassword: "synthetic-inline-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Username=NULL WHERE Id=?;`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Username='ancestor-user' WHERE Id=?;`, parent); err != nil {
		t.Fatal(err)
	}
	target, err := loadSSHTarget(path, id)
	if err != nil || target.username != "ancestor-user" {
		t.Fatal("legacy inline identity changed", err)
	}
	protocol, inline, username, host := 0, true, "ancestor-user", "host.example"
	p, err := resolver.Resolve([]vaultstore.NodeMetadata{{ID: id, ParentID: &parent, Name: "Inline", Kind: 1, Protocol: &protocol, Host: &host, UseInlinePassword: &inline}, {ID: parent, Name: "Folder", Kind: 0, Username: &username}}, "")
	if err != nil || p.Username != "" || p.Credential.Kind != "inline" {
		t.Fatal("candidate inline boundary changed", err)
	}
	var candidates []resolver.EffectiveCredentialSnapshot
	for _, path := range []string{"ssh", "sftp"} {
		candidates = append(candidates, resolver.EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: path, CredentialID: p.Credential.ID, Username: p.Username, Domain: p.Domain, SourceKind: p.Credential.Kind, ResolverVersion: resolver.Version})
	}
	differences, err := compareLegacyResolutionSnapshots(context.Background(), db, candidates)
	if err != nil || len(differences) != 2 {
		t.Fatal("golden drift not detected", err)
	}
	for _, d := range differences {
		if !d.UsernameChanged || d.CredentialChanged || d.SourceChanged || d.DomainChanged {
			t.Fatal("unexpected drift category")
		}
	}
	observed := []resolver.EffectiveCredentialSnapshot{readObservedSnapshot(t, db, id, "ssh"), readObservedSnapshot(t, db, id, "sftp")}
	live, err := compareLiveResolver(context.Background(), db, observed, runtime.GOOS)
	if err != nil || !reflect.DeepEqual(live, differences) {
		t.Fatal("live candidate did not detect actual inline drift", err)
	}
	baseline, err := captureLegacyResolverBaseline(context.Background(), db)
	if err != nil || len(baseline.Snapshots) != 3 || len(baseline.Differences) != 3 {
		t.Fatal("coherent baseline missed inline drift", baseline, err)
	}
	for _, difference := range baseline.Differences {
		if !difference.UsernameChanged || difference.CredentialChanged || difference.DomainChanged || difference.SourceChanged {
			t.Fatal("unexpected coherent drift category", difference)
		}
	}
	raw, err := json.Marshal(differences)
	if err != nil || strings.Contains(string(raw), "ancestor-user") || strings.Contains(string(raw), "synthetic-inline-secret") {
		t.Fatal("identity/secret in ID-only difference")
	}
}

func TestResolverSnapshotRevealUnavailableChoices(t *testing.T) {
	for _, kind := range []string{"unsupported-protocol", "unsupported-inline", "no-credential", "missing-credential", "wrong-protocol", "provider", "unsupported-kind"} {
		t.Run(kind, func(t *testing.T) {
			db, path := snapshotDatabase(t)
			c, err := createCredential(path, credentialCreateRequest{Name: "Account", Protocol: "ssh", Username: "account-user", Password: "synthetic-secret"})
			if err != nil {
				t.Fatal(err)
			}
			id, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Connection", Kind: "connection", Protocol: "ssh", Host: "host.example", CredentialMode: 2, CredentialID: c.ID})
			if err != nil {
				t.Fatal(err)
			}
			var statement string
			var args []any
			switch kind {
			case "unsupported-protocol":
				statement = `UPDATE Nodes SET Protocol=3 WHERE Id=?;`
				args = []any{id}
			case "unsupported-inline":
				statement = `UPDATE Nodes SET Protocol=6,UseInlinePassword=1 WHERE Id=?;`
				args = []any{id}
			case "no-credential":
				statement = `UPDATE Nodes SET CredentialMode=1,CredentialId=NULL WHERE Id=?;`
				args = []any{id}
			case "missing-credential":
				statement = `UPDATE Nodes SET CredentialId=? WHERE Id=?;`
				args = []any{uuid.NewString(), id}
			case "wrong-protocol":
				statement = `UPDATE Nodes SET Protocol=1 WHERE Id=?;`
				args = []any{id}
			case "provider":
				statement = `UPDATE CredentialProfiles SET SecretProvider=1 WHERE Id=?;`
				args = []any{c.ID}
			case "unsupported-kind":
				statement = `UPDATE CredentialProfiles SET Kind=99 WHERE Id=?;`
				args = []any{c.ID}
			}
			if _, err := db.Exec(statement, args...); err != nil {
				t.Fatal(err)
			}
			response, err := showWorkspaceNodeCredentials(path, workspaceNodeRequest{NodeID: id}, filepath.Dir(path))
			if err != nil || response.Found || response.Secret != "" {
				t.Fatal("unavailable reveal changed", err)
			}
			got := readObservedSnapshot(t, db, id, "reveal")
			if got.SourceKind != "none" || got.CredentialID != "" || got.Username != response.Username || got.Domain != response.Domain {
				t.Fatal("snapshot invented a usable identity")
			}
		})
	}
}
