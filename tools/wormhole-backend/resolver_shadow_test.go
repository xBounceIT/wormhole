package main

import (
	"context"
	"database/sql"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// These fixtures contain metadata only; there is deliberately no credential
// secret. A shadow read must never require decrypting one to choose an identity.
func shadowFixture(t *testing.T) (*sql.DB, string, string, string) {
	t.Helper()
	db, path := snapshotDatabase(t)
	id, credential := uuid.NewString(), uuid.NewString()
	_, err := db.Exec(`INSERT INTO CredentialProfiles(Id,Name,Username,Domain,Kind,Protocol,SecretProvider,CreatedAt) VALUES(?,'Private account name','private-user','',0,0,0,'fixture');`, credential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO Nodes(Id,Name,Kind,Protocol,Host,Username,CredentialMode,CredentialId,CreatedAt,UpdatedAt) VALUES(?,'Private node name',1,0,'private-host.example',NULL,2,?,'fixture','fixture');`, id, credential)
	if err != nil {
		t.Fatal(err)
	}
	return db, path, id, credential
}

func TestResolverSnapshotShadowLiveMetadata(t *testing.T) {
	db, _, id, credential := shadowFixture(t)
	old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "ssh", credential, "private-user", "", "saved"), legacyResolutionSnapshot(id, "sftp", credential, "private-user", "", "saved")}
	ctx := context.Background()
	if differences, err := compareLiveResolver(ctx, db, old, "linux"); err != nil || len(differences) != 0 {
		t.Fatal("equivalent metadata changed", differences, err)
	}
	if _, err := db.Exec(`UPDATE CredentialProfiles SET Username='new-private-user' WHERE Id=?;`, credential); err != nil {
		t.Fatal(err)
	}
	differences, err := compareLiveResolver(ctx, db, old, "linux")
	if err != nil || len(differences) != 2 {
		t.Fatal("live edit was not compared", differences, err)
	}
	for _, d := range differences {
		if !d.UsernameChanged || d.CredentialChanged || d.SourceChanged || d.DomainChanged {
			t.Fatal("wrong drift category", d)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM EffectiveCredentialSnapshot;`).Scan(&count); err != nil || count != 0 {
		t.Fatal("comparison mutated baseline", err)
	}
}

func TestResolverSnapshotShadowLogsOnlyIDsThroughActualObserver(t *testing.T) {
	db, path, id, credential := shadowFixture(t)
	logger := newAppLogger(path, io.Discard)
	previous := appLog
	if _, err := writeLogLevel(path, logLevelDebug); err != nil {
		t.Fatal(err)
	}
	appLog = logger
	t.Cleanup(func() { appLog = previous; logger.close() })
	// The normal observation hook executes the new resolver automatically.
	observeLegacyResolution(db, legacyResolutionSnapshot(id, "ssh", credential, "old-private-user", "", "saved"))
	contents, err := os.ReadFile(currentDayLogFilePath(path))
	if err != nil {
		t.Fatal(err)
	}
	line := string(contents)
	if !strings.Contains(line, "resolver_shadow_difference") || !strings.Contains(line, id) || !strings.Contains(line, `"usernameChanged":true`) {
		t.Fatal("missing structured difference")
	}
	for _, forbidden := range []string{"private-user", "Private node name", "Private account name", "private-host", "Username", "Domain"} {
		if strings.Contains(line, forbidden) {
			t.Fatal("private metadata logged")
		}
	}
	if got := readObservedSnapshot(t, db, id, "ssh"); got.Username != "old-private-user" {
		t.Fatal("shadow overwrote legacy choice")
	}
	// An unavailable candidate cannot prevent the existing observation succeeding.
	if _, err := db.Exec(`DROP TABLE CredentialProfiles;`); err != nil {
		t.Fatal(err)
	}
	observeLegacyResolution(db, legacyResolutionSnapshot(id, "ssh", credential, "last-legacy-user", "", "saved"))
	if got := readObservedSnapshot(t, db, id, "ssh"); got.Username != "last-legacy-user" {
		t.Fatal("shadow failure changed legacy observation")
	}
	contents, err = os.ReadFile(currentDayLogFilePath(path))
	if err != nil || !strings.Contains(string(contents), "resolver_shadow_unavailable") || strings.Contains(string(contents), "CredentialProfiles") {
		t.Fatal("unavailable diagnostic missing or exposed SQL error", err)
	}
}

func TestResolverSnapshotShadowAdapters(t *testing.T) {
	id, credential, gateway := uuid.NewString(), uuid.NewString(), uuid.NewString()
	base := resolver.Plan{Version: 1, NodeID: id, Protocol: 1, Username: `DOMAIN\user`, Credential: resolver.Choice{Kind: "saved", ID: credential}}
	lookup := func(id string) (vaultstore.CredentialMetadata, error) {
		if id != gateway {
			return vaultstore.CredentialMetadata{}, errResolverSnapshot
		}
		return vaultstore.CredentialMetadata{ID: gateway, Protocol: "rdp", Username: "gateway-user", Domain: "EDGE"}, nil
	}
	tests := []struct {
		name, path, os, source, selected, username, domain string
		modify                                             func(*resolver.Plan)
	}{
		{"rdp split", "rdp", "windows", "saved", credential, "user", "DOMAIN", nil},
		{"same gateway", "rdp-gateway", "linux", "saved", credential, "user", "", func(p *resolver.Plan) { p.GatewayMethod = 1; p.GatewaySameCredentials = true }},
		{"separate gateway", "rdp-gateway", "linux", "saved", gateway, `EDGE\gateway-user`, "", func(p *resolver.Plan) { p.GatewayMethod = 1; p.GatewayCredentialID = gateway }},
		{"disabled gateway", "rdp-gateway", "linux", "none", "", "", "", nil},
		{"empty gateway", "rdp-gateway", "linux", "none", "", "", "", func(p *resolver.Plan) { p.GatewayMethod = 1 }},
		{"external windows", "rdp", "windows", "system", "", "", "", func(p *resolver.Plan) { p.ExternalRDPClient = true }},
		{"external gateway", "rdp-gateway", "windows", "system", "", "", "", func(p *resolver.Plan) { p.ExternalRDPClient = true }},
		{"azure windows", "rdp", "windows", "system", "", "", "", func(p *resolver.Plan) { p.Domain = "AzureAD" }},
		{"external linux", "rdp", "linux", "saved", credential, "user", "DOMAIN", func(p *resolver.Plan) { p.ExternalRDPClient = true }},
		{"reveal external", "reveal", "windows", "saved", credential, `DOMAIN\user`, "", func(p *resolver.Plan) { p.ExternalRDPClient = true }},
		{"vnc", "vnc", "linux", "saved", credential, "", "", func(p *resolver.Plan) { p.Protocol = 6 }},
		{"ssh", "ssh", "linux", "saved", credential, `DOMAIN\user`, "", func(p *resolver.Plan) { p.Protocol = 0; p.Domain = "ignored" }},
		{"sftp", "sftp", "linux", "saved", credential, `DOMAIN\user`, "", func(p *resolver.Plan) { p.Protocol = 7 }},
		{"web reveal", "reveal", "linux", "none", "", "", "", func(p *resolver.Plan) { p.Protocol = 4 }},
		{"inline", "rdp", "linux", "inline", id, "user", "DOMAIN", func(p *resolver.Plan) { p.Credential = resolver.Choice{Kind: "inline", ID: id} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := base
			if test.modify != nil {
				test.modify(&p)
			}
			got, err := shadowCredentialSnapshot(p, test.path, test.os, lookup)
			want := resolver.EffectiveCredentialSnapshot{NodeID: id, ProtocolPath: test.path, ResolverVersion: 1, SourceKind: test.source, CredentialID: test.selected, Username: test.username, Domain: test.domain}
			if err != nil || got != want {
				t.Fatal(got, want, err)
			}
		})
	}
	for _, path := range []string{"ssh", "sftp", "vnc", "unknown"} {
		if _, err := shadowCredentialSnapshot(base, path, "linux", lookup); err == nil {
			t.Fatal("wrong path accepted", path)
		}
	}
	base.Protocol = 0
	for _, path := range []string{"rdp", "rdp-gateway"} {
		if _, err := shadowCredentialSnapshot(base, path, "linux", lookup); err == nil {
			t.Fatal("wrong path accepted", path)
		}
	}
	base.Protocol, base.GatewayMethod, base.GatewayCredentialID = 1, 1, credential
	if _, err := shadowCredentialSnapshot(base, "rdp-gateway", "linux", lookup); err == nil {
		t.Fatal("missing gateway accepted")
	}
}

func TestResolverSnapshotShadowRejectsCorruptInputsAtomically(t *testing.T) {
	for _, test := range []struct {
		name, sql string
		args      func(string, string) []any
	}{
		{"missing node", `DELETE FROM Nodes;`, nil},
		{"missing parent", `UPDATE Nodes SET ParentId=?;`, func(_, _ string) []any { return []any{uuid.NewString()} }},
		{"cycle", `UPDATE Nodes SET ParentId=Id;`, nil},
		{"invalid kind", `UPDATE Nodes SET Kind=9;`, nil},
		{"invalid bool", `UPDATE Nodes SET UseInlinePassword=2;`, nil},
		{"slot unavailable", `UPDATE Nodes SET CredentialMode=3;`, nil},
		{"empty host", `UPDATE Nodes SET Host='';`, nil},
		{"null host", `UPDATE Nodes SET Host=NULL;`, nil},
		{"NUL node identity", `UPDATE Nodes SET Username=?;`, func(_, _ string) []any { return []any{"\x00hidden"} }},
		{"oversized identity", `UPDATE Nodes SET Username=?;`, func(_, _ string) []any { return []any{strings.Repeat("x", 2049)} }},
		{"provider unavailable", `UPDATE CredentialProfiles SET SecretProvider=1;`, nil},
		{"credential missing", `DELETE FROM CredentialProfiles;`, nil},
		{"credential protocol", `UPDATE CredentialProfiles SET Protocol=1;`, nil},
		{"credential invalid kind", `UPDATE CredentialProfiles SET Kind=99;`, nil},
		{"credential NUL", `UPDATE CredentialProfiles SET Username=?;`, func(_, _ string) []any { return []any{"\x00hidden"} }},
		{"credential oversized", `UPDATE CredentialProfiles SET Domain=?;`, func(_, _ string) []any { return []any{strings.Repeat("x", 2049)} }},
		{"credential corrupt integer", `UPDATE CredentialProfiles SET Kind='invalid';`, nil},
		{"schema absent", `DROP TABLE Nodes;`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _, id, c := shadowFixture(t)
			var args []any
			if test.args != nil {
				args = test.args(id, c)
			}
			if _, err := db.Exec("PRAGMA foreign_keys=OFF;"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.sql, args...); err != nil {
				t.Fatal(err)
			}
			old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "ssh", c, "old-user", "", "saved")}
			if differences, err := compareLiveResolver(context.Background(), db, old, "linux"); err != errResolverSnapshot || differences != nil {
				t.Fatal("incomplete comparison accepted", differences, err)
			}
		})
	}
	db, _, id, c := shadowFixture(t)
	valid := legacyResolutionSnapshot(id, "ssh", c, "old-user", "", "saved")
	for _, values := range [][]resolver.EffectiveCredentialSnapshot{nil, make([]resolver.EffectiveCredentialSnapshot, 7), {valid, valid}, {{NodeID: "invalid"}}, {valid, legacyResolutionSnapshot(uuid.NewString(), "ssh", "", "", "", "none")}} {
		if d, err := compareLiveResolver(context.Background(), db, values, "linux"); err != errResolverSnapshot || d != nil {
			t.Fatal("partial comparison accepted", d, err)
		}
	}
	if _, err := compareLiveResolver(context.Background(), nil, []resolver.EffectiveCredentialSnapshot{valid}, "linux"); err != errResolverSnapshot {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := compareLiveResolver(cancelled, db, []resolver.EffectiveCredentialSnapshot{valid}, "linux"); err != errResolverSnapshot {
		t.Fatal(err)
	}
}

func TestResolverSnapshotShadowLegacyCaseAndAmbiguity(t *testing.T) {
	db, _, id, c := shadowFixture(t)
	old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "ssh", c, "private-user", "", "saved")}
	for _, statement := range []string{`UPDATE Nodes SET Id=upper(Id),CredentialId=upper(CredentialId);`, `UPDATE CredentialProfiles SET Id=upper(Id);`} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := compareLiveResolver(context.Background(), db, old, "linux"); err != nil || len(d) != 0 {
		t.Fatal(d, err)
	}
	if _, err := db.Exec(`INSERT INTO CredentialProfiles(Id,Name,Username,Kind,Protocol,SecretProvider,CreatedAt) VALUES(?,'Duplicate','another-user',0,0,0,'fixture');`, c); err != nil {
		t.Fatal(err)
	}
	if d, err := compareLiveResolver(context.Background(), db, old, "linux"); err != errResolverSnapshot || d != nil {
		t.Fatal("ambiguous credential accepted", d, err)
	}
	if _, err := db.Exec(`DELETE FROM CredentialProfiles WHERE Id=?;`, c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO Nodes(Id,Name,Kind,Protocol,Host,CreatedAt,UpdatedAt) VALUES(?,'Duplicate',1,0,'another-host','fixture','fixture');`, id); err != nil {
		t.Fatal(err)
	}
	if d, err := compareLiveResolver(context.Background(), db, old, "linux"); err != errResolverSnapshot || d != nil {
		t.Fatal("ambiguous node accepted", d, err)
	}
}

func TestResolverSnapshotShadowReadTransactionIsCoherent(t *testing.T) {
	db, path, id, c := shadowFixture(t)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		t.Fatal(err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	chain, err := readShadowChain(context.Background(), tx, id)
	if err != nil || len(chain) != 1 {
		t.Fatal(err)
	}
	before, err := readShadowCredential(context.Background(), tx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(`UPDATE CredentialProfiles SET Username='concurrent-user';`); err != nil {
		t.Fatal(err)
	}
	after, err := readShadowCredential(context.Background(), tx, c)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("mixed database snapshots", err)
	}
}

func TestResolverSnapshotShadowContentionSkipsWithoutChangingPolicy(t *testing.T) {
	db, path, id, c := shadowFixture(t)
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE;`); err != nil {
		t.Fatal(err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	connection, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(context.Background(), `BEGIN EXCLUSIVE;`); err != nil {
		t.Fatal(err)
	}
	defer connection.ExecContext(context.Background(), `ROLLBACK;`)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "ssh", c, "private-user", "", "saved")}
	if d, err := compareLiveResolver(ctx, db, old, "linux"); err != errResolverSnapshot || d != nil {
		t.Fatal("locked read accepted", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("shadow waited on SQLite lock for %v", elapsed)
	}
	var timeout int
	if err := db.QueryRow(`PRAGMA busy_timeout;`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Fatal("reader changed busy policy", timeout, err)
	}
}

func TestResolverSnapshotShadowBoundsAncestorDepth(t *testing.T) {
	db, _, id, c := shadowFixture(t)
	current := id
	for depth := 1; depth <= vaultstore.MaxNodeDepth; depth++ {
		parent := uuid.NewString()
		if _, err := db.Exec(`INSERT INTO Nodes(Id,Name,Kind,CreatedAt,UpdatedAt) VALUES(?,'Ancestor',0,'fixture','fixture');`, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE Nodes SET ParentId=? WHERE Id=?;`, parent, current); err != nil {
			t.Fatal(err)
		}
		current = parent
		if depth >= vaultstore.MaxNodeDepth-1 {
			old := []resolver.EffectiveCredentialSnapshot{legacyResolutionSnapshot(id, "ssh", c, "private-user", "", "saved")}
			differences, err := compareLiveResolver(context.Background(), db, old, "linux")
			if depth == vaultstore.MaxNodeDepth-1 {
				if err != nil || len(differences) != 0 {
					t.Fatal("valid maximum depth rejected", err)
				}
			} else if err != errResolverSnapshot || differences != nil {
				t.Fatal("excess depth accepted", err)
			}
		}
	}
}
