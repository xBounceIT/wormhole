package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
)

func TestResolverCaptureUsesCurrentMetadataWithoutSecretsOrObservations(t *testing.T) {
	db, _, id, c := shadowFixture(t)
	// The credential has no secret. Capture neither reads nor authenticates it;
	// the later secret import must do that before any destination activation.
	if _, err := db.Exec(`DROP TABLE EffectiveCredentialSnapshot;`); err != nil {
		t.Fatal(err)
	}
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	want := []resolver.EffectiveCredentialSnapshot{
		legacyResolutionSnapshot(id, "reveal", c, "private-user", "", "saved"),
		legacyResolutionSnapshot(id, "ssh", c, "private-user", "", "saved"),
		legacyResolutionSnapshot(id, "sftp", c, "private-user", "", "saved"),
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	if exists, err := tableExists(db, "EffectiveCredentialSnapshot"); err != nil || exists {
		t.Fatal("capture changed schema", err)
	}
	if _, err := db.Exec(`UPDATE CredentialProfiles SET Username='edited-user';`); err != nil {
		t.Fatal(err)
	}
	again, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != nil || len(again) != 3 || again[0].Username != "edited-user" {
		t.Fatal("stale capture", err)
	}
}

func TestResolverCaptureMatchesActualLegacySSHAndReveal(t *testing.T) {
	db, path := snapshotDatabase(t)
	c, err := createCredential(path, credentialCreateRequest{Name: "Saved", Protocol: "ssh", Username: "saved-user", Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := createWorkspaceNode(path, workspaceNodeWriteRequest{Name: "Ancestor", Kind: "folder"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET Username='ancestor-user' WHERE Id=?;`, folder); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, request := range []workspaceNodeWriteRequest{
		{Name: "Saved SSH", Kind: "connection", Protocol: "ssh", Host: "ssh.example", CredentialMode: 2, CredentialID: c.ID},
		{Name: "Inline SFTP", Kind: "connection", ParentID: folder, Protocol: "sftp", Host: "sftp.example", CredentialMode: 1, InlinePasswordAction: "set", InlinePassword: "synthetic-inline"},
		{Name: "No saved identity", Kind: "connection", Protocol: "ssh", Host: "none.example", Username: "manual-user", CredentialMode: 1},
		{Name: "Web", Kind: "connection", Protocol: "https", Host: "web.example"},
	} {
		id, err := createWorkspaceNode(path, request)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	// Capture before any connection has produced a runtime observation.
	captured, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != nil || len(captured) != 10 {
		t.Fatal("incomplete capture", len(captured), err)
	}
	for i, id := range ids {
		if i != 3 {
			if _, err := loadSSHTarget(path, id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := showWorkspaceNodeCredentials(path, workspaceNodeRequest{NodeID: id}, filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range captured {
		actual := readObservedSnapshot(t, db, expected.NodeID, expected.ProtocolPath)
		if actual != expected {
			t.Fatal("capture differs from active legacy walk", actual, expected)
		}
	}
	// This intentional legacy behavior must survive capture before migration pins.
	for _, s := range captured {
		if s.NodeID == ids[1] && (s.Username != "ancestor-user" || s.SourceKind != "inline") {
			t.Fatal("inline inheritance changed", s)
		}
	}
}

func TestResolverCaptureRejectsIncompleteInputWithoutPartialResult(t *testing.T) {
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{"missing parent", `UPDATE Nodes SET ParentId=?;`, []any{uuid.NewString()}},
		{"cycle", `UPDATE Nodes SET ParentId=Id;`, nil},
		{"invalid kind", `UPDATE Nodes SET Kind=2;`, nil},
		{"invalid id", `UPDATE Nodes SET Id='';`, nil},
		{"noncanonical id", `UPDATE Nodes SET Id='not-an-id';`, nil},
		{"missing credential", `DELETE FROM CredentialProfiles;`, nil},
		{"provider", `UPDATE CredentialProfiles SET SecretProvider=1;`, nil},
		{"wrong protocol", `UPDATE CredentialProfiles SET Protocol=1;`, nil},
		{"missing username", `UPDATE CredentialProfiles SET Username='';`, nil},
		{"oversized username", `UPDATE CredentialProfiles SET Username=?;`, []any{strings.Repeat("x", 2049)}},
		{"invalid username", `UPDATE CredentialProfiles SET Username=?;`, []any{"\x00private"}},
		{"missing table", `DROP TABLE Nodes;`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _, _, _ := shadowFixture(t)
			if _, err := db.Exec(`PRAGMA foreign_keys=OFF;`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.query, test.args...); err != nil {
				t.Fatal(err)
			}
			if got, err := captureLegacyResolverSnapshots(context.Background(), db); err != errResolverSnapshot || got != nil {
				t.Fatal("incomplete capture accepted", got, err)
			}
		})
	}
	db, _, id, _ := shadowFixture(t)
	if _, err := db.Exec(`INSERT INTO Nodes(Id,Name,Kind,Protocol,Host,Username,CreatedAt,UpdatedAt) VALUES(?,'Invalid second connection',1,0,'host',NULL,'fixture','fixture');`, "ffffffff-ffff-ffff-ffff-ffffffffffff"); err != nil {
		t.Fatal(err)
	}
	if got, err := captureLegacyResolverSnapshots(context.Background(), db); err != errResolverSnapshot || got != nil {
		t.Fatal("valid first connection leaked partial capture", id, got, err)
	}
	if got, err := captureLegacyResolverSnapshots(context.Background(), nil); err != errResolverSnapshot || got != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := captureLegacyResolverSnapshots(cancelled, db); err != errResolverSnapshot || got != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := captureLegacyResolverSnapshots(context.Background(), db); err != errResolverSnapshot || got != nil {
		t.Fatal(err)
	}
}

func TestResolverCaptureReaderKeepsLegacyLoadersInOneSnapshot(t *testing.T) {
	db, path, id, _ := shadowFixture(t)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	reader := resolverCaptureReader{context.Background(), tx}
	nodes, err := loadWorkspaceCredentialNodes(reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`UPDATE CredentialProfiles SET Username='concurrent-user';`); err != nil {
		t.Fatal(err)
	}
	selection, err := resolveLegacyRevealMetadata(nodes, id, func(id string) (workspaceCredentialProfile, bool, error) {
		return loadWorkspaceCredentialProfile(reader, id)
	})
	if err != nil || selection.response.Username != "private-user" {
		t.Fatal("mixed metadata revisions", err)
	}
	if selection.response.Secret != "" || selection.response.Found {
		t.Fatal("metadata path supplied a secret")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != nil || len(got) != 3 || got[0].Username != "concurrent-user" {
		t.Fatal("new capture did not see committed edit", err)
	}
}

func TestResolverCaptureEmptyWorkspace(t *testing.T) {
	db, _ := snapshotDatabase(t)
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatal("empty workspace rejected", err)
	}
}

func TestResolverCapturePreservesDifferentSSHAndRevealChoices(t *testing.T) {
	db, _, id, credential := shadowFixture(t)
	parent := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO Nodes(Id,Name,Kind,Protocol,CredentialMode,CredentialId,CreatedAt,UpdatedAt) VALUES(?,'Different protocol context',0,1,2,?,'fixture','fixture');`, parent, credential); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE Nodes SET ParentId=?,CredentialMode=0,CredentialId=NULL,Username='leaf-user' WHERE Id=?;`, parent, id); err != nil {
		t.Fatal(err)
	}
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	want := []resolver.EffectiveCredentialSnapshot{
		legacyResolutionSnapshot(id, "reveal", credential, "leaf-user", "", "saved"),
		legacyResolutionSnapshot(id, "ssh", "", "leaf-user", "", "none"),
		legacyResolutionSnapshot(id, "sftp", "", "leaf-user", "", "none"),
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("legacy path-specific choices were merged", got, err)
	}
}

func TestResolverCaptureVNCRequiresEveryApplicablePath(t *testing.T) {
	db, _, id, _ := shadowFixture(t)
	// VNC's existing exact-ID lookup cannot read this normalized legacy key.
	// A successful capture may not omit VNC and return only the Reveal result.
	if _, err := db.Exec(`UPDATE Nodes SET Id=upper(Id),Protocol=6; UPDATE CredentialProfiles SET Protocol=6;`); err != nil {
		t.Fatal(err)
	}
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	if err != errResolverSnapshot || got != nil {
		t.Fatal("missing VNC path certified", id, got, err)
	}
}

func TestResolverCaptureVNCSecretPresenceAndEligibility(t *testing.T) {
	db, _, id, credential := shadowFixture(t)
	if _, err := db.Exec(`UPDATE Nodes SET Protocol=6; UPDATE CredentialProfiles SET Protocol=6,Username=NULL;`); err != nil {
		t.Fatal(err)
	}
	check := func(source, selected string) {
		t.Helper()
		got, err := captureLegacyResolverSnapshots(context.Background(), db)
		if err != nil || len(got) != 2 {
			t.Fatal("VNC capture failed", got, err)
		}
		want := legacyResolutionSnapshot(id, "vnc", selected, "", "", source)
		if got[1] != want {
			t.Fatal(got[1], want)
		}
	}
	check("none", "")
	// Deliberately unusable ciphertext proves capture does not decrypt. Secret
	// import must reject it; this result alone is never a migration capability.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS CredentialSecrets(Id TEXT PRIMARY KEY,Secret TEXT,Encoding TEXT,UpdatedAt TEXT); INSERT INTO CredentialSecrets VALUES(?,'synthetic-invalid-ciphertext','unsupported-fixture','fixture');`, credential); err != nil {
		t.Fatal(err)
	}
	check("saved", credential)
	for _, assignment := range []string{"SecretProvider=1", "SecretProvider=0,Kind=1", "Kind=0,Protocol=0"} {
		if _, err := db.Exec(`UPDATE CredentialProfiles SET ` + assignment); err != nil {
			t.Fatal(err)
		}
		check("none", "")
	}
	// Reveal ignores unsupported inline VNC, but VNC itself still selects the
	// saved reference. That independent choice must also reject ambiguous IDs.
	if _, err := db.Exec(`UPDATE CredentialProfiles SET Protocol=6,Kind=0,SecretProvider=0; UPDATE Nodes SET UseInlinePassword=1;`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO CredentialProfiles(Id,Name,Username,Kind,Protocol,SecretProvider,CreatedAt) VALUES(?,'Ambiguous VNC',NULL,0,6,0,'fixture');`, strings.ToUpper(credential)); err != nil {
		t.Fatal(err)
	}
	if got, err := captureLegacyResolverSnapshots(context.Background(), db); err != errResolverSnapshot || got != nil {
		t.Fatal("ambiguous VNC selected despite different Reveal path", got, err)
	}
}

func TestResolverCaptureRDPMetadataAndGatewayWithoutSecretReads(t *testing.T) {
	db, _, id, credential := shadowFixture(t)
	gateway := uuid.NewString()
	if _, err := db.Exec(`UPDATE CredentialProfiles SET Protocol=1,Username='rdp-user',Domain='DOMAIN'; UPDATE Nodes SET Protocol=1,RdpGatewayUsageMethod=1,RdpGatewayHostname='gateway.example',RdpGatewayUseSameCreds=0,RdpGatewayCredentialId=?;`, gateway); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO CredentialProfiles(Id,Name,Username,Domain,Kind,Protocol,SecretProvider,CreatedAt) VALUES(?,'Gateway','gateway-user','EDGE',0,1,0,'fixture');`, gateway); err != nil {
		t.Fatal(err)
	}
	got, err := captureLegacyResolverSnapshots(context.Background(), db)
	want := []resolver.EffectiveCredentialSnapshot{
		legacyResolutionSnapshot(id, "reveal", credential, "rdp-user", "DOMAIN", "saved"),
		legacyResolutionSnapshot(id, "rdp", credential, "rdp-user", "DOMAIN", "saved"),
		legacyResolutionSnapshot(id, "rdp-gateway", gateway, `EDGE\gateway-user`, "", "saved"),
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	if _, err := db.Exec(`UPDATE CredentialProfiles SET SecretProvider=1 WHERE Id=?;`, gateway); err != nil {
		t.Fatal(err)
	}
	if got, err := captureLegacyResolverSnapshots(context.Background(), db); err != errResolverSnapshot || got != nil {
		t.Fatal("dynamic gateway guessed from cached metadata", got, err)
	}
}

func TestResolverCaptureNilLegacyCredentialReader(t *testing.T) {
	var database *sql.DB
	for _, reader := range []sqlMetadataReader{nil, database} {
		if _, err := resolveNodeCredentialID(reader, uuid.NewString(), 1); err == nil {
			t.Fatal("missing database accepted")
		}
	}
}
