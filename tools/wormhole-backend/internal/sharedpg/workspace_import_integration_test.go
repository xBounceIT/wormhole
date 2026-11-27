package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

const workspaceImportFixtureNodeCount = 5

func TestPostgresWorkspaceImportCommitsAtomically(t *testing.T) {
	settings, secret := postgresTestClusterTLS(t, true)
	// This fixture also deploys and restores multiple independent clusters.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	workspace := uuid.New()
	const tag = "importtest"
	if _, err := DeploySchema(ctx, settings, secret, tag, workspace.String()); err != nil {
		t.Fatal(err)
	}
	draft, factors, err := prepareWorkspaceBootstrapFromDeployment(ctx, settings, secret, workspace, tag, "first-admin", vault.Standard, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer factors.wipe()
	if _, err := publishWorkspaceBootstrap(ctx, draft, settings.DeviceRole, secret, factors.invitationCode[:]); err != nil {
		t.Fatal(err)
	}
	dba, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(dba)
	ask := bytes.Repeat([]byte{51}, 32)
	defer vault.Wipe(ask)
	recover := restoredAdministratorFixture{join: func(t *testing.T, target WorkspaceRecoveryTarget, conn *pgconn.PgConn, password []byte, login string, check joinedAdministratorCheck) {
		t.Helper()
		joinRestoredAdministrator(t, ctx, target, conn, password, draft, factors, ask, login, check)
	}}
	if electron := os.Getenv("WORMHOLE_TEST_REENROLLMENT_ELECTRON"); electron != "" {
		recover.appOffer = func(t *testing.T, target WorkspaceRecoveryTarget, password []byte, login string) ([]byte, []byte, []byte) {
			t.Helper()
			invitation := publishRestoredAdministrator(t, ctx, target, password, draft, factors, "application-issuer")
			defer invitation.Close()
			return issueAccountReenrollmentInElectron(t, ctx, invitation, ask, login, electron)
		}
	}
	joinTestAdministrator(t, ctx, draft.invitation, factors.invitationCode[:], draft.organisation.Signing, draft.recovery.Signing, ask, func(raw []byte) {
		var archive WorkspaceRecoverySnapshot
		if json.Unmarshal(raw, &archive) != nil {
			t.Fatal("could not inspect the committed import in its recovery export")
		}
		found := 0
		history := 0
		webTargets := 0
		for _, record := range archive.Records {
			if record.Relation == "node_import_data" {
				found++
			}
			if record.Relation == "workspace_import_receipts" || record.Relation == "web_session_checkpoints" || record.Relation == "web_session_views" {
				t.Fatal("operational authority entered a recovery archive")
			}
			if record.Relation == "user_enrollment_history" {
				history++
			}
			if record.Relation == "account_suspension_web_targets" {
				webTargets++
			}
		}
		if found != workspaceImportFixtureNodeCount {
			t.Fatal("the backup lost imported note or pin proofs", found)
		}
		if history != 1 {
			t.Fatal("expected one historical enrollment in the archive", history)
		}
		if webTargets != 1 {
			t.Fatal("expected the captured web target in the recovery archive", webTargets)
		}
		checkWorkspaceRecoveryRestore(t, ctx, dba, raw, draft, factors, ask, workspaceImportFixtureNodeCount)
	}, func(session *Session, trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys) {
		checkWorkspaceImportCommit(t, ctx, dba, session, trust, tls, actor, draft.boundary, recover)
		checkEnrollmentHistory(t, ctx, dba, trust, actor)
	})
}

func localWorkspaceImportFixture(t *testing.T, ctx context.Context) (*localvault.Owner, localvault.WorkspaceImport, string, string, string, string, string) {
	t.Helper()
	identity := vaultstore.Identity{WorkspaceID: uuid.NewString(), FileID: uuid.NewString(), Root: vaultstore.KeyRef{ID: uuid.NewString(), Version: 1}}
	key := vault.NewRecoveryKey()
	defer vault.Wipe(key)
	slot, err := vault.CreateRecoverySlot(identity.WorkspaceID, uuid.NewString(), 1, key, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	slots := vault.SlotFile{FormatVersion: 1, VaultID: identity.WorkspaceID, FileID: identity.FileID, Sequence: 1, FileEpoch: 1, Slots: []vault.Slot{slot}, RootKeyID: identity.Root.ID, RootKeyVersion: 1}
	raw, err := vault.EncodeSlotFile(key, slots)
	if err != nil {
		t.Fatal(err)
	}
	slots, err = vault.DecodeSlotFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := localvault.Open(ctx, filepath.Join(t.TempDir(), "source.db"), localvault.OpenOptions{Identity: identity, Slots: slots, MinimumSequence: 1, Create: true}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	profile := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Imported account", Protocol: "ssh", Kind: "password", Provider: "local", Username: "fixture-user"}
	if _, err := owner.PutCredential(ctx, profile, []localvault.SecretChange{{Field: "password", Value: []byte("fixture-only-private-credential")}}, 0); err != nil {
		t.Fatal(err)
	}
	sftpProfile := profile
	sftpProfile.ID, sftpProfile.Name, sftpProfile.Username = uuid.NewString(), "Imported SFTP account", "sftp-candidate-user"
	if _, err := owner.PutCredential(ctx, sftpProfile, []localvault.SecretChange{{Field: "password", Value: []byte("fixture-only-sftp-credential")}}, 0); err != nil {
		t.Fatal(err)
	}
	ssl := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Imported SSL fallback", Kind: 2}
	ipsec := vaultstore.TunnelMetadata{ID: uuid.NewString(), Name: "Imported IPsec primary", Kind: 9}
	if _, err := owner.PutTunnel(ctx, ssl, []byte(importedFallbackSettings), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.PutTunnel(ctx, ipsec, []byte(ssl.ID), 0); err != nil {
		t.Fatal(err)
	}
	host, protocol := "import.example", 7
	enableTunnel := true
	pending := vaultstore.NodeMetadata{ID: uuid.NewString(), Kind: 1, Name: "Imported pinned account", Host: &host, Protocol: &protocol,
		CredentialID: &profile.ID, TunnelEnabled: &enableTunnel, TunnelConfigID: &ipsec.ID}
	pinned, err := owner.PutNode(ctx, pending, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var previous, candidate []resolver.EffectiveCredentialSnapshot
	for _, path := range resolver.AccountPaths(protocol) {
		res, err := owner.ResolveConnectionPath(ctx, pinned.ID, "", path)
		if err != nil {
			t.Fatal(err)
		}
		old := res.Account
		old.ResolverVersion = 0
		if path == "ssh" {
			old.Username = "original-pinned-user"
		}
		if path == "sftp" {
			old.Username = "original-sftp-user"
			old.CredentialID = sftpProfile.ID
		}
		previous, candidate = append(previous, old), append(candidate, res.Account)
	}
	pins, err := resolver.BuildMigration(identity.WorkspaceID, previous, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ImportResolverMigration(ctx, pinned.ID, pins, pinned.RowVersion); err != nil {
		t.Fatal(err)
	}
	plain := pending
	plain.ID, plain.Name = uuid.NewString(), "Imported connection with notes"
	plain.TunnelEnabled, plain.TunnelConfigID = nil, nil
	rdp := 1
	plain.Protocol, plain.CredentialID, plain.Username = &rdp, nil, &profile.Username
	if _, err := owner.PutNode(ctx, plain, []localvault.SecretChange{{Field: "notes", Value: []byte("fixture-only-private-note")}}, 0); err != nil {
		t.Fatal(err)
	}
	sharedNote := plain
	sharedNote.ID, sharedNote.Name = uuid.NewString(), "Imported shared note"
	if _, err := owner.PutNode(ctx, sharedNote, []localvault.SecretChange{{Field: "notes", Value: []byte(importedGroupNote)}}, 0); err != nil {
		t.Fatal(err)
	}
	rdpID := localRDPImportFixture(t, ctx, owner, identity.WorkspaceID)
	webID := localWebImportFixture(t, ctx, owner, identity.WorkspaceID, profile.ID, ipsec.ID)
	source, err := owner.CaptureWorkspaceImport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return owner, source, pinned.ID, plain.ID, rdpID, sharedNote.ID, webID
}

const importedFallbackSettings = `{"settings":"synthetic-ssl-fallback"}`

func localWebImportFixture(t *testing.T, ctx context.Context, owner *localvault.Owner, workspace, credential, tunnel string) string {
	t.Helper()
	host, path, protocol := "web.example", "/login", 4
	enabled := true
	node, err := owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Imported HTTPS", Kind: 1,
		Protocol: &protocol, Host: &host, HTTPPath: &path, TunnelEnabled: &enabled, TunnelConfigID: &tunnel}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err := owner.ResolveConnectionPath(ctx, node.ID, "", "reveal")
	if err != nil {
		t.Fatal(err)
	}
	previous := current.Account
	previous.ResolverVersion, previous.SourceKind = 0, "saved"
	previous.CredentialID, previous.Username = credential, "original-web-account"
	migration, err := resolver.BuildMigration(workspace, []resolver.EffectiveCredentialSnapshot{previous}, []resolver.EffectiveCredentialSnapshot{current.Account})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ImportResolverMigration(ctx, node.ID, migration, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	return node.ID
}

func localRDPImportFixture(t *testing.T, ctx context.Context, owner *localvault.Owner, workspace string) string {
	t.Helper()
	primary := vaultstore.CredentialMetadata{ID: uuid.NewString(), Name: "Desktop", Protocol: "rdp", Kind: "password", Provider: "local", Username: "desktop-candidate"}
	gateway := primary
	gateway.ID, gateway.Name, gateway.Username = uuid.NewString(), "Gateway", "gateway-candidate"
	for _, profile := range []struct {
		meta     vaultstore.CredentialMetadata
		password string
	}{{primary, "synthetic-desktop-value"}, {gateway, "synthetic-gateway-value"}} {
		if _, err := owner.PutCredential(ctx, profile.meta, []localvault.SecretChange{{Field: "password", Value: []byte(profile.password)}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	host, gatewayHost, protocol, gatewayMethod, configuredSame := "desktop.example", "gateway.example", 1, 1, true
	node, err := owner.PutNode(ctx, vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "Imported RDP", Kind: 1, Protocol: &protocol, Host: &host,
		CredentialID: &primary.ID, RDPGatewayUsageMethod: &gatewayMethod, RDPGatewayHostname: &gatewayHost, RDPGatewayUseSameCreds: &configuredSame}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var previous, candidate []resolver.EffectiveCredentialSnapshot
	for _, path := range resolver.AccountPaths(protocol) {
		res, err := owner.ResolveConnectionPath(ctx, node.ID, "", path)
		if err != nil {
			t.Fatal(err)
		}
		old := res.Account
		old.ResolverVersion = 0
		switch path {
		case "rdp":
			old.Username, old.Domain = "original-desktop", "DESKTOP"
		case "rdp-gateway":
			old.Username, old.Domain, old.CredentialID = "original-gateway", "GATEWAY", gateway.ID
		}
		previous, candidate = append(previous, old), append(candidate, res.Account)
	}
	pins, err := resolver.BuildMigration(workspace, previous, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ImportResolverMigration(ctx, node.ID, pins, node.RowVersion); err != nil {
		t.Fatal(err)
	}
	return node.ID
}

func checkWorkspaceImportCommit(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session,
	trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys, boundary vault.BoundaryManifest, recover restoredAdministratorFixture) {
	t.Helper()
	owner, source, pins, notes, rdpSource, sharedNote, webSource := localWorkspaceImportFixture(t, ctx)
	current, personal, shared := checkWorkspaceImportDestinations(t, ctx, dba, session, trust, tls, actor, boundary.BoundaryID)
	trust = current
	selection := workspaceimport.Selection{}
	for _, profile := range source.Catalog.Credentials {
		if profile.Protocol != "rdp" {
			selection.Shared = append(selection.Shared, workspaceimport.ItemID{Kind: "credential", ID: profile.ID})
		}
	}
	for _, node := range source.Catalog.Nodes {
		if node.ID != notes && node.ID != rdpSource {
			selection.Shared = append(selection.Shared, workspaceimport.ItemID{Kind: "node", ID: node.ID})
		}
	}
	for _, tunnel := range source.Catalog.Tunnels {
		selection.Shared = append(selection.Shared, workspaceimport.ItemID{Kind: "tunnel", ID: tunnel.ID})
	}
	target := workspaceimport.Target{WorkspaceID: trust.WorkspaceID, UserID: trust.UserID, RequestID: uuid.New()}
	preview, plan, err := workspaceimport.Prepare(ctx, source, target, selection)
	if err != nil || plan == nil {
		t.Fatal("could not prepare source for the real target", err)
	}
	for _, item := range preview.Items {
		if item.Kind == "node" && (item.Destination == workspaceimport.Personal) != (item.ID == notes || item.ID == rdpSource) {
			t.Fatal("the unselected item did not default to a personal destination")
		}
	}
	account, err := trust.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := session.AccountEnrollmentMaterial(ctx)
	if err != nil || cert.EnrollmentCertificate == nil {
		t.Fatal("could not retrieve the admitted writer certification", err)
	}
	authority := workspaceimport.Authority{Trust: account, Account: *trust.Account, Enrollment: *cert.EnrollmentCertificate,
		EscrowPersonal: true, Shared: &workspaceimport.ImportBoundary{Manifest: *shared, MinimumRevision: shared.Revision},
		Personal: &workspaceimport.ImportBoundary{Manifest: *personal, MinimumRevision: personal.Revision}}
	transform := func(kind int, settings []byte, translate func(string) (string, error)) ([]byte, error) {
		if kind == 9 {
			id, err := translate(string(settings))
			return []byte(id), err
		}
		return settings, nil
	}
	sealed, err := plan.Seal(ctx, owner, authority, actor.SigningSeed, transform)
	if err != nil {
		t.Fatal("could not seal the real workspace import", err)
	}
	public, err := actor.Public()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.CommitWorkspaceImport(ctx, trust, tls, vault.UserPublicKeys{}, sealed); err != vault.ErrAuthentication {
		t.Fatal("a substituted writer got to the import transaction", err)
	}
	body, signature := sealed.PostgresPayload()
	defer vault.Wipe(body)
	read := func(query string) string {
		t.Helper()
		row, err := readDeploymentRow(ctx, dba, query, 1)
		if err != nil {
			t.Fatal(err)
		}
		return string(row[0])
	}
	commitRaw := func(document []byte) error {
		return session.queryServerCA(ctx, trust, commitWorkspaceImportSQL, [][]byte{document, hex.AppendEncode(nil, signature)}, 64, 1, 1,
			func([][][]byte) error { return nil })
	}
	var broken map[string]json.RawMessage
	var values []map[string]json.RawMessage
	if json.Unmarshal(body, &broken) != nil || json.Unmarshal(broken["values"], &values) != nil || len(values) != 8 {
		t.Fatal("could not isolate final field for rollback test")
	}
	values[len(values)-1]["keyCopy"] = json.RawMessage(`{"envelope":{"formatVersion":1,"suiteId":2,"enc":"AA=="}}`)
	broken["values"], err = json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	badBody, err := json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	const emptyGraph = `SELECT (NOT EXISTS(SELECT FROM wormhole_data.workspace_import_receipts)
        AND NOT EXISTS(SELECT FROM wormhole_data.nodes) AND NOT EXISTS(SELECT FROM wormhole_data.credential_profiles)
        AND NOT EXISTS(SELECT FROM wormhole_data.tunnel_profiles)
        AND NOT EXISTS(SELECT FROM wormhole_data.secret_values)
        AND NOT EXISTS(SELECT FROM wormhole_data.keys WHERE kind='dek')
        AND NOT EXISTS(SELECT FROM wormhole_data.node_import_data))::text`
	grant := func(permissions string) {
		t.Helper()
		result := dba.ExecParams(ctx, `UPDATE wormhole_data.boundary_grants SET permissions=$1::integer
            WHERE boundary_id IN ($2::uuid,$3::uuid) AND user_id=$4::uuid`,
			[][]byte{[]byte(permissions), []byte(boundary.BoundaryID.String()), []byte(personal.BoundaryID.String()), []byte(trust.UserID.String())}, nil, nil, nil).Read()
		if result.Err != nil || result.CommandTag.RowsAffected() != 2 {
			t.Fatal("could not adjust test boundary Write permission", result.Err)
		}
	}
	grant("1")
	if _, err := session.CommitWorkspaceImport(ctx, trust, tls, public, sealed); err == nil || read(emptyGraph) != "true" {
		t.Fatal("a member without boundary Write could commit", err)
	}
	grant("31")
	seq := read(`SELECT change_seq::text FROM wormhole_data.workspace_meta WHERE singleton`)
	if err := commitRaw(badBody); !errors.Is(err, ErrWorkspaceImport) || read(emptyGraph) != "true" ||
		read(`SELECT change_seq::text FROM wormhole_data.workspace_meta WHERE singleton`) != seq {
		t.Fatal("invalid final field retained writes or catalog changes", err)
	}
	approval, err := plan.ApprovalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if found, err := session.SetupImportCommitted(ctx, trust, tls, target, approval, actor); err != nil || found {
		t.Fatal("a setup receipt existed before publication", err)
	}
	if err := session.CommitSetupWorkspaceImport(ctx, trust, tls, target, approval, actor, sealed); err != nil {
		t.Fatal("certified setup import did not commit", err)
	}
	if found, err := session.SetupImportCommitted(ctx, trust, tls, target, approval, actor); err != nil || !found {
		t.Fatal("the committed approval could not be authenticated", err)
	}
	resealed, err := plan.Seal(ctx, owner, authority, actor.SigningSeed, transform)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.CommitSetupWorkspaceImport(ctx, trust, tls, target, approval, actor, resealed); err != nil {
		t.Fatal("restarting the approved import could not reconcile", err)
	}
	changed := approval
	changed[0] ^= 1
	if found, err := session.SetupImportCommitted(ctx, trust, tls, target, changed, actor); found || !errors.Is(err, ErrSetupImportConflict) {
		t.Fatal("a previously committed import covered different choices", err)
	}
	if err := session.CommitSetupWorkspaceImport(ctx, trust, tls, target, changed, actor, resealed); !errors.Is(err, ErrSetupImportConflict) {
		t.Fatal("a different approval altered the existing import", err)
	}
	if status, err := session.CommitWorkspaceImport(ctx, trust, tls, public, sealed); err != nil || status != "already-imported" {
		t.Fatal("identical receipt retry modified the import", status, err)
	}
	if err := commitRaw(append([]byte{' '}, body...)); !errors.Is(err, ErrWorkspaceImport) {
		t.Fatal("an allocated request was reused with a different document", err)
	}
	if read(`SELECT ((SELECT count(*) FROM wormhole_data.nodes)=5 AND
        (SELECT count(*) FROM wormhole_data.credential_profiles)=4 AND
        (SELECT count(*) FROM wormhole_data.workspace_import_receipts)=1 AND
        (SELECT count(*) FROM wormhole_data.node_import_data)=5 AND
        (SELECT count(*) FROM wormhole_data.secret_values)=8 AND
        (SELECT count(*) FROM wormhole_data.audit_log WHERE action='commit_workspace_import' AND outcome='imported')=1)::text`) != "true" {
		t.Fatal("the import graph, receipt and audit were not committed exactly once")
	}
	withNotes, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "node", ID: notes})
	row, err := readAccountResetRow(ctx, dba, `SELECT pg_catalog.encode(envelope,'hex') FROM wormhole_data.secret_values WHERE field='notes' AND owner_id=$1::uuid`,
		[][]byte{[]byte(withNotes)}, 1, 2048)
	if err != nil {
		t.Fatal("could not inspect the committed note envelope", err)
	}
	raw, err := hex.DecodeString(string(row[0]))
	if err != nil || bytes.Contains(raw, []byte("fixture-only-private-note")) {
		t.Fatal("a private note was persisted in plaintext", err)
	}
	if _, err := vault.DecodeSharedEnvelope(raw); err != nil {
		t.Fatal("PostgreSQL changed the canonical ciphertext serialization", err)
	}
	withPins, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "node", ID: pins})
	scoped, err := readAccountResetRow(ctx, dba, `SELECT (owner_user_id=$2::uuid AND boundary_id=$3::uuid)::text FROM wormhole_data.nodes WHERE id=$1::uuid`,
		[][]byte{[]byte(withNotes), []byte(trust.UserID.String()), []byte(personal.BoundaryID.String())}, 1, 32)
	if err != nil || string(scoped[0]) != "true" {
		t.Fatal("the personal connection escaped its owner or was written to the shared boundary", err)
	}
	scoped, err = readAccountResetRow(ctx, dba, `SELECT (count(*)=2)::text FROM wormhole_data.credential_profiles
        WHERE owner_user_id=$1::uuid AND boundary_id=$2::uuid AND protocol='rdp'`,
		[][]byte{[]byte(trust.UserID.String()), []byte(personal.BoundaryID.String())}, 1, 32)
	if err != nil || string(scoped[0]) != "true" {
		t.Fatal("personal RDP credentials escaped the importer's boundary", err)
	}
	withGateway, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "node", ID: rdpSource})
	for _, tc := range []struct {
		node uuid.UUID
		pin  string
		note uint64
	}{
		{node: uuid.MustParse(withPins), pin: "original-pinned-user"},
		{node: uuid.MustParse(withNotes), note: 1},
	} {
		input, err := session.ImportedNodeData(ctx, tc.node)
		if err != nil {
			t.Fatal("could not load import metadata", err)
		}
		next, data, err := trust.VerifyImportedNodeData(tc.node, input)
		if err != nil || data == nil || data.NoteVersion != tc.note || next.Revision <= trust.Revision {
			t.Fatal("could not verify signed import metadata", err)
		}
		trust = next
		if tc.pin == "" && len(data.Pins) != 0 {
			t.Fatal("unexpected pin on the note-only connection")
		}
		if tc.pin != "" && (len(data.Pins) != 2 || data.Pins[0].ProtocolPath != "sftp" || data.Pins[1].ProtocolPath != "ssh" || data.Pins[1].Username != tc.pin) {
			t.Fatal("the attachment did not preserve the exact historical SSH identity")
		}
	}
	nodeWithPins := uuid.MustParse(withPins)
	if supported, err := session.ConnectionPathsSupported(ctx); err != nil || !supported {
		t.Fatal("schema 55 did not advertise the connection path APIs", err)
	}
	defaultPlan, err := session.ConnectionPlanPath(ctx, nodeWithPins, DefaultConnectionPath)
	if err != nil {
		t.Fatal("could not discover the connection's inherited account path", err)
	}
	if _, resolved, err := trust.VerifyConnectionPlan(ctx, nodeWithPins, defaultPlan); err != nil || resolved.Path != "sftp" || resolved.Plan.Username != "original-sftp-user" {
		t.Fatal("the protocol-7 node did not pick its SFTP pin when asked for the default", err)
	}
	revisions := map[string]bool{}
	for _, path := range []struct{ name, username string }{
		{"ssh", "original-pinned-user"},
		{"sftp", "original-sftp-user"},
		{"reveal", "fixture-user"},
	} {
		input, err := session.ConnectionPlanPath(ctx, nodeWithPins, path.name)
		if err != nil {
			t.Fatalf("%s plan unavailable: %v", path.name, err)
		}
		next, verified, err := trust.VerifyConnectionPlan(ctx, nodeWithPins, input)
		if err != nil || verified.Path != path.name || verified.Plan.Username != path.username ||
			verified.Plan.Credential.Kind != "saved" || verified.Plan.Host != "import.example" ||
			verified.Revision == "" || revisions[verified.Revision] {
			t.Fatalf("%s plan did not preserve the expected authenticated identity and target: %v", path.name, err)
		}
		trust = next
		revisions[verified.Revision] = true
	}
	t.Run("ssh-host-pin", func(t *testing.T) { checkImportedSSHHostPin(t, ctx, dba, session, trust, nodeWithPins, actor) })
	t.Run("update-node", func(t *testing.T) { checkImportedNodeEdit(t, ctx, dba, session, trust, nodeWithPins, actor) })
	checkImportedPathReleases(t, ctx, session, trust, nodeWithPins, actor.EncryptionPrivate, uuid.Nil)
	var primary, fallback uuid.UUID
	for _, tunnel := range source.Catalog.Tunnels {
		id, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "tunnel", ID: tunnel.ID})
		switch tunnel.Kind {
		case 9:
			primary = uuid.MustParse(id)
		case 2:
			fallback = uuid.MustParse(id)
		}
	}
	checkImportedFallbackRelease(t, ctx, session, trust, nodeWithPins, primary, fallback, actor.EncryptionPrivate, uuid.Nil)
	if read(`SELECT ((SELECT count(*) FROM wormhole_data.audit_log WHERE action='begin_use_path'
      AND outcome='issued' AND protocol_path IN ('ssh','sftp'))=3)::text`) != "true" {
		t.Fatal("each explicit path must have one committed audit record")
	}
	if _, err := session.ConnectionPlan(ctx, uuid.MustParse(withPins)); !errors.Is(err, ErrImportedConnectionPins) {
		t.Fatal("older resolver could use the wrong inherited account", err)
	}
	publicPlan, err := session.ConnectionPlan(ctx, uuid.MustParse(withNotes))
	if err != nil {
		t.Fatal("a note-only import could not use its ordinary credential", err)
	}
	if _, verified, err := trust.VerifyConnectionPlan(ctx, uuid.MustParse(withNotes), publicPlan); err != nil || verified.Plan.Username != "fixture-user" {
		t.Fatal("native client could not verify the imported catalog seals", err)
	}
	pending, err := session.BeginUsePath(ctx, nodeWithPins, "ui", "sftp")
	if err != nil {
		t.Fatal("could not issue the path ticket for the replacement test", err)
	}
	ordinary, err := session.BeginUse(ctx, uuid.MustParse(withNotes), "ui")
	if err != nil || ordinary.Path != "" {
		t.Fatal("ordinary release could not replace a protocol-specific ticket", err)
	}
	checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH015", []byte(withPins), []byte(pending.Ticket.String()), []byte("sftp"))
	if _, err := session.FetchSecret(ctx, *ordinary); err != nil {
		t.Fatal("ordinary release failed on the upgraded schema", err)
	}
	checkImportedRDPAccounts(t, ctx, session, trust, uuid.MustParse(withGateway), uuid.MustParse(withNotes), actor.EncryptionPrivate)
	withWeb, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "node", ID: webSource})
	checkImportedWebPlan(t, ctx, session, trust, uuid.MustParse(withWeb), nodeWithPins, primary, fallback, actor.EncryptionPrivate, grant, read)
	t.Run("protocol-edit-permissions", func(t *testing.T) {
		checkProtocolEditPermissions(t, ctx, session, trust, actor, uuid.MustParse(withGateway), uuid.MustParse(withWeb), grant)
	})
	checkImportedWebSuspensionInventory(t, ctx, dba, session, trust, uuid.MustParse(withWeb), nodeWithPins, grant)
	grant("1")
	checkImportedQueryDenied(t, ctx, session, importedNodeDataSQL, "WH014", []byte(withPins))
	checkImportedNoteView(t, ctx, dba, session, trust, uuid.MustParse(withNotes), nodeWithPins, actor.EncryptionPrivate, grant)
	grant("2")
	if intent, err := session.BeginNoteView(ctx, uuid.MustParse(withNotes), 1); err != nil || intent != nil {
		t.Fatal("a reader without boundary View received a note ticket", err)
	}
	grant("31")
	if _, err := session.ImportedNodeData(ctx, uuid.MustParse(withPins)); err != nil {
		t.Fatal("restoring Use did not restore the metadata read", err)
	}
	withSharedNote, _, _ := plan.DestinationFor(workspaceimport.ItemID{Kind: "node", ID: sharedNote})
	group := checkPostgresGroupKeyProvisioning(t, ctx, dba, session, trust, tls, actor)
	checkGroupBoundaryRelease(t, ctx, dba, session, trust, tls, actor, group, boundary,
		uuid.MustParse(withSharedNote), nodeWithPins, primary, fallback, recover)
}

func checkImportedWebSuspensionInventory(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, web, unopened uuid.UUID, grant func(string)) {
	t.Helper()
	use := func(sql string, args ...string) {
		t.Helper()
		params := make([][]byte, len(args))
		for i, arg := range args {
			params[i] = []byte(arg)
		}
		if r := dba.ExecParams(ctx, sql, params, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	generation, err := session.OpenWebSessionView(ctx, web)
	if err != nil || generation == uuid.Nil {
		t.Fatal("the enrolled device did not get a current View generation", err)
	}
	if accepted, err := session.SetWebSessionCheckpoint(ctx, web, uuid.New(), true); accepted || err != nil {
		t.Fatal("a stale generation could leave a checkpoint marker", err)
	}
	if accepted, err := session.SetWebSessionCheckpoint(ctx, web, generation, true); !accepted || err != nil {
		t.Fatal("the real enrolled device could not report its checkpoint", err)
	}
	if accepted, err := session.SetWebSessionCheckpoint(ctx, web, generation, false); !accepted || err != nil {
		t.Fatal("the real enrolled device could not withdraw its checkpoint", err)
	}
	if len(readPersonalRotationValue(t, ctx, dba, `SELECT id::text FROM wormhole_data.nodes WHERE id=$1::uuid
        AND NOT EXISTS(SELECT FROM wormhole_data.web_session_checkpoints c WHERE c.node_id=$1::uuid)`, []byte(web.String()))) == 0 {
		t.Fatal("forget left a live checkpoint marker")
	}
	user := trust.UserID.String()
	nodeGrant := string(readPersonalRotationValue(t, ctx, dba, `SELECT permissions::text FROM wormhole_data.grants WHERE node_id=$1::uuid AND user_id=$2::uuid`, []byte(web.String()), []byte(user)))
	use(`UPDATE wormhole_data.grants SET permissions=1 WHERE node_id=$1::uuid AND user_id=$2::uuid`, web.String(), user)
	if accepted, err := session.SetWebSessionCheckpoint(ctx, web, generation, true); accepted || err != nil {
		t.Fatal("View without Use reported a checkpoint", err)
	}
	use(`UPDATE wormhole_data.grants SET permissions=$3::integer WHERE node_id=$1::uuid AND user_id=$2::uuid`, web.String(), user, nodeGrant)
	nonWebGeneration, err := session.OpenWebSessionView(ctx, unopened)
	if err != nil || nonWebGeneration == uuid.Nil {
		t.Fatal("the non-web negative case needs an existing generation", err)
	}
	if accepted, err := session.SetWebSessionCheckpoint(ctx, unopened, nonWebGeneration, true); accepted || err != nil {
		t.Fatal("a non-web target reported a cookie checkpoint", err)
	}

	subject := uuid.NewString()
	use(`INSERT INTO wormhole_data.users(id,login_name,disabled) VALUES($1::uuid,'web-exposure-fixture',true)`, subject)
	use(`INSERT INTO wormhole_data.account_suspensions(account_id,revision) VALUES($1::uuid,1)`, subject)
	request := AccountSuspensionRequest{AccountID: subject, Kind: "web-sessions"}
	if reply, err := session.AccountSuspensionInventory(ctx, trust, request); err != nil || reply.Status != "not-recorded" || reply.Page != nil {
		t.Fatal("legacy suspension was mistaken for a confirmed empty inventory", reply.Status, err)
	}
	use(`UPDATE wormhole_data.users SET disabled=false,row_version=2 WHERE id=$1::uuid`, subject)
	use(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$3::uuid,3),($2::uuid,$3::uuid,3)`, web.String(), unopened.String(), subject)
	use(`INSERT INTO wormhole_data.web_session_views(user_id,node_id) VALUES($1::uuid,$2::uuid),($1::uuid,$3::uuid)`, subject, web.String(), unopened.String())
	use(`INSERT INTO wormhole_data.devices(id,user_id,role_name,status)
        SELECT d.id,$1::uuid,'wh_importtest_d_'||d.id::text,'active' FROM (VALUES(gen_random_uuid()),(gen_random_uuid())) d(id)`, subject)
	use(`INSERT INTO wormhole_data.web_session_checkpoints(user_id,node_id,device_id)
        SELECT $1::uuid,$2::uuid,d.id FROM wormhole_data.devices d WHERE d.user_id=$1::uuid`, subject, web.String())
	use("BEGIN")
	use(`UPDATE wormhole_data.users SET disabled=true,row_version=3 WHERE id=$1::uuid`, subject)
	use("ROLLBACK")
	if got := string(readPersonalRotationValue(t, ctx, dba, `SELECT count(*)::text FROM wormhole_data.web_session_checkpoints WHERE user_id=$1::uuid`, []byte(subject))); got != "2" {
		t.Fatal("rollback retired the device evidence", got)
	}
	use(`UPDATE wormhole_data.users SET disabled=true,row_version=3 WHERE id=$1::uuid`, subject)
	if got := string(readPersonalRotationValue(t, ctx, dba, `SELECT count(*)::text FROM wormhole_data.web_session_checkpoints WHERE user_id=$1::uuid`, []byte(subject))); got != "0" {
		t.Fatal("suspension left live checkpoint authority", got)
	}
	reply, err := session.AccountSuspensionInventory(ctx, trust, request)
	if err != nil || reply.Status != "ready" || reply.Page == nil || reply.Page.Revision != "3" || len(reply.Page.Entries) != 1 ||
		reply.Page.Entries[0].ID != web.String() || reply.Page.Entries[0].Kind != "web-target" || reply.Page.Entries[0].Name != "Imported HTTPS" {
		t.Fatal("the captured inventory omitted the web target, included a dry open, or duplicated a device", reply.Status, err)
	}
	request.Revision, request.After = "2", "1"
	if reply, err := session.AccountSuspensionInventory(ctx, trust, request); err != nil || reply.Status != "stale" || reply.Page != nil {
		t.Fatal("an older suspension could access a current page", err)
	}
	request.Revision, request.After = "", ""
	grant("1")
	masked, err := session.AccountSuspensionInventory(ctx, trust, request)
	if err != nil || masked.Page == nil || len(masked.Page.Entries) != 1 || masked.Page.Entries[0] != (AccountSuspensionEntry{Position: "1"}) {
		t.Fatal("a reviewer without Manage received target metadata", err)
	}
	grant("31")
}

func checkImportedWebPlan(t *testing.T, ctx context.Context, session *Session, trust TrustState, node, ssh, primary, fallback uuid.UUID, private []byte, grant func(string), read func(string) string) {
	t.Helper()
	if supported, err := session.WebConnectionPlanSupported(ctx); err != nil || !supported {
		t.Fatal("the deployed schema did not advertise the web planning API", err)
	}
	if _, err := session.ConnectionPlan(ctx, node); !errors.Is(err, ErrImportedConnectionPins) {
		t.Fatal("the fixture needs a retained account", err)
	}
	input, err := session.ConnectionPlanPath(ctx, node, "reveal")
	if err != nil {
		t.Fatal("the fixture lost its original Reveal account", err)
	}
	next, reveal, err := trust.VerifyConnectionPlan(ctx, node, input)
	if err != nil || reveal.Plan.Username != "original-web-account" || reveal.Plan.Credential.Kind != "saved" {
		t.Fatal("the retained Reveal account was not authenticated", err)
	}
	trust = next
	grant("1")
	checkImportedQueryDenied(t, ctx, session, webConnectionPlanSQL, "42501", []byte(node.String()))
	checkImportedQueryDenied(t, ctx, session, beginTunnelUseSQL, "42501", []byte(node.String()), []byte("ui"))
	grant("3")
	checkImportedQueryDenied(t, ctx, session, connectionPlanPathSQL, "42501", []byte(node.String()), []byte("reveal"))
	checkImportedQueryDenied(t, ctx, session, webConnectionPlanSQL, "WH017", []byte(ssh.String()))
	checkImportedQueryDenied(t, ctx, session, beginUsePathSQL, "22023", []byte(node.String()), []byte("ui"), []byte(WebConnectionPlanPath))
	const tickets = `SELECT count(*)::text FROM wormhole_data.audit_log WHERE action IN ('begin_use','begin_use_path')`
	before := read(tickets)
	for _, fetch := range []func() (*UnverifiedConnectionPlan, error){
		func() (*UnverifiedConnectionPlan, error) { return session.WebConnectionPlan(ctx, node) },
		func() (*UnverifiedConnectionPlan, error) {
			return session.ConnectionPlanPath(ctx, node, DefaultConnectionPath)
		},
	} {
		input, err = fetch()
		if err != nil {
			t.Fatal("Use alone could not plan the web browser or its route", err)
		}
		_, plan, err := trust.VerifyConnectionPlan(ctx, node, input)
		if err != nil || plan.Path != WebConnectionPlanPath || plan.Plan.Protocol != 4 || plan.Plan.Host != "web.example" ||
			plan.Plan.Port != 443 || plan.Plan.HTTPPath != "/login" || plan.Plan.Credential.Kind != "none" || plan.Plan.Username != "" ||
			plan.Tunnel == nil || plan.Tunnel.Metadata.ID != primary.String() || read(tickets) != before {
			t.Fatal("the web plan failed to authenticate its routing or requested credential release", err)
		}
	}
	input.metadata.plan.Host = "untrusted.example"
	if _, plan, err := trust.VerifyConnectionPlan(ctx, node, input); err != ErrAdmissionResponse || plan != (ResolvedConnectionPlan{}) {
		t.Fatal("the server could change web routing without a signed node", err)
	}
	input.metadata.plan.Host = "web.example"
	input.metadata.records.Imported = []byte("{}")
	if _, plan, err := trust.VerifyConnectionPlan(ctx, node, input); err != ErrAdmissionResponse || plan != (ResolvedConnectionPlan{}) {
		t.Fatal("account material crossed into the web planning response", err)
	}
	checkImportedWebTunnelRelease(t, ctx, session, trust, node, primary, fallback, private)
	if read(`SELECT (count(*)=1)::text FROM wormhole_data.audit_log WHERE action='begin_use_path' AND outcome='issued' AND protocol_path='web'`) != "true" {
		t.Fatal("web tunnel settings were released without an independent committed audit")
	}
	grant("31")
}

func checkImportedWebTunnelRelease(t *testing.T, ctx context.Context, session *Session, trust TrustState, node, primary, fallback uuid.UUID, private []byte) {
	t.Helper()
	if supported, err := session.TunnelUseSupported(ctx); err != nil || !supported {
		t.Fatal("the web tunnel capability is missing", err)
	}
	intent, err := session.BeginTunnelUse(ctx, node, "ui")
	if err != nil || intent == nil || intent.Path != WebConnectionPlanPath {
		t.Fatal("could not authorize the web tunnel", err)
	}
	if _, err := session.FetchSecret(ctx, *intent); err != ErrConfiguration {
		t.Fatal("the credential consumer accepted a tunnel ticket", err)
	}
	checkImportedQueryDenied(t, ctx, session, fetchSecretSQL, "WH015", []byte(node.String()), []byte(intent.Ticket.String()))
	graph, err := session.FetchTunnelSecret(ctx, *intent)
	if err != nil || len(graph.accounts) != 1 || graph.accounts[0].role != "tunnel" {
		t.Fatal("the web ticket returned an account or omitted its tunnel settings", err)
	}
	checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH015", []byte(node.String()), []byte(intent.Ticket.String()), []byte(WebConnectionPlanPath))
	next, verified, err := trust.VerifyCredentialRelease(ctx, node, graph)
	if err != nil {
		t.Fatal("the web tunnel graph could not be authenticated", err)
	}
	if err := verified.WithValues(ctx, next, private, func(resolver.Plan, CredentialReleaseValues) error {
		t.Fatal("a tunnel graph opened through the general credential consumer")
		return nil
	}); err != ErrConfiguration {
		t.Fatal("the tunnel graph was not restricted to WithTunnelValues", err)
	}
	if err := verified.WithTunnelValues(ctx, next, private, func(plan resolver.Plan, values CredentialReleaseValues) error {
		if plan.TunnelID != primary.String() || values.Tunnel == nil || values.Primary != nil || values.Gateway != nil || values.Inline != nil ||
			string(values.Tunnel.Fields["settings"]) != fallback.String() {
			t.Fatal("web tunnel opened an account or the wrong configuration")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	secondary, err := session.BeginFallbackUse(ctx, node, primary, fallback, "ui")
	if err != nil {
		t.Fatal("the browser could not authorize the fallback", err)
	}
	fallbackGraph, err := session.FetchFallbackSecret(ctx, *secondary)
	if err != nil || fallbackGraph.source.metadata.records.Path != WebConnectionPlanPath || len(fallbackGraph.source.accounts) != 1 {
		t.Fatal("the fallback reused an account release", err)
	}
	next, prepared, err := next.VerifyFallbackRelease(ctx, node, fallbackGraph)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.WithConfiguration(ctx, next, private, func(settings []byte) (string, error) {
		return string(settings), nil
	}, func(sources FallbackSources, settings []byte) error {
		if sources.Plan.Credential.Kind != "none" || sources.Fallback.Metadata.ID != fallback.String() || !bytes.Equal(settings, []byte(importedFallbackSettings)) {
			t.Fatal("web fallback opened the wrong configuration")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func checkWorkspaceImportDestinations(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session,
	trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys, sharedID uuid.UUID) (TrustState, *vault.BoundaryManifest, *vault.BoundaryManifest) {
	t.Helper()
	if supported, err := session.WorkspaceImportDestinationsSupported(ctx); err != nil || !supported {
		t.Fatal("schema 57 did not advertise authenticated import destinations", err)
	}
	if _, selected, err := session.WorkspaceImportBoundary(ctx, trust, tls, workspaceimport.Personal); err != nil || selected != nil {
		t.Fatal("a missing personal boundary was confused with the workspace boundary", err)
	}
	if _, selected, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, &vault.UserKeys{}); err == nil || selected != nil {
		t.Fatal("an unrelated owner key could provision an import scope", err)
	}
	administration := func(active string) {
		t.Helper()
		row := dba.ExecParams(ctx, `UPDATE wormhole_data.users SET is_admin=$2::boolean WHERE id=$1::uuid`,
			[][]byte{[]byte(trust.UserID.String()), []byte(active)}, nil, nil, nil).Read()
		if row.Err != nil || row.CommandTag.RowsAffected() != 1 {
			t.Fatal("could not adjust test custodian membership", row.Err)
		}
	}
	administration("false")
	if _, selected, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, actor); !errors.Is(err, ErrServerCertificateAuthority) || selected != nil {
		t.Fatal("a regular member could provision organisation-signed keys", err)
	}
	administration("true")
	observed, personal, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, actor)
	if err != nil || personal == nil || personal.BoundaryID != personalImportBoundaryID(trust.WorkspaceID, trust.UserID) ||
		personal.OwnerUserID != trust.UserID || personal.Secret.Key.ID == personal.View.Key.ID || !personal.OrgEscrow {
		t.Fatal("personal boundary could not be provisioned for the authenticated owner", err)
	}
	if observed.Revision <= trust.Revision {
		t.Fatal("personal boundary did not advance its signed floor")
	}
	trust = observed
	observed, again, err := session.EnsurePersonalImportBoundary(ctx, trust, tls, actor)
	if err != nil || !reflect.DeepEqual(again, personal) || observed.Revision != trust.Revision {
		t.Fatal("a retry generated replacement roots", err)
	}
	observed, shared, err := session.WorkspaceImportBoundary(ctx, trust, tls, workspaceimport.Shared)
	if err != nil || shared == nil || shared.BoundaryID != sharedID ||
		shared.BoundaryID == personal.BoundaryID || shared.OwnerUserID != uuid.Nil {
		t.Fatal("shared destination confused with private scope", err)
	}
	const persisted = `SELECT (
        (SELECT count(*) FROM wormhole_data.boundaries WHERE owner_user_id=$1::uuid)=1
        AND (SELECT count(*) FROM wormhole_data.keys k JOIN wormhole_data.key_copies c USING(key_id,key_version) WHERE k.owner_id=$2::uuid)=4
        AND NOT EXISTS(SELECT FROM wormhole_data.boundary_grants WHERE boundary_id=$2::uuid AND (user_id IS DISTINCT FROM $1::uuid OR group_id IS NOT NULL))
        AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='provision_personal_import_boundary')=1
        AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='personal_import_signer')=1
    )::text`
	row, err := readAccountResetRow(ctx, dba, persisted, [][]byte{[]byte(trust.UserID.String()), []byte(personal.BoundaryID.String())}, 1, 32)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("personal provisioning did not commit exactly two root pairs and one owner grant", err)
	}
	return observed, personal, shared
}

func checkImportedNoteView(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, note, blank uuid.UUID, private []byte, grant func(string)) {
	t.Helper()
	result := dba.ExecParams(ctx, `UPDATE wormhole_data.grants SET permissions=1 WHERE node_id=$1::uuid AND user_id=$2::uuid`,
		[][]byte{[]byte(note.String()), []byte(trust.UserID.String())}, nil, nil, nil).Read()
	if result.Err != nil || result.CommandTag.RowsAffected() != 1 {
		t.Fatal("could not grant View independently from Use on the fixture node", result.Err)
	}
	if supported, err := session.NoteViewSupported(ctx); err != nil || !supported {
		t.Fatal("note display capability missing from schema 56", err)
	}
	if intent, err := session.BeginNoteView(ctx, note, 2); err != nil || intent != nil {
		t.Fatal("a stale display selection received a note ticket", err)
	}
	row, err := readAccountResetRow(ctx, dba, "SELECT row_version::text FROM wormhole_data.nodes WHERE id=$1::uuid", [][]byte{[]byte(blank.String())}, 1, 32)
	if err != nil {
		t.Fatal("could not read the current imported revision", err)
	}
	blankRevision, ok := treeNumber(row[0], 1, math.MaxInt64)
	if !ok {
		t.Fatal("invalid imported revision")
	}
	if intent, err := session.BeginNoteView(ctx, blank, blankRevision); err != nil || intent != nil {
		t.Fatal("View-only access received an attachment with legacy credential pins", err)
	}
	checkImportedQueryDenied(t, ctx, session, beginUsePathSQL, "22023", []byte(note.String()), []byte("ui"), []byte("notes"))
	for _, tc := range []struct {
		node     uuid.UUID
		revision uint64
		want     []byte
	}{{note, 1, []byte("fixture-only-private-note")}, {blank, blankRevision, nil}} {
		if tc.node == blank {
			grant("31")
		}
		intent, err := session.BeginNoteView(ctx, tc.node, tc.revision)
		if err != nil || intent == nil {
			t.Fatal("View without Use did not issue a note ticket", err)
		}
		nodeArg, ticketArg := []byte(tc.node.String()), []byte(intent.use.Ticket.String())
		checkImportedQueryDenied(t, ctx, session, fetchSecretSQL, "WH015", nodeArg, ticketArg)
		checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH015", nodeArg, ticketArg, []byte("rdp"))
		graph, err := session.FetchNote(ctx, intent)
		if err != nil {
			t.Fatal("the note graph was unavailable", err)
		}
		next, view, err := trust.VerifyNoteView(ctx, tc.node, tc.revision, graph)
		if err != nil {
			t.Fatal("the note graph did not authenticate", err)
		}
		trust = next
		if len(tc.want) != 0 && (view.purpose != vault.BoundaryView || view.material == nil ||
			view.material.root.Binding.Key != view.material.manifest.View.Key || graph.nodeData.body != nil) {
			t.Fatal("an imported note was wrapped to the wrong root")
		}
		if len(tc.want) != 0 {
			checkProtectedNoteProof(t, ctx, trust, tc.node, graph, private)
		}
		var borrowed []byte
		callbackErr := errors.New("synthetic note view callback")
		err = view.WithValue(ctx, trust, private, func(value []byte) error {
			if !bytes.Equal(value, tc.want) {
				t.Fatal("display received the wrong note")
			}
			borrowed = value
			return callbackErr
		})
		if err != callbackErr || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("borrowed bytes escaped the note owner or the callback error was lost", err)
		}
		if err := view.WithValue(ctx, trust, private, func([]byte) error { t.Fatal("note replay"); return nil }); err != ErrUseTicket {
			t.Fatal("native note witness accepted replay", err)
		}
		checkImportedQueryDenied(t, ctx, session, fetchNoteSQL, "WH015", nodeArg, ticketArg)
	}
}

func checkProtectedNoteProof(t *testing.T, ctx context.Context, trust TrustState, node uuid.UUID, graph *UnverifiedNoteView, private []byte) {
	t.Helper()
	material, nodeData := *graph.material, *graph.nodeData
	for _, tc := range []struct {
		name string
		edit func(*UnverifiedNoteView)
		want error
	}{
		{"missing material", func(g *UnverifiedNoteView) { g.material = nil }, ErrAdmissionResponse},
		{"pin material alongside independent note", func(g *UnverifiedNoteView) {
			g.nodeData.body = []byte("synthetic pinned-account attachment")
		}, ErrAdmissionResponse},
		{"secret root for new note", func(g *UnverifiedNoteView) {
			g.material.root.Binding.Key = g.material.manifest.Secret.Key
		}, vault.ErrAuthentication},
		{"bad DEK signature", func(g *UnverifiedNoteView) {
			g.material.dek.Copy.Signature = bytes.Clone(g.material.dek.Copy.Signature)
			g.material.dek.Copy.Signature[0] ^= 1
		}, vault.ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, copy, metadata := *graph, material, nodeData
			bad.material, bad.nodeData = &copy, &metadata
			tc.edit(&bad)
			if _, view, err := trust.VerifyNoteView(ctx, node, 1, &bad); view != nil || !errors.Is(err, tc.want) {
				t.Fatal("the note proof did not fail closed", err)
			}
		})
	}
	canonical, view, err := trust.VerifyNoteView(ctx, node, 1, graph)
	if err != nil {
		t.Fatal(err)
	}
	neverBorrow := func([]byte) error { t.Fatal("ineligible owner borrowed plaintext"); return nil }
	stale := canonical
	stale.Revision++
	if err := view.WithValue(ctx, stale, private, neverBorrow); err != ErrTrustState {
		t.Fatal("the note opener accepted a different committed state", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := view.WithValue(canceled, canonical, private, neverBorrow); err != context.Canceled {
		t.Fatal("the note opener borrowed after cancellation", err)
	}
	if err := view.WithValue(ctx, canonical, bytes.Repeat([]byte{82}, 32), neverBorrow); err == nil {
		t.Fatal("the note opened with an unrelated account key")
	}
}

func checkImportedPathReleases(t *testing.T, ctx context.Context, session *Session, trust TrustState, node uuid.UUID, private []byte, group uuid.UUID) {
	t.Helper()
	for _, tc := range []struct{ request, path, other, username, secret string }{
		{"ssh", "ssh", "sftp", "original-pinned-user", "fixture-only-private-credential"},
		{"sftp", "sftp", "ssh", "original-sftp-user", "fixture-only-sftp-credential"},
		{DefaultConnectionPath, "sftp", "ssh", "original-sftp-user", "fixture-only-sftp-credential"},
	} {
		intent, err := session.BeginUsePath(ctx, node, "ui", tc.request)
		if err != nil || intent == nil || intent.Path != tc.path {
			t.Fatalf("%s intent unavailable: %v", tc.path, err)
		}
		nodeArg, ticketArg := []byte(node.String()), []byte(intent.Ticket.String())
		checkImportedQueryDenied(t, ctx, session, fetchSecretSQL, "WH015", nodeArg, ticketArg)
		checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH015", nodeArg, ticketArg, []byte(tc.other))
		graph, err := session.FetchSecret(ctx, *intent)
		if err != nil {
			t.Fatalf("%s ciphertext graph unavailable: %v", tc.path, err)
		}
		if len(graph.roots) == 0 {
			t.Fatal("ciphertext graph omitted the expected boundary root")
		}
		for _, root := range graph.roots {
			checkFixtureBoundaryRecipient(t, root, group)
		}
		next, verified, err := trust.VerifyCredentialRelease(ctx, node, graph)
		if err != nil {
			t.Fatalf("%s ciphertext graph did not verify: %v", tc.path, err)
		}
		trust = next
		called := false
		err = verified.WithValues(ctx, next, private, func(p resolver.Plan, account CredentialReleaseValues) error {
			called = true
			if p.Username != tc.username || account.Primary == nil || account.Primary.Metadata.ID != p.Credential.ID ||
				!bytes.Equal(account.Primary.Fields["password"], []byte(tc.secret)) || account.Gateway != nil || account.Inline != nil {
				t.Fatal("release mixed accounts or substituted the chosen path")
			}
			return nil
		})
		if err != nil || !called {
			t.Fatalf("%s secret could not be opened by its owning native callback: %v", tc.path, err)
		}
		checkImportedQueryDenied(t, ctx, session, fetchSecretPathSQL, "WH015", nodeArg, ticketArg, []byte(tc.path))
	}
}

func checkImportedFallbackRelease(t *testing.T, ctx context.Context, session *Session, trust TrustState, node, primary, fallback uuid.UUID, private []byte, group uuid.UUID) {
	t.Helper()
	intent, err := session.BeginFallbackUse(ctx, node, primary, fallback, "ui")
	if err != nil {
		t.Fatal("the pinned connection could not authorize its original fallback", err)
	}
	encrypted, err := session.FetchFallbackSecret(ctx, *intent)
	if err != nil {
		t.Fatal("the pinned connection did not receive its fallback graph", err)
	}
	checkFixtureBoundaryRecipient(t, encrypted.root, group)
	next, verified, err := trust.VerifyFallbackRelease(ctx, node, encrypted)
	if err != nil {
		t.Fatal("the fallback graph did not prove the source's default identity", err)
	}
	err = verified.WithConfiguration(ctx, next, private, func(settings []byte) (string, error) {
		// The synthetic IPsec settings contain just the remapped fallback ID.
		if !bytes.Equal(settings, []byte(fallback.String())) {
			t.Fatal("the fallback escaped its imported reference")
		}
		return fallback.String(), nil
	}, func(sources FallbackSources, settings []byte) error {
		if sources.Primary.Metadata.ID != primary.String() || sources.Fallback.Metadata.ID != fallback.String() ||
			sources.Plan.Username != "original-sftp-user" || !bytes.Equal(settings, []byte(importedFallbackSettings)) {
			t.Fatal("the fallback used a different imported route or identity")
		}
		return nil
	})
	if err != nil {
		t.Fatal("authenticated imported fallback settings could not be opened", err)
	}
}

func checkImportedRDPAccounts(t *testing.T, ctx context.Context, session *Session, trust TrustState, routed, direct uuid.UUID, private []byte) {
	t.Helper()
	checkImportedQueryDenied(t, ctx, session, beginUsePathSQL, "22023", []byte(routed.String()), []byte("ui"), []byte("rdp-gateway"))
	for _, tc := range []struct {
		node        uuid.UUID
		openPrimary bool
	}{{routed, true}, {routed, false}, {direct, true}} {
		intent, err := session.BeginUsePath(ctx, tc.node, "ui", DefaultConnectionPath)
		if err != nil || intent == nil || intent.Path != "rdp" {
			t.Fatal("paired RDP ticket was unavailable", err)
		}
		graph, err := session.FetchSecret(ctx, *intent)
		if err != nil {
			t.Fatal("could not fetch both authorized RDP roles", err)
		}
		if !tc.openPrimary {
			// An unusable saved primary value must not affect manual opening.
			graph.accounts[0].values[0].Envelope.Ciphertext[0] ^= 1
		}
		next, verified, err := trust.VerifyCredentialRelease(ctx, tc.node, graph)
		if err != nil {
			t.Fatal("could not verify the paired RDP graph", err)
		}
		trust = next
		var borrowed [][]byte
		open := verified.WithValues
		if !tc.openPrimary {
			open = verified.WithGatewayValues
		}
		err = open(ctx, next, private, func(plan resolver.Plan, values CredentialReleaseValues) error {
			if tc.node == direct {
				if plan.Username != "fixture-user" || values.Gateway != nil || values.Primary != nil {
					t.Fatal("direct RDP invented a gateway or stored credential")
				}
				return nil
			}
			gateway := values.Gateway
			if gateway == nil || plan.Host != "desktop.example" || plan.GatewayHost != "gateway.example" || plan.GatewaySameCredentials ||
				gateway.Metadata.Username != "original-gateway" || gateway.Metadata.Domain != "GATEWAY" ||
				plan.GatewayCredentialID != gateway.Metadata.ID || plan.Credential.ID == gateway.Metadata.ID {
				t.Fatal("the two RDP paths lost their signed historical identities")
			}
			if !bytes.Equal(gateway.Fields["password"], []byte("synthetic-gateway-value")) {
				t.Fatal("the gateway path opened the wrong password")
			}
			borrowed = append(borrowed, gateway.Fields["password"])
			if tc.openPrimary {
				if plan.Username != "original-desktop" || plan.Domain != "DESKTOP" ||
					values.Primary == nil || !bytes.Equal(values.Primary.Fields["password"], []byte("synthetic-desktop-value")) {
					t.Fatal("the desktop path opened the wrong password")
				}
				borrowed = append(borrowed, values.Primary.Fields["password"])
			} else if values.Primary != nil || values.Inline != nil || plan.Username != "" || plan.Domain != "" {
				t.Fatal("manual RDP borrowed the stored primary credential")
			}
			return nil
		})
		if err != nil {
			t.Fatal("could not open the requested RDP credential roles", err)
		}
		for _, secret := range borrowed {
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("paired RDP retained a borrowed value after callback")
			}
		}
		if err := open(ctx, next, private, func(resolver.Plan, CredentialReleaseValues) error {
			t.Fatal("the paired graph opened twice")
			return nil
		}); err != ErrUseTicket {
			t.Fatal("paired RDP did not retain its one-use fence", err)
		}
	}
}

func checkImportedQueryDenied(t *testing.T, ctx context.Context, session *Session, statement, code string, args ...[]byte) {
	t.Helper()
	// Check the database response without retiring the session used for restore.
	owned, opCtx, release, err := session.lease(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := session.capability.With(func(raw []byte) error {
		capability := hex.AppendEncode(nil, raw)
		defer vault.Wipe(capability)
		result := owned.(*pgconn.PgConn).ExecParams(opCtx, statement, append([][]byte{capability}, args...), nil, nil, nil).Read()
		var refusal *pgconn.PgError
		if !errors.As(result.Err, &refusal) || len(result.Rows) != 0 {
			t.Fatal("protected path did not return only a refusal")
		}
		if refusal.Code != code {
			t.Fatal("protected path returned the wrong refusal", refusal.Code)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
