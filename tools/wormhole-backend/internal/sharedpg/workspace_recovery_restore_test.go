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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestWorkspaceRestoreRejectsInvalidRequestsBeforeConnecting(t *testing.T) {
	target := WorkspaceRecoveryTarget{
		WorkspaceID: uuid.New(), Endpoint: Endpoint{Host: "localhost", Port: 5432},
		Database: "recovered", DeployerRole: "wh_archive2_deployer",
	}
	password := []byte("fixture-deployer")
	if _, err := RestoreWorkspaceRecoverySnapshot(nil, target, nil, password); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing operation context was accepted", err)
	}
	if _, err := RestoreWorkspaceRecoverySnapshot(context.Background(), target, nil, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing deployer password was accepted", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RestoreWorkspaceRecoverySnapshot(canceled, target, nil, password); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request did not preserve cancellation", err)
	}
	badRole := target
	badRole.DeployerRole = "postgres"
	if _, err := RestoreWorkspaceRecoverySnapshot(context.Background(), badRole, nil, password); !errors.Is(err, ErrConfiguration) {
		t.Fatal("role outside the workspace was accepted", err)
	}
	if _, err := RestoreWorkspaceRecoverySnapshot(context.Background(), target, []byte("{}"), password); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("incomplete archive reached the destination", err)
	}
}

func restoreWorkspaceRecoveryArchive(t *testing.T, ctx context.Context, source *pgconn.PgConn, plaintext []byte,
	owner, recoveryRecipient uuid.UUID, wantNodes int) (WorkspaceRecoveryTarget, *pgconn.PgConn, []byte) {
	t.Helper()
	summary, err := InspectWorkspaceRecoverySnapshot(plaintext)
	if err != nil || summary.Nodes != wantNodes {
		t.Fatal("restore requires a real source workspace with a catalog", err)
	}
	dba, password := postgresTestClusterTLS(t, true)
	targetConn, err := Connect(ctx, dba, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeDeploymentConnection(targetConn) })
	targetFiles := postgresFixtureDataDirectory(t, ctx, targetConn)
	sourceFiles := postgresFixtureDataDirectory(t, ctx, source)
	for _, leaf := range []string{"server.crt", "server.key"} {
		raw, err := os.ReadFile(filepath.Join(sourceFiles, leaf))
		if err != nil {
			t.Fatal("read synthetic source TLS file", err)
		}
		err = os.WriteFile(filepath.Join(targetFiles, leaf), raw, 0600)
		vault.Wipe(raw)
		if err != nil {
			t.Fatal("install synthetic destination TLS file", err)
		}
	}
	ca, err := os.ReadFile(filepath.Join(sourceFiles, "server.crt"))
	if err != nil {
		t.Fatal("read synthetic TLS identity", err)
	}
	dba.CAPEM = ca
	reloadPostgresFixtureTLS(t, ctx, targetConn, dba, password)
	if _, err := DeploySchema(ctx, dba, password, summary.RoleTag, summary.WorkspaceID.String()); err != nil {
		t.Fatal("prepare target cluster", err)
	}

	deployer := "wh_" + summary.RoleTag + "_deployer"
	target := WorkspaceRecoveryTarget{WorkspaceID: summary.WorkspaceID, Endpoint: dba.Endpoints[0], Database: dba.Database, DeployerRole: deployer}
	exec := func(sql string) {
		t.Helper()
		if _, err := targetConn.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal("fixture statement failed", err)
		}
	}
	exec("ALTER ROLE " + deployer + " PASSWORD '" + postgresTestVerifier(password) + "'")
	if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, plaintext, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatal("restore authenticated with the wrong deployer password", err)
	}
	if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, plaintext, password); !errors.Is(err, ErrWorkspaceRestoreLogging) {
		t.Fatal("restore sent archive with logging enabled", err)
	}
	exec("ALTER ROLE " + deployer + " SET log_parameter_max_length=0")
	exec("ALTER ROLE " + deployer + " SET log_parameter_max_length_on_error=0")
	if r := targetConn.ExecParams(ctx, "SELECT wormhole_api_v1.restore_workspace($1::text,$2::text)",
		[][]byte{plaintext, []byte(dba.Database)}, nil, nil, nil).Read(); !hasSQLState(r.Err, "42501", 0) {
		t.Fatal("unscoped DBA login could invoke restore", r.Err)
	}
	other := target
	other.WorkspaceID = uuid.New()
	if _, err := RestoreWorkspaceRecoverySnapshot(ctx, other, plaintext, password); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("wrong workspace identity was accepted", err)
	}
	var exported WorkspaceRecoverySnapshot
	if err := json.Unmarshal(plaintext, &exported); err != nil {
		t.Fatal(err)
	}
	defer exported.Close()
	selected := exported
	selected.Records = append([]WorkspaceRecoveryRecord(nil), exported.Records...)
	containsImport, containsGroupKey := false, false
	for _, record := range exported.Records {
		containsImport = containsImport || record.Relation == "node_import_data"
		if record.Relation == "groups" {
			var group struct {
				KeyManifest *string `json:"key_manifest"`
			}
			if err := json.Unmarshal(record.Body, &group); err != nil {
				t.Fatal(err)
			}
			containsGroupKey = containsGroupKey || group.KeyManifest != nil
		}
	}
	for i := range selected.Records {
		if !containsImport && !containsGroupKey && selected.Records[i].Relation == "workspace_meta" {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(selected.Records[i].Body, &fields); err != nil {
				t.Fatal(err)
			}
			fields["schema_version"] = json.RawMessage("49")
			selected.Records[i].Body, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	restoreArchive, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(restoreArchive)
	broken := exported
	broken.Records = append([]WorkspaceRecoveryRecord(nil), exported.Records...)
	for index := range broken.Records {
		if broken.Records[index].Relation == "workspace_bootstrap" {
			broken.Records[index].Body = json.RawMessage(`{"singleton":true}`)
		}
	}
	bad, err := json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(bad)
	if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, bad, password); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("restore accepted a broken final custody row", err)
	}
	if containsImport {
		missing := exported
		missing.Records = make([]WorkspaceRecoveryRecord, 0, len(exported.Records))
		for _, record := range exported.Records {
			if record.Relation != "node_import_data" {
				missing.Records = append(missing.Records, record)
			}
		}
		damaged, err := json.Marshal(missing)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(damaged)
		if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, damaged, password); !errors.Is(err, ErrDeploymentRejected) {
			t.Fatal("restore accepted a node with missing signed import data", err)
		}
	}
	if missing, removed := omitPersonalImportEscrow(t, exported, personalImportBoundaryID(exported.WorkspaceID, owner), recoveryRecipient); removed {
		damaged, err := json.Marshal(missing)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(damaged)
		if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, damaged, password); !errors.Is(err, ErrDeploymentRejected) {
			t.Fatal("restore accepted a personal boundary with missing escrow", err)
		}
	}
	for index, record := range exported.Records {
		if record.Relation != "user_enrollment_history" {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(record.Body, &fields); err != nil {
			t.Fatal(err)
		}
		fields["user_id"], err = json.Marshal(owner)
		if err != nil {
			t.Fatal(err)
		}
		badHistory := exported
		badHistory.Records = append([]WorkspaceRecoveryRecord(nil), exported.Records...)
		badHistory.Records[index].Body, err = json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		damaged, err := json.Marshal(badHistory)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(damaged)
		if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, damaged, password); !errors.Is(err, ErrDeploymentRejected) {
			t.Fatal("restore accepted enrollment history for the wrong account", err)
		}
		break
	}
	for index, record := range exported.Records {
		if record.Relation != "group_boundary_rotation_queue" {
			continue
		}
		missing := exported
		missing.Records = append(append([]WorkspaceRecoveryRecord{}, exported.Records[:index]...), exported.Records[index+1:]...)
		damaged, err := json.Marshal(missing)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(damaged)
		if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, damaged, password); !errors.Is(err, ErrDeploymentRejected) {
			t.Fatal("restore accepted an incomplete group boundary rotation queue", err)
		}
		break
	}
	if row, err := readDeploymentRow(ctx, targetConn, `SELECT (
    (SELECT state='provisioning' FROM wormhole_data.workspace_meta WHERE singleton)
    AND NOT EXISTS(SELECT FROM wormhole_data.users) AND NOT EXISTS(SELECT FROM wormhole_data.nodes)
    AND NOT EXISTS(SELECT FROM wormhole_data.audit_log WHERE action='restore_workspace')
)::text`, 1); err != nil || string(row[0]) != "true" {
		t.Fatal("rejected restore left partially applied data", err)
	}
	if result, err := RestoreWorkspaceRecoverySnapshot(ctx, target, restoreArchive, password); result != WorkspaceRestored || err != nil {
		t.Fatal("could not restore source archive on a new cluster", result, err)
	}
	if result, err := RestoreWorkspaceRecoverySnapshot(ctx, target, restoreArchive, password); result != WorkspaceAlreadyRestored || err != nil {
		t.Fatal("identical archive retry was not idempotent", result, err)
	}
	if _, err := RestoreWorkspaceRecoverySnapshot(ctx, target, bad, password); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("ready workspace accepted a different archive", err)
	}
	if row, err := readDeploymentRow(ctx, targetConn, `SELECT (
    (SELECT state='ready' AND epoch>1 AND change_seq=catalog_reset_seq FROM wormhole_data.workspace_meta WHERE singleton)
    AND EXISTS(SELECT FROM wormhole_data.workspace_bootstrap WHERE singleton AND invite_id IS NULL)
    AND NOT EXISTS(SELECT FROM wormhole_data.devices) AND NOT EXISTS(SELECT FROM wormhole_data.account_auth)
    AND NOT EXISTS(SELECT FROM wormhole_data.invites) AND NOT EXISTS(SELECT FROM wormhole_data.sessions)
    AND NOT EXISTS(SELECT FROM wormhole_data.invitation_logins)
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='restore_workspace' AND outcome='restored')=1
)::text`, 1); err != nil || string(row[0]) != "true" {
		t.Fatal("restored activation, history or login boundary is incorrect", err)
	}
	verifyRestoredRecords(t, ctx, targetConn, exported.Records)
	return target, targetConn, password
}

func checkWorkspaceRecoveryRestore(t *testing.T, ctx context.Context, source *pgconn.PgConn, plaintext []byte, original *workspaceBootstrap, factors *workspaceBootstrapSecrets, ask []byte, wantNodes int) {
	t.Helper()
	target, targetConn, password := restoreWorkspaceRecoveryArchive(t, ctx, source, plaintext,
		original.invitation.Enrollment.Context.UserID, original.recovery.Encryption.ID, wantNodes)
	verifyRestoredAccountKeys(t, ctx, targetConn, original, factors)
	joinRestoredAdministrator(t, ctx, target, targetConn, password, original, factors, ask, "restored-admin",
		func(session *Session, state TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys) {
			checkAccountResetIssuance(t, ctx, targetConn, session, state, tls, actor, []Endpoint{target.Endpoint}, original.invitation)
		})
}

func joinRestoredAdministrator(t *testing.T, ctx context.Context, target WorkspaceRecoveryTarget, targetConn *pgconn.PgConn, password []byte,
	original *workspaceBootstrap, factors *workspaceBootstrapSecrets, ask []byte, login string, checks ...joinedAdministratorCheck) {
	t.Helper()
	recovery := publishRestoredAdministrator(t, ctx, target, password, original, factors, login)
	defer recovery.Close()
	for _, setting := range []string{"log_parameter_max_length", "log_parameter_max_length_on_error"} {
		if _, err := targetConn.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{target.Database}.Sanitize()+" SET "+setting+"=0").ReadAll(); err != nil {
			t.Fatal("could not protect fixture bind parameters", err)
		}
	}
	if err := recovery.BorrowJoin(func(i Invitation, code []byte) error {
		joinTestAdministrator(t, ctx, i, code, original.organisation.Signing, original.recovery.Signing, ask, nil, checks...)
		return nil
	}); err != nil {
		t.Fatal("recovered administrator was not admitted on the restored cluster", err)
	}
}

func publishRestoredAdministrator(t *testing.T, ctx context.Context, target WorkspaceRecoveryTarget, password []byte,
	original *workspaceBootstrap, factors *workspaceBootstrapSecrets, login string) *PreparedWorkspaceRecovery {
	t.Helper()
	custody, err := encodeWorkspaceRecoveryKit(workspaceRecoveryKit{Version: 1, Workspace: target.WorkspaceID,
		Encryption: original.recovery.Encryption, Signing: original.recovery.Signing,
		Public: original.organisation, Capsule: original.recoveryKeys})
	if err != nil {
		t.Fatal(err)
	}
	code, err := vault.FormatRecoveryKey(factors.recoveryKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	recovery, err := PrepareWorkspaceRecovery(ctx, target, custody, code, original.invitation.TLSIdentity.Bundle, password, login)
	if err != nil {
		t.Fatal("restored custody could not prepare first access", err)
	}
	if err := recovery.Publish(ctx, password); err != nil {
		recovery.Close()
		t.Fatal("restored custody could not issue first access", err)
	}
	return recovery
}

func omitPersonalImportEscrow(t *testing.T, snapshot WorkspaceRecoverySnapshot, boundary, recipient uuid.UUID) (WorkspaceRecoverySnapshot, bool) {
	t.Helper()
	var view uuid.UUID
	for _, record := range snapshot.Records {
		if record.Relation != "keys" {
			continue
		}
		var key struct {
			ID    uuid.UUID `json:"key_id"`
			Owner uuid.UUID `json:"owner_id"`
			Kind  string    `json:"kind"`
		}
		if err := json.Unmarshal(record.Body, &key); err != nil {
			t.Fatal(err)
		}
		if key.Owner == boundary && key.Kind == "boundary-view" {
			view = key.ID
			break
		}
	}
	if view == uuid.Nil {
		return snapshot, false
	}
	result := snapshot
	result.Records = make([]WorkspaceRecoveryRecord, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		if record.Relation == "key_copies" {
			var copy struct {
				Key    uuid.UUID `json:"key_id"`
				Holder uuid.UUID `json:"holder_key_id"`
			}
			if err := json.Unmarshal(record.Body, &copy); err != nil {
				t.Fatal(err)
			}
			if copy.Key == view && copy.Holder == recipient {
				continue
			}
		}
		result.Records = append(result.Records, record)
	}
	if len(result.Records) != len(snapshot.Records)-1 {
		t.Fatal("could not identify the single personal view escrow copy in the archive")
	}
	return result, true
}

func verifyRestoredAccountKeys(t *testing.T, ctx context.Context, conn *pgconn.PgConn, original *workspaceBootstrap, factors *workspaceBootstrapSecrets) {
	t.Helper()
	const query = `SELECT c.key_id::text,c.key_version::text,pg_catalog.encode(c.enc,'hex'),
    pg_catalog.encode(c.ciphertext,'hex'),pg_catalog.encode(c.signature,'hex'),k.kind,
    c.issuer_key_id::text,c.issuer_key_version::text,pg_catalog.encode(k.public_key,'hex'),pg_catalog.encode(i.public_key,'hex')
FROM wormhole_data.key_copies c
JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.key_id,c.key_version)
JOIN wormhole_data.keys i ON (i.key_id,i.key_version)=(c.issuer_key_id,c.issuer_key_version)
WHERE (c.holder_key_id,c.holder_key_version)=($1::uuid,1) AND k.owner_id=$2::uuid
      AND k.kind IN ('user-enc','user-sign') ORDER BY k.kind`
	result := conn.ExecParams(ctx, query, [][]byte{[]byte(original.recovery.Encryption.ID.String()),
		[]byte(original.invitation.Enrollment.Context.UserID.String())}, nil, nil, nil).Read()
	if result.Err != nil || len(result.Rows) != 2 {
		t.Fatal("restored account custody is incomplete", result.Err)
	}
	custody, err := vault.OpenOrganisationRecovery(factors.recoveryKey[:], original.recovery, original.recoveryKeys, original.organisation)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Wipe()
	var recovered vault.UserKeys
	defer recovered.Wipe()
	for idx, row := range result.Rows {
		key, sealed, err := parseServerCAOrgCopy(row[:5])
		issuerID, idOK := treeID(row[6])
		issuerVersion, versionOK := treeNumber(row[7], 1, math.MaxInt32)
		public, pubErr := hex.DecodeString(string(row[9]))
		if err != nil || !idOK || !versionOK || pubErr != nil {
			t.Fatal("restored custody metadata is invalid", err, pubErr)
		}
		binding := vault.KeyCopyBinding{WorkspaceID: original.recovery.WorkspaceID, Key: key, Holder: original.recovery.Encryption,
			Issuer: vault.KeyRef{ID: issuerID, Version: uint32(issuerVersion)}}
		keyBytes, err := vault.OpenKeyCopy(custody.EncryptionPrivate, binding, sealed, public)
		if err != nil {
			t.Fatal("offline custody could not open the original account key", err)
		}
		if idx == 0 && string(row[5]) == "user-enc" {
			recovered.EncryptionPrivate = keyBytes
		} else if idx == 1 && string(row[5]) == "user-sign" {
			recovered.SigningSeed = keyBytes
		} else {
			vault.Wipe(keyBytes)
			t.Fatal("expected one copy of each account key")
		}
	}
	public, err := recovered.Public()
	if err != nil || string(result.Rows[0][8]) != hex.EncodeToString(public.Encryption) ||
		string(result.Rows[1][8]) != hex.EncodeToString(public.Signing) {
		t.Fatal("escrow did not recover the account's enrolled keys", err)
	}
}

func verifyRestoredRecords(t *testing.T, ctx context.Context, conn *pgconn.PgConn, records []WorkspaceRecoveryRecord) {
	t.Helper()
	if _, err := conn.Exec(ctx, "SET timezone='UTC'; SET bytea_output='hex'").ReadAll(); err != nil {
		t.Fatal("could not select recovery export formatting", err)
	}
	compact := func(relation string, raw []byte) string {
		t.Helper()
		if relation == "group_member_rotation_jobs" || relation == "group_boundary_rotation_queue" {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			// Earlier archives omit these fields. Restoring them supplies NULL.
			for _, key := range []string{"holder_version", "replacement_revision", "replacement_version"} {
				if bytes.Equal(fields[key], []byte("null")) {
					delete(fields, key)
				}
			}
			var err error
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if err := json.Compact(&out, raw); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	expected := make(map[string]map[string]int)
	for _, record := range records {
		relation := record.Relation
		if relation == "workspace_meta" || relation == "workspace_bootstrap" {
			continue
		}
		if _, ok := recoverySnapshotRelations[relation]; !ok {
			t.Fatal("unexpected relation in signed test archive")
		}
		if expected[relation] == nil {
			expected[relation] = make(map[string]int)
		}
		expected[relation][compact(relation, record.Body)]++
	}
	for relation, expected := range expected {
		r := conn.ExecParams(ctx, "SELECT pg_catalog.to_jsonb(t)::text FROM wormhole_data."+relation+" t", nil, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal("cannot read restored records", r.Err)
		}
		actual := make(map[string]int)
		for _, row := range r.Rows {
			actual[compact(relation, row[0])]++
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("protected records changed during restore", relation)
		}
	}
}
