package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresNodePermissionsIntegration(t *testing.T) {
	settings, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(sql, state string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != state {
			t.Fatalf("expected %s: %v", state, err)
		}
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("state check failed", r.Err)
		}
	}
	migrations := []func(string, string) (string, error){deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration, deploy.SessionProofMigration, deploy.PasswordChangeMigration, deploy.AccountKeysMigration, deploy.AccountCertificatesMigration, deploy.AccountStateMigration, deploy.TLSTrustMigration, deploy.InvitationLoginMigration, deploy.InvitationCopiesMigration, deploy.AccountEnrollmentMigration, deploy.InvitationCommitMigration, deploy.DeviceConfirmationMigration, deploy.InvitationCertificationMigration}
	for _, migration := range migrations {
		sql, e := migration("testscope", testHintID)
		if e != nil {
			t.Fatal(e)
		}
		script(sql)
	}
	migration, _ := deploy.NodePermissionsMigration("testscope", testHintID)
	wrong, _ := deploy.NodePermissionsMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("ROLLBACK")
	script("CREATE TABLE wormhole_data.groups(collision integer)")
	reject(migration, "42P07")
	script("ROLLBACK")
	check("SELECT (schema_version=15 AND to_regclass('wormhole_data.nodes') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP TABLE wormhole_data.groups")
	script(migration)
	reject(migration, "55000")
	script("ROLLBACK")
	for _, table := range []string{"nodes", "groups", "group_members", "grants"} {
		check("SELECT (NOT has_table_privilege('wh_testscope_user','wormhole_data." + table + "','SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('wh_testscope_admin','wormhole_data." + table + "','SELECT,INSERT,UPDATE,DELETE'))::text")
	}
	check(`SELECT (has_function_privilege('wh_testscope_user','wormhole_api_v1.node_permissions(bytea,uuid)','EXECUTE') AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.node_permissions(bytea,uuid)','EXECUTE') AND NOT has_function_privilege('wh_testscope_user','wormhole_data.effective_permissions(uuid,uuid)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.node_permissions(bytea,uuid)'::regprocedure AND a.grantee=0))::text`)
	user, other, root, leaf, group := uuid.MustParse(testHintID), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,'permissions-test'),($2::uuid,'other')", []byte(user.String()), []byte(other.String()))
	exec("INSERT INTO wormhole_data.nodes(id,kind) VALUES($1::uuid,0)", []byte(root.String()))
	exec("INSERT INTO wormhole_data.nodes(id,parent_id,kind) VALUES($1::uuid,$2::uuid,1)", []byte(leaf.String()), []byte(root.String()))
	exec("INSERT INTO wormhole_data.groups(id,name) VALUES($1::uuid,'Team')", []byte(group.String()))
	exec("INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES($1::uuid,$2::uuid)", []byte(group.String()), []byte(user.String()))
	chain := []permissions.Node{{ID: leaf, Parent: root, Kind: 1}, {ID: root}}
	evaluate := func(want permissions.Mask, groups []uuid.UUID, grants []permissions.Grant) {
		t.Helper()
		got, e := permissions.Effective(user, chain, groups, grants)
		if e != nil || got != want {
			t.Fatal("Go permission result", got, e)
		}
		r := admin.ExecParams(ctx, "SELECT wormhole_data.effective_permissions($1::uuid,$2::uuid)::text", [][]byte{[]byte(user.String()), []byte(leaf.String())}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != strconv.Itoa(int(want)) {
			t.Fatal("SQL permission result", r.Err)
		}
	}
	for mask := permissions.Mask(1); mask <= permissions.All; mask++ {
		exec("DELETE FROM wormhole_data.grants")
		grants := []permissions.Grant{{Node: root, User: user, Permissions: mask}, {Node: leaf, Group: group, Permissions: permissions.Use}, {Node: leaf, User: other, Permissions: permissions.All}}
		exec("INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,$3::integer),($4::uuid,$5::uuid,31)", []byte(root.String()), []byte(user.String()), []byte(strconv.Itoa(int(mask))), []byte(leaf.String()), []byte(other.String()))
		exec("INSERT INTO wormhole_data.grants(node_id,group_id,permissions) VALUES($1::uuid,$2::uuid,2)", []byte(leaf.String()), []byte(group.String()))
		evaluate(mask|permissions.Use, []uuid.UUID{group}, grants)
		exec("DELETE FROM wormhole_data.group_members")
		evaluate(mask, nil, grants)
		exec("INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES($1::uuid,$2::uuid)", []byte(group.String()), []byte(user.String()))
	}
	grants := []permissions.Grant{{Node: root, User: user, Permissions: permissions.All}}
	exec("UPDATE wormhole_data.nodes SET owner_user_id=$1::uuid WHERE id=$2::uuid", []byte(other.String()), []byte(root.String()))
	chain[1].Owner = other
	evaluate(0, nil, grants)
	exec("UPDATE wormhole_data.nodes SET owner_user_id=$1::uuid WHERE id=$2::uuid", []byte(user.String()), []byte(root.String()))
	chain[1].Owner = user
	evaluate(permissions.All, nil, grants)
	exec("UPDATE wormhole_data.nodes SET owner_user_id=NULL WHERE id=$1::uuid", []byte(root.String()))
	chain[1].Owner = uuid.Nil
	for _, assignment := range []string{"permissions=0", "permissions=32", "row_version=0", "user_id=NULL,group_id=NULL", "user_id='" + user.String() + "',group_id='" + group.String() + "'", "signature=decode(repeat('00',64),'hex')"} {
		reject("UPDATE wormhole_data.grants SET "+assignment, "23514")
	}
	exec("UPDATE wormhole_data.nodes SET kind=1 WHERE id=$1::uuid", []byte(root.String()))
	reject("SELECT wormhole_data.effective_permissions('"+user.String()+"','"+leaf.String()+"')", "22023")
	exec("UPDATE wormhole_data.nodes SET kind=0 WHERE id=$1::uuid", []byte(root.String()))
	exec("UPDATE wormhole_data.nodes SET kind=0 WHERE id=$1::uuid", []byte(leaf.String()))
	exec("UPDATE wormhole_data.nodes SET parent_id=$1::uuid WHERE id=$2::uuid", []byte(leaf.String()), []byte(root.String()))
	reject("SELECT wormhole_data.effective_permissions('"+user.String()+"','"+leaf.String()+"')", "22023")
	exec("UPDATE wormhole_data.nodes SET parent_id=NULL WHERE id=$1::uuid", []byte(root.String()))
	parent := root
	for i := 1; i <= 128; i++ {
		id := uuid.New()
		exec("INSERT INTO wormhole_data.nodes(id,parent_id,kind) VALUES($1::uuid,$2::uuid,0)", []byte(id.String()), []byte(parent.String()))
		parent = id
		if i == 127 {
			check("SELECT (wormhole_data.effective_permissions('" + user.String() + "','" + id.String() + "')=31)::text")
		}
	}
	reject("SELECT wormhole_data.effective_permissions('"+user.String()+"','"+parent.String()+"')", "22023")
	reject("SELECT wormhole_data.effective_permissions(NULL,'"+root.String()+"')", "22023")
	reject("SELECT wormhole_data.effective_permissions('"+user.String()+"',NULL)", "22023")
	reject("SELECT wormhole_data.effective_permissions('"+user.String()+"','"+uuid.NewString()+"')", "22023")

	// A real device SCRAM login and audited proof exercise the native API, not
	// a privileged test role pretending to be an application connection.
	material := bytes.Repeat([]byte{71}, 32)
	defer vault.Wipe(material)
	login, _ := EncodeLoginSecret(material)
	defer vault.Wipe(login)
	verifier, _ := NewSCRAMVerifier(material)
	defer vault.Wipe(verifier)
	role := "wh_testscope_d_" + testHintID
	script("CREATE ROLE \"" + role + "\" LOGIN CONNECTION LIMIT 3; GRANT wh_testscope_user TO \"" + role + "\"")
	script(`CREATE FUNCTION pg_temp.set_password(p_role text,p_verifier text) RETURNS void LANGUAGE plpgsql AS $test$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L',p_role,p_verifier); END $test$`)
	exec("SELECT pg_temp.set_password($1,$2)", []byte(role), verifier)
	exec("INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES($1::uuid,$1::uuid,$2,'active')", []byte(testHintID), []byte(role))
	exec("INSERT INTO wormhole_data.account_auth(user_id,iterations,salt,stored_key,server_key) SELECT $1::uuid,p.* FROM wormhole_data.parse_scram_verifier($2) p", []byte(testHintID), verifier)
	script("UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea,require_tls=false")
	settings.DeviceRole = role
	unaudited, err := Connect(ctx, settings, login)
	if err != nil {
		t.Fatal(err)
	}
	raw := unaudited.ExecParams(ctx, nodePermissionsSQL, [][]byte{bytes.Repeat([]byte{'0'}, 64), []byte(leaf.String())}, nil, nil, nil).Read()
	var denied *pgconn.PgError
	if !errors.As(raw.Err, &denied) || denied.Code != "WH007" {
		_ = unaudited.Close(context.Background())
		t.Fatal("direct SQL bypassed audited proof", raw.Err)
	}
	if err := unaudited.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	native := NewSession()
	defer native.Close(context.Background())
	if err := native.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := native.NodePermissions(ctx, leaf); err != ErrAuthentication {
		t.Fatal("unaudited access", err)
	}
	if _, err := native.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	if got, err := native.NodePermissions(ctx, leaf); err != nil || got != permissions.All {
		t.Fatal("native access", got, err)
	}
	script("BEGIN; UPDATE wormhole_data.nodes SET row_version=row_version+1 WHERE id='" + root.String() + "'")
	if _, err := native.NodePermissions(ctx, leaf); err != ErrChangeInProgress {
		t.Fatal("contended ancestry accepted", err)
	}
	script("ROLLBACK")
	if got, err := native.NodePermissions(ctx, leaf); err != nil || got != permissions.All {
		t.Fatal("contention retired valid session", got, err)
	}
	if _, err := native.NodePermissions(ctx, uuid.New()); err == nil {
		t.Fatal("missing node accepted")
	}
	script("UPDATE wormhole_data.users SET disabled=true WHERE id='" + testHintID + "'")
	if _, err := native.NodePermissions(ctx, leaf); err != ErrIdentityUnavailable {
		t.Fatal("disabled account access", err)
	}
	script("UPDATE wormhole_data.users SET disabled=false WHERE id='" + testHintID + "'")
	malicious := NewSession()
	defer malicious.Close(context.Background())
	if err := malicious.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := malicious.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	testPostgresTreeSnapshot(t, ctx, admin, malicious, root, leaf)
	// A compromised server cannot inject an unknown permission bit into the
	// native result. This is response validation, not trust in DBA-owned policy.
	script(`CREATE OR REPLACE FUNCTION wormhole_api_v1.node_permissions(p_capability bytea,p_node uuid)
RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT 32'`)
	if _, err := malicious.NodePermissions(ctx, leaf); err != ErrAdmissionResponse {
		t.Fatal("malformed permission response accepted", err)
	}
	select {
	case <-malicious.Done():
	default:
		t.Fatal("malformed response retained session")
	}
	malformedTree := NewSession()
	defer malformedTree.Close(context.Background())
	if err := malformedTree.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := malformedTree.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	script("UPDATE wormhole_data.nodes SET protocol=999")
	if _, err := malformedTree.TreePage(ctx, TreeCursor{}, 1); err != ErrAdmissionResponse {
		t.Fatal("invalid tree metadata accepted", err)
	}
	select {
	case <-malformedTree.Done():
	default:
		t.Fatal("invalid tree response retained session")
	}
	malformedAuthor := NewSession()
	defer malformedAuthor.Close(context.Background())
	if err := malformedAuthor.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := malformedAuthor.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	script("UPDATE wormhole_data.user_key_states SET signed_state=decode('00','hex')")
	meta := admin.ExecParams(ctx, "SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if meta.Err != nil || len(meta.Rows) != 1 {
		t.Fatal("snapshot", meta.Err)
	}
	epoch, _ := strconv.ParseUint(string(meta.Rows[0][0]), 10, 64)
	sequence, _ := strconv.ParseUint(string(meta.Rows[0][1]), 10, 64)
	if _, err := malformedAuthor.NodeAuthor(ctx, root, epoch, sequence); err != ErrAdmissionResponse {
		t.Fatal("invalid author state accepted", err)
	}
	select {
	case <-malformedAuthor.Done():
	default:
		t.Fatal("invalid author response retained session")
	}
	malformedChanges := NewSession()
	defer malformedChanges.Close(context.Background())
	if err := malformedChanges.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := malformedChanges.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	revokedChanges := NewSession()
	defer revokedChanges.Close(context.Background())
	if err := revokedChanges.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := revokedChanges.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
		t.Fatal(err)
	}
	script("UPDATE wormhole_data.users SET disabled=true WHERE id='" + testHintID + "'")
	if _, err := revokedChanges.ChangesSince(ctx, 0, 0); err != ErrIdentityUnavailable {
		t.Fatal("disabled change access", err)
	}
	script("UPDATE wormhole_data.users SET disabled=false WHERE id='" + testHintID + "'")
	script(`CREATE OR REPLACE FUNCTION wormhole_api_v1.get_changes_since(p_capability bytea,p_epoch bigint,p_since bigint)
RETURNS TABLE(workspace_id uuid,user_id uuid,epoch bigint,change_seq bigint,resolver_version integer,reset_required boolean,node_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS
'SELECT ''` + testHintID + `''::uuid,''` + testHintID + `''::uuid,1::bigint,0::bigint,1,false,NULL::uuid'`)
	if _, err := malformedChanges.ChangesSince(ctx, 0, 0); err != ErrAdmissionResponse {
		t.Fatal("invalid change response accepted", err)
	}
	select {
	case <-malformedChanges.Done():
	default:
		t.Fatal("invalid change response retained session")
	}
	testPostgresUseRestart(t, ctx, admin, settings, login, material, root)
}
