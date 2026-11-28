package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresWebSessionViewGenerations(t *testing.T) {
	settings, password := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	admin, err := Connect(ctx, settings, password)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	run := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	fresh, err := deploy.SchemaScript("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	previous, _, ok := strings.Cut(fresh, "-- Version 81:")
	if !ok {
		t.Fatal("schema upgrade boundary was not found")
	}
	run(previous + "COMMIT;")
	probe := NewSession()
	defer probe.Close(context.Background())
	if err := probe.Open(ctx, settings, password, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if supported, err := probe.WebSessionViewsSupported(ctx); err != nil || supported {
		t.Fatal("schema 80 advertised the View generation API", err)
	}
	migration, err := deploy.WebSessionViewsMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(migration)
	if supported, err := probe.WebSessionViewsSupported(ctx); err != nil || !supported {
		t.Fatal("schema 81 did not advertise the View generation API", err)
	}
	row, err := readDeploymentRow(ctx, admin, `SELECT (
      (SELECT schema_version=81 FROM wormhole_data.workspace_meta)
      AND NOT has_table_privilege('wh_testscope_user','wormhole_data.web_session_views','SELECT,INSERT,UPDATE,DELETE')
      AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.open_web_session_view(bytea,uuid)','EXECUTE')
      AND NOT has_function_privilege('wh_testscope_deployer','wormhole_api_v1.check_web_session_views(bytea,uuid[])','EXECUTE')
      AND has_function_privilege('wh_testscope_user','wormhole_api_v1.check_web_session_views(bytea,uuid[])','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("View generation permissions did not match the API boundary", err)
	}
	if supported, err := probe.WebConnectionPlanSupported(ctx); err != nil || supported {
		t.Fatal("schema 81 advertised web-only planning", err)
	}
	webMigration, err := deploy.WebConnectionPlanMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(webMigration)
	if supported, err := probe.WebConnectionPlanSupported(ctx); err != nil || !supported {
		t.Fatal("schema 82 did not advertise web-only planning", err)
	}
	row, err = readDeploymentRow(ctx, admin, `SELECT (
      (SELECT schema_version=82 FROM wormhole_data.workspace_meta)
      AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.web_connection_plan(bytea,uuid)','EXECUTE')
      AND NOT has_function_privilege('wh_testscope_deployer','wormhole_api_v1.web_connection_plan(bytea,uuid)','EXECUTE')
      AND has_function_privilege('wh_testscope_user','wormhole_api_v1.web_connection_plan(bytea,uuid)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("web planning permissions did not match the API boundary", err)
	}
	if supported, err := probe.TunnelUseSupported(ctx); err != nil || supported {
		t.Fatal("schema 82 advertised a dedicated tunnel ticket", err)
	}
	tunnelMigration, err := deploy.WebTunnelReleaseMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(tunnelMigration)
	if supported, err := probe.TunnelUseSupported(ctx); err != nil || !supported {
		t.Fatal("schema 83 did not advertise the tunnel ticket", err)
	}
	row, err = readDeploymentRow(ctx, admin, `SELECT (
      (SELECT schema_version=83 FROM wormhole_data.workspace_meta)
      AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.begin_tunnel_use(bytea,uuid,text)','EXECUTE')
      AND NOT has_function_privilege('wh_testscope_deployer','wormhole_api_v1.begin_tunnel_use(bytea,uuid,text)','EXECUTE')
      AND has_function_privilege('wh_testscope_user','wormhole_api_v1.begin_tunnel_use(bytea,uuid,text)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("tunnel ticket permissions did not match the API boundary", err)
	}
	if supported, err := probe.WebSessionCheckpointsSupported(ctx); err != nil || supported {
		t.Fatal("schema 83 advertised web inventory tracking", err)
	}
	inventoryMigration, err := deploy.WebSuspensionInventoryMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	run(inventoryMigration)
	if supported, err := probe.WebSessionCheckpointsSupported(ctx); err != nil || !supported {
		t.Fatal("schema 84 did not advertise web inventory tracking", err)
	}
	row, err = readDeploymentRow(ctx, admin, `SELECT (
      (SELECT schema_version=84 FROM wormhole_data.workspace_meta)
      AND NOT has_table_privilege('wh_testscope_user','wormhole_data.web_session_checkpoints','SELECT,INSERT,UPDATE,DELETE')
      AND NOT has_table_privilege('wh_testscope_user','wormhole_data.account_suspension_web_targets','SELECT,INSERT,UPDATE,DELETE')
      AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.set_web_session_checkpoint(bytea,uuid,uuid,boolean)','EXECUTE')
      AND has_function_privilege('wh_testscope_user','wormhole_api_v1.set_web_session_checkpoint(bytea,uuid,uuid,boolean)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("checkpoint privileges did not match the API boundary", err)
	}

	material := bytes.Repeat([]byte{0x81}, 32)
	defer vault.Wipe(material)
	login, err := EncodeLoginSecret(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	verifier, err := NewSCRAMVerifier(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	role := "wh_testscope_d_" + testHintID
	run(`CREATE ROLE "` + role + `" LOGIN CONNECTION LIMIT 3; GRANT wh_testscope_user TO "` + role + `"`)
	run(`CREATE FUNCTION pg_temp.set_password(p_role text,p_verifier text) RETURNS void LANGUAGE plpgsql AS
        $fixture$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L',p_role,p_verifier); END $fixture$`)
	exec("SELECT pg_temp.set_password($1,$2)", []byte(role), verifier)
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,'view-fixture')", []byte(testHintID))
	exec("INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES($1::uuid,$1::uuid,$2,'active')", []byte(testHintID), []byte(role))
	exec("INSERT INTO wormhole_data.account_auth(user_id,iterations,salt,stored_key,server_key) SELECT $1::uuid,p.* FROM wormhole_data.parse_scram_verifier($2) p", []byte(testHintID), verifier)

	root, leaf, independent, group := uuid.NewString(), uuid.New(), uuid.New(), uuid.NewString()
	run("INSERT INTO wormhole_data.nodes(id,kind) VALUES('" + root + "',0)")
	run("INSERT INTO wormhole_data.nodes(id,parent_id,kind,protocol,host) VALUES" +
		"('" + leaf.String() + "','" + root + "',1,4,'fixture.example'),('" + independent.String() + "',NULL,1,4,'other.example')")
	run("INSERT INTO wormhole_data.groups(id,name) VALUES('" + group + "','Browser users')")
	member := "INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES('" + group + "','" + testHintID + "')"
	run(member)
	run("INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES" +
		"('" + root + "','" + testHintID + "',3),('" + independent.String() + "','" + testHintID + "',3)")
	run("INSERT INTO wormhole_data.grants(node_id,group_id,permissions) VALUES('" + leaf.String() + "','" + group + "',3)")
	otherAccount := uuid.NewString()
	run("INSERT INTO wormhole_data.users(id,login_name) VALUES('" + otherAccount + "','other-view-fixture')")
	run("INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES('" + root + "','" + otherAccount + "',3)")
	run("INSERT INTO wormhole_data.web_session_views(user_id,node_id) VALUES('" + otherAccount + "','" + leaf.String() + "')")
	run("UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea,require_tls=false")

	settings.DeviceRole = role
	offline, err := Connect(ctx, settings, login)
	if err != nil {
		t.Fatal(err)
	}
	result := offline.ExecParams(ctx, openWebSessionViewSQL, [][]byte{bytes.Repeat([]byte{'0'}, 64), []byte(leaf.String())}, nil, nil, nil).Read()
	_ = offline.Close(ctx)
	var unaudited *pgconn.PgError
	if !errors.As(result.Err, &unaudited) || unaudited.Code != "WH007" {
		t.Fatal("unaudited database role acquired View authority", result.Err)
	}
	connect := func() *Session {
		t.Helper()
		session := NewSession()
		t.Cleanup(func() { _ = session.Close(context.Background()) })
		if err := session.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := session.AuthenticateSession(ctx, admissionRequest(), material); err != nil {
			t.Fatal(err)
		}
		return session
	}
	session := connect()
	issue := func(node uuid.UUID, wantAllowed bool) uuid.UUID {
		t.Helper()
		generation, err := session.OpenWebSessionView(ctx, node)
		if err != nil || (generation != uuid.Nil) != wantAllowed {
			t.Fatalf("View generation did not match current permission: %v", err)
		}
		return generation
	}
	observed := func(wantLeaf, wantIndependent uuid.UUID) {
		t.Helper()
		values, err := session.CheckWebSessionViews(ctx, []uuid.UUID{independent, leaf, uuid.New()})
		if err != nil || values[leaf] != wantLeaf || values[independent] != wantIndependent {
			t.Fatalf("checkpoint generations did not match expected authority: %v", err)
		}
	}
	original, unaffected := issue(leaf, true), issue(independent, true)
	if issue(leaf, true) != original {
		t.Fatal("a second open reset continuous View")
	}
	issue(uuid.New(), false)
	run("DELETE FROM wormhole_data.grants WHERE node_id='" + root + "' AND user_id='" + testHintID + "'")
	observed(original, unaffected) // Group View still applies.
	removeMember := "DELETE FROM wormhole_data.group_members WHERE group_id='" + group + "'"
	run("BEGIN; " + removeMember + "; ROLLBACK")
	observed(original, unaffected)
	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	run(removeMember)
	run(member) // No client was connected during the intervening loss.
	session = connect()
	observed(uuid.Nil, unaffected)
	replacement := issue(leaf, true)
	if replacement == original {
		t.Fatal("a new grant reused a generation from before revocation")
	}
	run("UPDATE wormhole_data.grants SET permissions=1 WHERE group_id='" + group + "'")
	issue(leaf, false)
	observed(replacement, unaffected) // Losing Use does not revoke View.
	run("UPDATE wormhole_data.users SET disabled=true WHERE id='" + testHintID + "'")
	run("UPDATE wormhole_data.users SET disabled=false WHERE id='" + testHintID + "'")
	session = connect()
	observed(uuid.Nil, uuid.Nil)
	checkOtherAccount := func(want bool) {
		t.Helper()
		row, err := readDeploymentRow(ctx, admin, "SELECT EXISTS(SELECT FROM wormhole_data.web_session_views WHERE user_id='"+
			otherAccount+"' AND node_id='"+leaf.String()+"')::text", 1)
		if err != nil || (string(row[0]) == "true") != want {
			t.Fatalf("independent account's authority presence should be %t: %v", want, err)
		}
	}
	checkOtherAccount(true)
	run("DELETE FROM wormhole_data.grants WHERE node_id='" + leaf.String() + "'")
	checkOtherAccount(true)
	run("DELETE FROM wormhole_data.nodes WHERE id='" + leaf.String() + "'")
	checkOtherAccount(false)
}
