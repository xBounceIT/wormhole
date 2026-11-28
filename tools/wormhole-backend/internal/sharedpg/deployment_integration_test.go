package sharedpg

import (
	"context"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresIdentityMigrationIntegration(t *testing.T) {
	settings, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := Connect(ctx, settings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	admin := NewSession()
	defer admin.Close(context.Background())
	if err := admin.Open(ctx, settings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	script, err := deploy.InitialMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Query(ctx, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sql string, want ...string) {
		t.Helper()
		rows, err := admin.Query(ctx, sql, nil)
		if err != nil || len(rows) != 1 || len(rows[0]) != len(want) {
			t.Fatalf("invalid metadata query: %v", err)
		}
		for i, v := range want {
			if string(rows[0][i]) != v {
				t.Fatalf("unexpected metadata column %d: got %q want %q", i, rows[0][i], v)
			}
		}
	}
	// Refuse existing objects before creating any cluster-global roles.
	for _, pair := range [][2]string{
		{"CREATE TABLE public.existing(id integer)", "DROP TABLE public.existing"},
		{"CREATE FUNCTION public.existing() RETURNS integer LANGUAGE sql AS 'SELECT 1'", "DROP FUNCTION public.existing()"},
		{"CREATE TYPE public.existing AS ENUM ('a')", "DROP TYPE public.existing"},
		{"CREATE SCHEMA pgcustom", "DROP SCHEMA pgcustom"},
	} {
		exec(pair[0])
		if _, err := conn.Exec(ctx, script).ReadAll(); err == nil {
			t.Fatal("adopted nonempty database")
		}
		if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
			t.Fatal(err)
		}
		check("SELECT count(*)::text FROM pg_catalog.pg_roles WHERE rolname='wh_testscope_owner'", "0")
		exec(pair[1])
	}
	exec("CREATE ROLE wh_testscope_user NOLOGIN")
	if _, err := conn.Exec(ctx, script).ReadAll(); err == nil {
		t.Fatal("adopted existing cluster role")
	}
	if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	check("SELECT count(*)::text FROM pg_catalog.pg_roles WHERE rolname='wh_testscope_owner'", "0")
	check("SELECT count(*)::text FROM pg_catalog.pg_roles WHERE rolname='wh_testscope_user'", "1")
	exec("DROP ROLE wh_testscope_user")
	if _, err := conn.Exec(ctx, script).ReadAll(); err != nil {
		t.Fatalf("identity migration failed: %v", err)
	}
	check("SELECT workspace_id::text,role_tag,schema_version::text,state FROM wormhole_data.workspace_meta", testHintID, "testscope", "1", "provisioning")
	check("SELECT rolsuper::text,rolcreaterole::text,rolinherit::text,rolcanlogin::text FROM pg_catalog.pg_roles WHERE rolname='wh_testscope_owner'", "false", "true", "false", "false")
	check("SELECT m.inherit_option::text,m.set_option::text FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE r.rolname='wh_testscope_owner' AND u.rolname='wh_testscope_deployer'", "false", "true")
	check("SELECT pg_catalog.has_database_privilege('wh_testscope_user',pg_catalog.current_database(),'CONNECT')::text, pg_catalog.has_database_privilege('wh_testscope_user',pg_catalog.current_database(),'TEMP')::text", "true", "false")
	check("SELECT pg_catalog.has_schema_privilege('wh_testscope_user','wormhole_api_v1','USAGE')::text,pg_catalog.has_schema_privilege('wh_testscope_user','wormhole_data','USAGE')::text,pg_catalog.has_table_privilege('wh_testscope_user','wormhole_data.users','SELECT')::text", "true", "false", "false")
	check("SELECT pg_catalog.has_function_privilege('wh_testscope_user','wormhole_data.immutable_login_name()','EXECUTE')::text", "false")
	exec("SET ROLE wh_testscope_user")
	if _, err := admin.Query(ctx, "SELECT * FROM wormhole_data.users", nil); err != ErrQuery {
		t.Fatal("client read a private table")
	}
	if _, err := admin.Query(ctx, "CREATE TABLE public.client_owned(id integer)", nil); err != ErrQuery {
		t.Fatal("client created a public object")
	}
	exec("RESET ROLE")
	exec("ALTER ROLE wh_testscope_deployer PASSWORD '" + postgresTestVerifier(secret) + "'")
	deployerSettings := settings
	deployerSettings.DeviceRole = "wh_testscope_deployer"
	deployer := NewSession()
	defer deployer.Close(context.Background())
	if err := deployer.Open(ctx, deployerSettings, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Query(ctx, "SELECT * FROM wormhole_data.users", nil); err != ErrQuery {
		t.Fatal("deployer inherited owner privileges")
	}
	if _, err := deployer.Query(ctx, "SET ROLE wh_testscope_owner", nil); err != nil {
		t.Fatal("deployer cannot explicitly become owner")
	}
	if _, err := deployer.Query(ctx, "SELECT * FROM wormhole_data.users", nil); err != nil {
		t.Fatal("explicit owner privileges missing")
	}
	if err := deployer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET ROLE wh_testscope_owner; CREATE FUNCTION wormhole_api_v1.test_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1'; RESET ROLE;").ReadAll(); err != nil {
		t.Fatal(err)
	}
	check("SELECT pg_catalog.has_function_privilege('wh_testscope_user','wormhole_api_v1.test_probe()','EXECUTE')::text", "false")
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + testHintID + "','local-test-user')")
	exec("UPDATE wormhole_data.users SET disabled=true WHERE id='" + testHintID + "'")
	if _, err := admin.Query(ctx, "UPDATE wormhole_data.users SET login_name='renamed'", nil); err != ErrQuery {
		t.Fatal("login name mutation accepted")
	}
	check("SELECT login_name,disabled::text FROM wormhole_data.users", "local-test-user", "true")
	if _, err := admin.Query(ctx, "INSERT INTO wormhole_data.devices(id,user_id,role_name) VALUES ('"+testHintID+"','"+testHintID+"','foreign_role')", nil); err != ErrQuery {
		t.Fatal("foreign device role accepted")
	}
	exec("INSERT INTO wormhole_data.devices(id,user_id,role_name) VALUES ('" + testHintID + "','" + testHintID + "','wh_testscope_d_" + testHintID + "')")
	if _, err := admin.Query(ctx, "UPDATE wormhole_data.workspace_meta SET state='ready'", nil); err != ErrQuery {
		t.Fatal("workspace ready without signed profile")
	}
	if _, err := admin.Query(ctx, "UPDATE wormhole_data.workspace_meta SET signed_profile=''::bytea,state='ready'", nil); err != ErrQuery {
		t.Fatal("empty profile accepted")
	}
	if _, err := conn.Exec(ctx, script).ReadAll(); err == nil {
		t.Fatal("migration silently reapplied")
	}
	if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	check("SELECT count(*)::text FROM wormhole_data.workspace_meta", "1")
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
