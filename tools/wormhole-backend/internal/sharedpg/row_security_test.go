package sharedpg

import (
	"context"
	"errors"
	"testing"
)

// Exercise both supported DBA installations. Leave the protection on so the
// delegated bootstrap test runs its ordinary APIs under forced row security.
func checkWorkspaceRowSecurity(t *testing.T, ctx context.Context, s Settings, password []byte, tag, fingerprint string) {
	t.Helper()
	dba := s
	dba.DeviceRole = "wormhole_test_admin"
	db, err := Connect(ctx, dba, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(db)
	run := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(sql, state string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql).ReadAll(); !hasSQLState(err, state, 0) {
			t.Fatalf("expected SQLSTATE %s, got %v", state, err)
		}
	}
	check := func(sql string) {
		t.Helper()
		row, err := readDeploymentRow(ctx, db, sql, 1)
		if err != nil || string(row[0]) != "true" {
			t.Fatalf("row security assertion failed: %s (%v)", sql, err)
		}
	}
	owner := "SET ROLE wh_" + tag + "_owner"
	toggle := "SELECT wormhole_data.set_row_security('" + testHintID + "',"
	run("SET ROLE wh_" + tag + "_user")
	reject(toggle+"true)", "42501")
	run(owner)
	reject("SELECT wormhole_data.set_row_security(gen_random_uuid(),true)", "42501")
	reject(toggle+"NULL)", "42501")
	maintenance, err := Connect(ctx, dba, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := maintenance.Exec(ctx, "BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('wormhole/schema/"+testHintID+"',0))").ReadAll(); err != nil {
		closeDeploymentConnection(maintenance)
		t.Fatal(err)
	}
	reject(toggle+"true)", "55P03")
	closeDeploymentConnection(maintenance)
	// A conflicting policy on a late table must preserve all earlier tables.
	run("CREATE POLICY operator_policy ON wormhole_data.users FOR SELECT USING (true)")
	reject(toggle+"true)", "55000")
	check("SELECT (NOT EXISTS (SELECT FROM pg_class WHERE relnamespace='wormhole_data'::regnamespace AND relrowsecurity))::text")
	run("DROP POLICY operator_policy ON wormhole_data.users")
	run(toggle + "true)")
	run(toggle + "true)")
	run("SELECT * FROM wormhole_data.maintain_audit_partitions('" + testHintID + "')")
	check("SELECT bool_and(relrowsecurity AND relforcerowsecurity)::text FROM pg_class WHERE relnamespace='wormhole_data'::regnamespace AND relkind IN ('r','p')")
	run("RESET ROLE")
	requireReleasedCatalog(t, ctx, s, password, tag, fingerprint)
	if _, err := CheckSchemaDeployment(ctx, s, password, tag, testHintID); err != nil {
		t.Fatal("protected deployment inspection", err)
	}
	// An accidental table grant must still expose zero workspace rows.
	run("BEGIN; GRANT USAGE ON SCHEMA wormhole_data TO wh_" + tag + "_user; GRANT SELECT(singleton) ON wormhole_data.workspace_meta TO wh_" + tag + "_user; SET LOCAL ROLE wh_" + tag + "_user")
	check("SELECT (count(singleton)=0)::text FROM wormhole_data.workspace_meta")
	run("ROLLBACK")
	run("BEGIN; " + owner + "; INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + testHintID + "','rls-fixture'); " +
		"INSERT INTO wormhole_data.devices(id,user_id,role_name) VALUES ('" + testHintID + "','" + testHintID + "','wh_" + tag + "_d_" + testHintID + "'); SET LOCAL ROLE wh_" + tag + "_observer")
	check("SELECT (count(id)=1)::text FROM wormhole_data.devices WHERE role_name='wh_" + tag + "_d_" + testHintID + "'")
	run("ROLLBACK")
	run(owner)
	run("BEGIN; ALTER TABLE wormhole_data.users NO FORCE ROW LEVEL SECURITY")
	reject(toggle+"true)", "55000")
	run("ROLLBACK")
	run("BEGIN; DROP POLICY wh_owner ON wormhole_data.users")
	reject(toggle+"false)", "55000")
	run("ROLLBACK")
	run("ALTER POLICY wh_owner ON wormhole_data.users USING (true)")
	if _, err := CheckSchemaDeployment(ctx, s, password, tag, testHintID); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("inspection accepted altered row policy", err)
	}
	reject(toggle+"false)", "55000")
	run("ALTER POLICY wh_owner ON wormhole_data.users USING (current_user='wh_" + tag + "_owner'::name)")
	run(toggle + "false)")
	run(toggle + "false)")
	check("SELECT (NOT EXISTS (SELECT FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='wormhole_data'::regnamespace))::text")
	run(toggle + "true)")
}
