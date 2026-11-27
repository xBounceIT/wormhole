package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresDeviceConnectionLimitUpgrade(t *testing.T) {
	settings, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := Connect(ctx, settings, password)
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
	fresh, err := deploy.SchemaScript("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	previous, _, found := strings.Cut(fresh, "-- Version 92:")
	if !found {
		t.Fatal("schema 91 boundary missing")
	}
	run(previous + "COMMIT;")
	// The tagged owner creates its own device roles as in real enrollment.
	// Cases 2–4 distinguish unconfirmed, explicitly constrained and replaced roles.
	run(`SET ROLE wh_testscope_owner;
		DO $fixture$
		DECLARE seq integer; device uuid; target text;
		BEGIN
			FOR seq IN 1..4 LOOP
				device:=('00000000-0000-4000-8000-00000000000'||seq)::uuid;
				target:='wh_testscope_d_'||device;
				INSERT INTO wormhole_data.users(id,login_name) VALUES(device,'limit-user-'||seq);
				INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES(device,device,target,'active');
				EXECUTE format('CREATE ROLE %I LOGIN NOINHERIT CONNECTION LIMIT %s',target,CASE WHEN seq=3 THEN 1 ELSE 2 END);
				EXECUTE format('GRANT wh_testscope_user TO %I WITH INHERIT TRUE, SET FALSE',target);
				IF seq<>2 THEN
					INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
					SELECT device,CASE WHEN seq=4 THEN 'wh_testscope_owner'::regrole::oid ELSE r.oid END,sha256('fixture'::bytea)
					FROM pg_roles r WHERE r.rolname=target;
				END IF;
			END LOOP;
		END $fixture$;
		RESET ROLE;`)
	migration, err := deploy.NextMigrationScript("testscope", testHintID, 91)
	if err != nil {
		t.Fatal(err)
	}
	run(migration)
	limits, err := readDeploymentRow(ctx, db, `SELECT string_agg(r.rolconnlimit::text,',' ORDER BY d.id)
		FROM wormhole_data.devices d JOIN pg_roles r ON r.rolname=d.role_name`, 1)
	if err != nil || string(limits[0]) != "3,2,1,2" {
		t.Fatal("unexpected upgraded role limits", limits, err)
	}
	if _, err := db.Exec(ctx, migration).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated upgrade", err)
	}
	run("ROLLBACK")
	const available = "SELECT (to_regprocedure('wormhole_api_v1.admin_credential_slots(bytea,uuid,bytea,bytea)') IS NOT NULL)::text"
	if row, err := readDeploymentRow(ctx, db, available, 1); err != nil || string(row[0]) != "false" {
		t.Fatal("unexpected slot API on schema 92", err)
	}
	slots, err := deploy.NextMigrationScript("testscope", testHintID, 92)
	if err != nil {
		t.Fatal(err)
	}
	run(slots)
	if row, err := readDeploymentRow(ctx, db, available, 1); err != nil || string(row[0]) != "true" {
		t.Fatal("slot API missing after schema 93 upgrade", err)
	}
	if _, err := db.Exec(ctx, slots).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated slot upgrade", err)
	}
	run("ROLLBACK")
	groups, err := deploy.NextMigrationScript("testscope", testHintID, 93)
	if err != nil {
		t.Fatal(err)
	}
	// The database may already have FORCE RLS when the new private table is installed.
	run("SET ROLE wh_testscope_owner; SELECT wormhole_data.set_row_security('" + testHintID + "',true); RESET ROLE")
	roleName := func(login string) string {
		digest := sha256.Sum256([]byte("testscope" + login))
		return "wh_testscope_u_" + strings.ToLower(base32.StdEncoding.EncodeToString(digest[:])[:20])
	}
	collision := roleName("limit-user-2")
	run("CREATE ROLE " + collision + " NOLOGIN")
	if _, err := db.Exec(ctx, groups).ReadAll(); !hasSQLState(err, "42710", 0) {
		t.Fatal("existing cluster role accepted", err)
	}
	run("ROLLBACK")
	assert := func(query string) {
		t.Helper()
		row, err := readDeploymentRow(ctx, db, "SELECT ("+query+")::text", 1)
		if err != nil || string(row[0]) != "true" {
			t.Fatal(query, err)
		}
	}
	assert("to_regclass('wormhole_data.account_group_roles') IS NULL AND to_regrole('" + roleName("limit-user-1") + "') IS NULL")
	run("DROP ROLE " + collision)
	run(groups)
	assert("(SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='wormhole_data.account_group_roles'::regclass)")
	assert("(SELECT count(*)=4 FROM wormhole_data.account_group_roles)")
	const affiliations = `SELECT string_agg(u.login_name,',' ORDER BY u.login_name)
		FROM wormhole_data.users u JOIN wormhole_data.account_group_roles g ON g.user_id=u.id
		JOIN pg_auth_members m ON m.roleid=g.role_oid JOIN pg_roles r ON r.oid=m.member
		JOIN wormhole_data.devices d ON d.role_name=r.rolname AND d.user_id=u.id
		WHERE NOT (m.admin_option OR m.set_option OR m.inherit_option) AND m.grantor='wh_testscope_owner'::regrole`
	assert("(" + affiliations + ")='limit-user-1,limit-user-3'")
	assert("NOT has_table_privilege('wh_testscope_user','wormhole_data.account_group_roles','SELECT') AND NOT has_function_privilege('wh_testscope_user','wormhole_data.sync_account_device_group(uuid)','EXECUTE')")
	run("UPDATE wormhole_data.users SET disabled=true WHERE login_name='limit-user-3'")
	assert("(" + affiliations + ")='limit-user-1'")
	run("UPDATE wormhole_data.users SET disabled=false WHERE login_name='limit-user-3'")
	assert("(" + affiliations + ")='limit-user-1,limit-user-3'")
	run("UPDATE wormhole_data.devices SET status='revoked' WHERE id='00000000-0000-4000-8000-000000000001'")
	assert("(" + affiliations + ")='limit-user-3'")
	run(`INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
		SELECT d.id,r.oid,sha256('fixture'::bytea) FROM wormhole_data.devices d
		JOIN pg_roles r ON r.rolname=d.role_name WHERE d.id='00000000-0000-4000-8000-000000000002'`)
	assert("(" + affiliations + ")='limit-user-2,limit-user-3'")
	run("UPDATE wormhole_data.users SET disabled=true WHERE login_name='limit-user-2'")
	run("UPDATE wormhole_data.account_group_roles SET role_oid='wh_testscope_owner'::regrole WHERE role_name='" + collision + "'")
	if _, err := db.Exec(ctx, "UPDATE wormhole_data.users SET disabled=false WHERE login_name='limit-user-2'").ReadAll(); !hasSQLState(err, "WH009", 0) {
		t.Fatal("account with an unrecognized group was re-enabled", err)
	}
	assert("(SELECT disabled FROM wormhole_data.users WHERE login_name='limit-user-2')")
	assert("(" + affiliations + ")='limit-user-3'")
	const login = "Élise 東京"
	run("INSERT INTO wormhole_data.users(id,login_name) VALUES(gen_random_uuid(),'" + login + "')")
	assert(`EXISTS(SELECT FROM wormhole_data.account_group_roles g JOIN pg_roles r ON r.oid=g.role_oid AND r.rolname=g.role_name
		JOIN wormhole_data.users u ON u.id=g.user_id WHERE u.login_name='` + login + `' AND r.rolname='` + roleName(login) + `'
		AND NOT (r.rolcanlogin OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolsuper OR r.rolreplication OR r.rolbypassrls))`)
	if _, err := db.Exec(ctx, groups).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated group migration", err)
	}
	run("ROLLBACK")
	if r, err := readDeploymentRow(ctx, db, createSlotAvailableSQL, 1); err != nil || string(r[0]) != "false" {
		t.Fatal("older deployment offered slot creation", err)
	}
	createSlot, err := deploy.NextMigrationScript("testscope", testHintID, 94)
	if err != nil {
		t.Fatal(err)
	}
	run(createSlot)
	if r, err := readDeploymentRow(ctx, db, createSlotAvailableSQL, 1); err != nil || string(r[0]) != "true" {
		t.Fatal("upgraded deployment could not create slots", err)
	}
	assert(`(SELECT prosecdef AND has_function_privilege('wh_testscope_user',p.oid,'EXECUTE')
		AND NOT has_function_privilege('wh_testscope_enroll',p.oid,'EXECUTE') FROM pg_proc p
		WHERE p.pronamespace='wormhole_api_v1'::regnamespace AND p.proname='create_credential_slot')`)
	if _, err := db.Exec(ctx, createSlot).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated creation API upgrade", err)
	}
	run("ROLLBACK")
	retirement, err := deploy.NextMigrationScript("testscope", testHintID, 95)
	if err != nil {
		t.Fatal(err)
	}
	run(retirement)
	checkDeploymentAPIPermissions(t, ctx, db)
	// These are synthetic accounts in this temporary cluster. Use one fixed
	// login to cover deletion, rollback and a new identity at that login.
	name := roleName(login)
	row, err := readDeploymentRow(ctx, db, "SELECT oid::text FROM pg_roles WHERE rolname='"+name+"'", 1)
	if err != nil {
		t.Fatal(err)
	}
	original := string(row[0])
	remove := "DELETE FROM wormhole_data.users WHERE login_name='" + login + "'"
	run("BEGIN")
	run(remove)
	assert("NOT EXISTS(SELECT FROM pg_roles WHERE rolname='" + name + "')")
	run("ROLLBACK")
	assert("EXISTS(SELECT FROM pg_roles WHERE oid=" + original + "::oid AND rolname='" + name + "')")
	run("GRANT " + name + " TO wh_testscope_observer")
	if _, err := db.Exec(ctx, remove).ReadAll(); !hasSQLState(err, "WH009", 0) {
		t.Fatal("deleted a group with external membership", err)
	}
	assert("pg_has_role('wh_testscope_observer','" + name + "','MEMBER')")
	run("REVOKE " + name + " FROM wh_testscope_observer")
	run("ALTER ROLE " + name + " RENAME TO preserved_account_role")
	run("CREATE ROLE " + name + " NOLOGIN NOINHERIT")
	if _, err := db.Exec(ctx, remove).ReadAll(); !hasSQLState(err, "WH009", 0) {
		t.Fatal("deleted a replacement cluster role", err)
	}
	assert("EXISTS(SELECT FROM pg_roles WHERE rolname='" + name + "' AND oid<>" + original + "::oid)")
	run("DROP ROLE " + name)
	run("ALTER ROLE preserved_account_role RENAME TO " + name)
	run(remove)
	assert("NOT EXISTS(SELECT FROM pg_roles WHERE oid=" + original + "::oid OR rolname='" + name + "')")
	run("INSERT INTO wormhole_data.users(id,login_name) VALUES(gen_random_uuid(),'" + login + "')")
	assert("EXISTS(SELECT FROM wormhole_data.account_group_roles g JOIN pg_roles r ON r.oid=g.role_oid AND r.rolname=g.role_name WHERE r.rolname='" + name + "' AND r.oid<>" + original + "::oid)")
	if _, err := db.Exec(ctx, retirement).ReadAll(); !hasSQLState(err, "55000", 0) {
		t.Fatal("repeated role retirement migration", err)
	}
}
