package sharedpg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresBoundaryPermissions(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	exec := func(sql string, args ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	check := func(sql string) {
		t.Helper()
		r := exec(sql)
		if len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("boundary state")
		}
	}
	rejectMigration := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("boundary migration rejection", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.BoundaryPermissionsMigration("testscope", testHintID)
	wrong, _ := deploy.BoundaryPermissionsMigration("testscope", uuid.NewString())
	rejectMigration(wrong, "55000")
	script("CREATE TABLE wormhole_data.boundary_grants(collision boolean)")
	rejectMigration(migration, "42P07")
	check("SELECT (schema_version=28 AND to_regclass('wormhole_data.boundaries') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP TABLE wormhole_data.boundary_grants")
	script(migration)
	rejectMigration(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, table := range []string{"boundaries", "boundary_grants"} {
			check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data." + table + "','SELECT,INSERT,UPDATE,DELETE,TRUNCATE'))::text")
		}
		for _, fn := range []string{"effective_boundary_permissions(uuid,uuid)", "connection_account_permissions(bytea,uuid,bigint,bigint,integer)"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
		}
	}
	user, other, group, boundary := native.admission.UserID, uuid.New(), uuid.New(), uuid.New()
	script("BEGIN")
	defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,$2)", []byte(other.String()), []byte(other.String()))
	exec("INSERT INTO wormhole_data.groups(id,name) VALUES($1::uuid,'Boundary group')", []byte(group.String()))
	exec("INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES($1::uuid,$2::uuid)", []byte(group.String()), []byte(user.String()))
	exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(boundary.String()))
	evaluate := func(want permissions.Mask, owner uuid.UUID, grants []permissions.Grant) {
		t.Helper()
		expected, e := permissions.Effective(user, []permissions.Node{{ID: boundary, Owner: owner}}, []uuid.UUID{group}, grants)
		if e != nil || expected != want {
			t.Fatal("native boundary fixture", e)
		}
		r := exec("SELECT wormhole_data.effective_boundary_permissions($1::uuid,$2::uuid)::text", []byte(user.String()), []byte(boundary.String()))
		if string(r.Rows[0][0]) != strconv.Itoa(int(want)) {
			t.Fatal("SQL boundary permission mismatch", want, string(r.Rows[0][0]))
		}
	}
	for mask := permissions.Mask(1); mask <= permissions.All; mask++ {
		script("DELETE FROM wormhole_data.boundary_grants")
		exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES($1::uuid,$2::uuid,$3::int),($1::uuid,$4::uuid,31)", []byte(boundary.String()), []byte(user.String()), []byte(strconv.Itoa(int(mask))), []byte(other.String()))
		exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,group_id,permissions) VALUES($1::uuid,$2::uuid,2)", []byte(boundary.String()), []byte(group.String()))
		evaluate(mask|permissions.Use, uuid.Nil, []permissions.Grant{{Node: boundary, User: user, Permissions: mask}, {Node: boundary, Group: group, Permissions: permissions.Use}, {Node: boundary, User: other, Permissions: permissions.All}})
	}
	exec("UPDATE wormhole_data.boundaries SET owner_user_id=$1::uuid WHERE id=$2::uuid", []byte(other.String()), []byte(boundary.String()))
	evaluate(0, other, []permissions.Grant{{Node: boundary, User: user, Permissions: permissions.All}})
	exec("UPDATE wormhole_data.boundaries SET owner_user_id=$1::uuid WHERE id=$2::uuid", []byte(user.String()), []byte(boundary.String()))
	evaluate(permissions.All, user, []permissions.Grant{{Node: boundary, User: user, Permissions: permissions.All}})
	script("UPDATE wormhole_data.boundaries SET owner_user_id=NULL,deleted=true")
	evaluate(0, other, []permissions.Grant{{Node: boundary, User: user, Permissions: permissions.All}})
	script("UPDATE wormhole_data.boundaries SET deleted=false")
	reject := func(sql, code string, args ...[]byte) {
		t.Helper()
		script("SAVEPOINT boundary_failure")
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("boundary rejection", code, r.Err)
		}
		script("ROLLBACK TO SAVEPOINT boundary_failure; RELEASE SAVEPOINT boundary_failure")
	}
	for _, table := range []string{"nodes", "credential_profiles", "credential_slots", "credential_slot_values", "user_node_overrides"} {
		reject("UPDATE wormhole_data."+table+" SET boundary_id=$1::uuid", "23503", []byte(uuid.NewString()))
	}
	for _, sql := range []string{"INSERT INTO wormhole_data.boundaries(id) VALUES('00000000-0000-0000-0000-000000000000')", "UPDATE wormhole_data.boundaries SET row_version=0", "UPDATE wormhole_data.boundary_grants SET permissions=0", "UPDATE wormhole_data.boundary_grants SET permissions=32", "UPDATE wormhole_data.boundary_grants SET signature=decode('00','hex')", "UPDATE wormhole_data.boundary_grants SET user_id=NULL,group_id=NULL", "UPDATE wormhole_data.boundary_grants SET row_version=0"} {
		reject(sql, "23514")
	}
	reject("INSERT INTO wormhole_data.boundary_grants SELECT * FROM wormhole_data.boundary_grants", "23505")
	for _, args := range [][][]byte{{nil, []byte(boundary.String())}, {[]byte(user.String()), nil}, {[]byte(uuid.Nil.String()), []byte(boundary.String())}, {[]byte(user.String()), []byte(uuid.Nil.String())}} {
		reject("SELECT wormhole_data.effective_boundary_permissions($1::uuid,$2::uuid)", "22023", args...)
	}
	for _, ids := range [][2]uuid.UUID{{user, uuid.New()}, {uuid.New(), boundary}} {
		r := exec("SELECT wormhole_data.effective_boundary_permissions($1::uuid,$2::uuid)", []byte(ids[0].String()), []byte(ids[1].String()))
		if string(r.Rows[0][0]) != "0" {
			t.Fatal("missing boundary/user granted")
		}
	}
	script("SAVEPOINT disabled_boundary_user")
	exec("UPDATE wormhole_data.users SET disabled=true WHERE id=$1::uuid", []byte(user.String()))
	r := exec("SELECT wormhole_data.effective_boundary_permissions($1::uuid,$2::uuid)", []byte(user.String()), []byte(boundary.String()))
	if string(r.Rows[0][0]) != "0" {
		t.Fatal("disabled boundary access")
	}
	script("ROLLBACK TO SAVEPOINT disabled_boundary_user; RELEASE SAVEPOINT disabled_boundary_user")
	script("ROLLBACK")
	// Existing journal/snapshot reader must refuse while either new table changes.
	for _, mutation := range []string{"INSERT INTO wormhole_data.boundaries(id) VALUES('" + uuid.NewString() + "')", "DELETE FROM wormhole_data.boundary_grants", "TRUNCATE wormhole_data.boundary_grants"} {
		script("BEGIN")
		script(mutation)
		if _, e := native.TreePage(ctx, TreeCursor{}, 32); e != ErrChangeInProgress {
			t.Fatal("boundary mutation did not lock snapshot", e)
		}
		script("ROLLBACK")
	}
	// This test wrapper obtains real admitted identity/capability, and is rolled
	// back. The helper itself never receives a caller-selected user or boundary.
	script("BEGIN")
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,$2)", []byte(other.String()), []byte(other.String()))
	script("CREATE FUNCTION wormhole_api_v1.test_account_permissions(p bytea,n uuid,e bigint,s bigint,m integer) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT wormhole_data.connection_account_permissions(p,n,e,s,m)'; ALTER FUNCTION wormhole_api_v1.test_account_permissions(bytea,uuid,bigint,bigint,integer) OWNER TO wh_testscope_owner; REVOKE ALL ON FUNCTION wormhole_api_v1.test_account_permissions(bytea,uuid,bigint,bigint,integer) FROM PUBLIC; GRANT EXECUTE ON FUNCTION wormhole_api_v1.test_account_permissions(bytea,uuid,bigint,bigint,integer) TO wh_testscope_user")
	var capHex []byte
	if e := native.capability.With(func(b []byte) error { capHex = hex.AppendEncode(nil, b); return nil }); e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(capHex)
	node, nodeBoundary, primaryBoundary, gatewayBoundary, profile, gateway := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, b := range []string{nodeBoundary, primaryBoundary, gatewayBoundary} {
		exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(b))
	}
	exec("INSERT INTO wormhole_data.nodes(id,kind,name,protocol,host,username,credential_mode,credential_id,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal) SELECT $1::uuid,1,'Gate',1,'server.example','node-user',2,$2::uuid,$3::uuid,2,seal_signer_key_id,seal_signer_key_version,seal FROM wormhole_data.nodes WHERE seal IS NOT NULL LIMIT 1", []byte(node), []byte(profile), []byte(nodeBoundary))
	for i, p := range []string{profile, gateway} {
		b := primaryBoundary
		if i == 1 {
			b = gatewayBoundary
		}
		exec("INSERT INTO wormhole_data.credential_profiles(id,name,protocol,kind,provider,username,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal) SELECT $1::uuid,$2,'rdp','password','local','account-user',$3::uuid,2,seal_signer_key_id,seal_signer_key_version,seal FROM wormhole_data.nodes WHERE id=$4::uuid", []byte(p), []byte(p), []byte(b), []byte(node))
	}
	exec("INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,2)", []byte(node), []byte(user.String()))
	grant := func(b string, mask int) {
		t.Helper()
		exec("INSERT INTO wormhole_data.boundary_grants(boundary_id,user_id,permissions) VALUES($1::uuid,$2::uuid,$3::int) ON CONFLICT (boundary_id,user_id,group_id) DO UPDATE SET permissions=EXCLUDED.permissions", []byte(b), []byte(user.String()), []byte(strconv.Itoa(mask)))
	}
	call := func(mask int, want string) *resolver.Plan {
		t.Helper()
		snapshot := exec("SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta").Rows[0]
		script("SAVEPOINT account_call")
		script("SET LOCAL SESSION AUTHORIZATION \"wh_testscope_d_" + native.admission.DeviceID.String() + "\"")
		r := admin.ExecParams(ctx, "SELECT wormhole_api_v1.test_account_permissions(decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::int)::text", [][]byte{capHex, []byte(node), snapshot[0], snapshot[1], []byte(strconv.Itoa(mask))}, nil, nil, nil).Read()
		if want != "" {
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != want || len(r.Rows) != 0 {
				t.Fatal("account gate", want, r.Err)
			}
		} else if r.Err != nil || len(r.Rows) != 1 {
			t.Fatal("account gate", r.Err)
		}
		script("ROLLBACK TO SAVEPOINT account_call; RELEASE SAVEPOINT account_call")
		if want != "" {
			return nil
		}
		var p resolver.Plan
		if json.Unmarshal(r.Rows[0][0], &p) != nil {
			t.Fatal("account plan")
		}
		return &p
	}
	savedCap := capHex
	capHex = []byte("00")
	call(2, "WH007")
	capHex = savedCap
	call(2, "42501")
	grant(primaryBoundary, 2)
	if p := call(2, ""); p.Credential.ID != profile {
		t.Fatal("wrong account")
	}
	call(8, "42501")
	grant(primaryBoundary, 8)
	call(2, "42501")
	exec("UPDATE wormhole_data.grants SET permissions=8 WHERE node_id=$1::uuid", []byte(node))
	call(8, "")
	grant(primaryBoundary, 2)
	call(8, "42501")
	exec("UPDATE wormhole_data.grants SET permissions=2 WHERE node_id=$1::uuid", []byte(node))
	exec("UPDATE wormhole_data.nodes SET rdp_gateway_usage_method=1,rdp_gateway_hostname='gateway.example',rdp_gateway_credential_id=$1::uuid WHERE id=$2::uuid", []byte(gateway), []byte(node))
	call(2, "42501")
	grant(gatewayBoundary, 2)
	call(2, "")
	exec("UPDATE wormhole_data.grants SET permissions=8 WHERE node_id=$1::uuid", []byte(node))
	grant(primaryBoundary, 8)
	call(8, "42501")
	grant(gatewayBoundary, 8)
	call(8, "")
	exec("UPDATE wormhole_data.grants SET permissions=2 WHERE node_id=$1::uuid", []byte(node))
	grant(primaryBoundary, 2)
	grant(gatewayBoundary, 2)
	script("SAVEPOINT disabled_account_gate")
	exec("UPDATE wormhole_data.users SET disabled=true WHERE id=$1::uuid", []byte(user.String()))
	call(2, "WH001")
	script("ROLLBACK TO SAVEPOINT disabled_account_gate; RELEASE SAVEPOINT disabled_account_gate")
	script("SAVEPOINT revoked_device_gate")
	exec("UPDATE wormhole_data.devices SET status='revoked' WHERE id=$1::uuid", []byte(native.admission.DeviceID.String()))
	call(2, "WH001")
	script("ROLLBACK TO SAVEPOINT revoked_device_gate; RELEASE SAVEPOINT revoked_device_gate")

	script("SAVEPOINT private_boundary")
	exec("UPDATE wormhole_data.boundaries SET owner_user_id=$1::uuid WHERE id=$2::uuid", []byte(other.String()), []byte(primaryBoundary))
	call(2, "42501")
	script("ROLLBACK TO SAVEPOINT private_boundary; RELEASE SAVEPOINT private_boundary")
	script("SAVEPOINT deleted_boundary")
	exec("UPDATE wormhole_data.boundaries SET deleted=true WHERE id=$1::uuid", []byte(primaryBoundary))
	call(2, "42501")
	script("ROLLBACK TO SAVEPOINT deleted_boundary; RELEASE SAVEPOINT deleted_boundary")
	exec("UPDATE wormhole_data.nodes SET use_inline_password=true,rdp_gateway_usage_method=0 WHERE id=$1::uuid", []byte(node))
	call(2, "42501")
	grant(nodeBoundary, 2)
	if p := call(2, ""); p.Credential.Kind != "inline" {
		t.Fatal("inline account")
	}
	exec("UPDATE wormhole_data.nodes SET use_inline_password=false,credential_mode=1 WHERE id=$1::uuid", []byte(node))
	call(2, "")
	for _, mask := range []int{0, 1, 3, 16, 31} {
		call(mask, "22023")
	}
	script("ROLLBACK")
}
