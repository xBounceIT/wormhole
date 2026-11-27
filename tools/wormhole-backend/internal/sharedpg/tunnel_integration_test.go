package sharedpg

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func testPostgresTunnelMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatal("tunnel migration", err)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("tunnel migration state", r.Err)
		}
	}
	migration, _ := deploy.TunnelProfilesMigration("testscope", testHintID)
	wrong, _ := deploy.TunnelProfilesMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE TABLE wormhole_data.tunnel_profiles(id integer)")
	reject(migration, "42P07")
	check("SELECT (schema_version=39)::text FROM wormhole_data.workspace_meta")
	script("DROP TABLE wormhole_data.tunnel_profiles")
	script(migration)
	reject(migration, "55000")
	check("SELECT (schema_version=40)::text FROM wormhole_data.workspace_meta")
	ipsec, _ := deploy.FortinetIPsecMigration("testscope", testHintID)
	wrongIPsec, _ := deploy.FortinetIPsecMigration("testscope", uuid.NewString())
	reject(wrongIPsec, "55000")
	script(ipsec)
	reject(ipsec, "55000")
	check("SELECT (schema_version=41)::text FROM wormhole_data.workspace_meta")
	check("SELECT (pg_get_constraintdef(oid) LIKE '%9%')::text FROM pg_constraint WHERE conrelid='wormhole_data.tunnel_profiles'::regclass AND conname='tunnel_profiles_kind_check'")

	for _, role := range []string{"user", "admin", "enroll"} {
		for _, permission := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"} {
			check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data.tunnel_profiles','" + permission + "'))::text")
		}
		for _, fn := range []string{"selection_record(text,uuid,uuid,bigint,bigint)", "owner_values(text,uuid,bigint,bigint)", "connection_snapshot(uuid,uuid,bigint,bigint)", "connection_account_permissions(bytea,uuid,bigint,bigint,integer)", "credential_release_graph(uuid,uuid,bigint,bigint)"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
		}
	}
}
