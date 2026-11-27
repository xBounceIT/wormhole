package sharedpg

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"testing"
)

func testPostgresConnectionSnapshot(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("snapshot migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.ConnectionSnapshotMigration("testscope", testHintID)
	wrong, _ := deploy.ConnectionSnapshotMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.connection_snapshot(uuid,uuid,bigint,bigint) RETURNS jsonb LANGUAGE sql AS 'SELECT null::jsonb'")
	reject(migration, "42723")
	r := admin.ExecParams(ctx, "SELECT (schema_version=30 AND to_regprocedure('wormhole_data.catalog_projection_wire(jsonb)') IS NULL)::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("snapshot migration rollback", r.Err)
	}
	script("DROP FUNCTION wormhole_data.connection_snapshot(uuid,uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, fn := range []string{"connection_snapshot(uuid,uuid,bigint,bigint)", "catalog_projection_wire(jsonb)"} {
			r := admin.ExecParams(ctx, "SELECT (NOT has_function_privilege('wh_testscope_"+role+"','wormhole_data."+fn+"','EXECUTE'))::text", nil, nil, nil, nil).Read()
			if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
				t.Fatal("snapshot ACL", r.Err)
			}
		}
	}
	testPostgresConnectionResolutionCases(t, ctx, admin, true)
}
