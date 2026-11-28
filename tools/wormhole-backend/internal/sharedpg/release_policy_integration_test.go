package sharedpg

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func testPostgresReleasePolicyMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	reject := func(sql string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != "55000" {
			t.Fatal("release policy migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.ReleasePolicyMigration("testscope", testHintID)
	wrong, _ := deploy.ReleasePolicyMigration("testscope", uuid.NewString())
	reject(wrong)
	before := admin.ExecParams(ctx, "SELECT 'wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint)'::regprocedure::oid::text", nil, nil, nil, nil).Read()
	if before.Err != nil || len(before.Rows) != 1 {
		t.Fatal(before.Err)
	}
	script(migration)
	reject(migration)
	after := admin.ExecParams(ctx, "SELECT 'wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint)'::regprocedure::oid::text", nil, nil, nil, nil).Read()
	if after.Err != nil || len(after.Rows) != 1 || string(before.Rows[0][0]) != string(after.Rows[0][0]) {
		t.Fatal("function identity changed", after.Err)
	}
	for _, role := range []string{"user", "admin", "enroll"} {
		r := admin.ExecParams(ctx, "SELECT (NOT has_function_privilege('wh_testscope_"+role+"','wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint)','EXECUTE'))::text", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("policy graph exposed", r.Err)
		}
	}
}
