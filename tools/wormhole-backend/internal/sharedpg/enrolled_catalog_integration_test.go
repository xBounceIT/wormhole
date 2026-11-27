package sharedpg

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func testPostgresEnrolledCatalogMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("enrolled migration state", r.Err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatal("enrolled migration rejection", err)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.EnrolledCatalogAuthorsMigration("testscope", testHintID)
	wrong, _ := deploy.EnrolledCatalogAuthorsMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.enrolled_author_certificate(uuid,uuid,integer) RETURNS bytea LANGUAGE sql AS 'SELECT NULL::bytea'")
	reject(migration, "42723")
	check("SELECT (schema_version=41 AND (SELECT pronargs=4 FROM pg_proc WHERE oid='wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)'::regprocedure))::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.enrolled_author_certificate(uuid,uuid,integer)")
	script(migration)
	reject(migration, "55000")
	check("SELECT (schema_version=42)::text FROM wormhole_data.workspace_meta")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, fn := range []string{"enrolled_author_certificate(uuid,uuid,integer)", "catalog_projection_wire(jsonb)", "key_copy_wire(jsonb)", "connection_snapshot(uuid,uuid,bigint,bigint)", "credential_release_graph(uuid,uuid,bigint,bigint)"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
		}
	}
	check("SELECT (has_function_privilege('wh_testscope_user','wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)'::regprocedure AND a.grantee=0))::text")
}
