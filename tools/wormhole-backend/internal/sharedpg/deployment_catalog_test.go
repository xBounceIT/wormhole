package sharedpg

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Verify the policy independently of the catalog digest. Regenerating the
// fingerprint for a new migration must not bless a weaker public API.
func checkDeploymentAPIPermissions(t *testing.T, ctx context.Context, db *pgconn.PgConn) {
	t.Helper()
	rows := db.ExecParams(ctx, `SELECT p.proname FROM pg_proc p WHERE p.pronamespace='wormhole_api_v1'::regnamespace AND (
		NOT p.prosecdef OR NOT coalesce('search_path=pg_catalog, pg_temp'=ANY(p.proconfig),false)
		OR NOT EXISTS(SELECT FROM unnest(p.proconfig) s WHERE s ~ '^lock_timeout=[1-9][0-9]*(ms|s|min)?$')
		OR NOT EXISTS(SELECT FROM unnest(p.proconfig) s WHERE s ~ '^statement_timeout=[1-9][0-9]*(ms|s|min)?$')
		OR EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
			WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))
		ORDER BY p.proname`, nil, nil, nil, nil).Read()
	if rows.Err != nil {
		t.Fatal(rows.Err)
	}
	for _, row := range rows.Rows {
		t.Errorf("public API has unsafe privileges, search path or timeouts: %s", row[0])
	}
}

func checkCatalogDrift(t *testing.T, ctx context.Context, settings Settings, password []byte, db *pgconn.PgConn) {
	t.Helper()
	exec := func(t *testing.T, sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	const routine = "wormhole_api_v1.unencrypted_clients(bytea,uuid)"
	// Change just a comment inside the body, keeping the actual function
	// behavior, identity, language and deployment version intact.
	source := db.ExecParams(ctx, `SELECT pg_get_functiondef(oid),
	    replace(pg_get_functiondef(oid),prosrc,prosrc||E'\n-- local change\n') FROM pg_proc WHERE oid=$1::regprocedure`, [][]byte{[]byte(routine)}, nil, nil, nil).Read()
	if source.Err != nil || len(source.Rows) != 1 || len(source.Rows[0]) != 2 || string(source.Rows[0][0]) == string(source.Rows[0][1]) {
		t.Fatal("routine fixture", source.Err)
	}
	const sqlRoutine = "wormhole_api_v1.workspace_admin_recovery_material()"
	sqlBody := db.ExecParams(ctx, "SELECT pg_get_functiondef($1::regprocedure)", [][]byte{[]byte(sqlRoutine)}, nil, nil, nil).Read()
	if sqlBody.Err != nil || len(sqlBody.Rows) != 1 {
		t.Fatal("SQL routine fixture", sqlBody.Err)
	}
	exec(t, `CREATE ROLE catalog_reader NOLOGIN;
	    SET ROLE wh_testscope_owner;
	    CREATE TABLE wormhole_data.audit_log_208001 PARTITION OF wormhole_data.audit_log FOR VALUES FROM ('2080-01-01 00:00:00+00') TO ('2080-02-01 00:00:00+00');
	    RESET ROLE`)
	check := func(t *testing.T, want error) {
		t.Helper()
		_, err := CheckSchemaDeployment(ctx, settings, password, "testscope", testHintID)
		if !errors.Is(err, want) {
			t.Fatalf("catalog check: got %v, want %v", err, want)
		}
	}
	check(t, nil)
	const alter = "ALTER FUNCTION " + routine
	for _, tc := range []struct{ name, change, restore string }{
		{"source", string(source.Rows[0][1]), string(source.Rows[0][0])},
		{"parsed SQL source", "CREATE OR REPLACE FUNCTION " + sqlRoutine + ` RETURNS text LANGUAGE sql SECURITY DEFINER
		    SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s' RETURN NULL::text`, string(sqlBody.Rows[0][0])},
		{"configuration", alter + " SET application_name='fixture'", alter + " RESET application_name"},
		{"function grant", "REVOKE EXECUTE ON FUNCTION " + routine + " FROM wh_testscope_user", "GRANT EXECUTE ON FUNCTION " + routine + " TO wh_testscope_user"},
		{"table grant", "GRANT SELECT ON wormhole_data.workspace_meta TO catalog_reader", "REVOKE SELECT ON wormhole_data.workspace_meta FROM catalog_reader"},
		{"column grant", "REVOKE SELECT(id) ON wormhole_data.devices FROM wh_testscope_observer", "GRANT SELECT(id) ON wormhole_data.devices TO wh_testscope_observer"},
		{"single audit partition", "GRANT SELECT(action) ON wormhole_data.audit_log_208001 TO catalog_reader", "REVOKE SELECT(action) ON wormhole_data.audit_log_208001 FROM catalog_reader"},
		{"account group confirmation trigger", "ALTER TABLE wormhole_data.device_confirmations DISABLE TRIGGER confirm_account_group", "ALTER TABLE wormhole_data.device_confirmations ENABLE TRIGGER confirm_account_group"},
		{"unexpected API", "CREATE FUNCTION wormhole_api_v1.local_fixture() RETURNS int LANGUAGE sql RETURN 1", "DROP FUNCTION wormhole_api_v1.local_fixture()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(t, tc.change)
			t.Cleanup(func() { exec(t, tc.restore); check(t, nil) })
			check(t, ErrDeploymentMismatch)
		})
	}
	t.Run("workspace metadata", func(t *testing.T) {
		exec(t, "UPDATE wormhole_data.workspace_meta SET schema_version=schema_version-1 WHERE singleton")
		t.Cleanup(func() {
			exec(t, "UPDATE wormhole_data.workspace_meta SET schema_version=schema_version+1 WHERE singleton")
			check(t, nil)
		})
		check(t, ErrDeploymentMismatch)
	})
	t.Run("canceled inspection", func(t *testing.T) {
		conn, err := Connect(ctx, settings, password)
		if err != nil {
			t.Fatal(err)
		}
		defer closeDeploymentConnection(conn)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := checkSchemaDeployment(canceled, conn, "testscope", testHintID); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled catalog inspection", err)
		}
	})
}
