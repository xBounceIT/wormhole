package sharedpg

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func testPostgresNodeFieldsMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
			t.Fatal("node field migration", err)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("node field migration state", r.Err)
		}
	}
	migration, _ := deploy.NodeSecretManifestsMigration("testscope", testHintID)
	wrong, _ := deploy.NodeSecretManifestsMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE TABLE wormhole_data.node_secret_manifests(id integer)")
	reject(migration, "42P07")
	check("SELECT (schema_version=38 AND to_regprocedure('wormhole_data.node_fields_valid(jsonb,boolean)') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP TABLE wormhole_data.node_secret_manifests")
	script(migration)
	reject(migration, "55000")
	check("SELECT (schema_version=39)::text FROM wormhole_data.workspace_meta")
	for _, role := range []string{"user", "admin", "enroll"} {
		for _, fn := range []string{"node_fields_valid(jsonb,boolean)", "owner_values(text,uuid,bigint,bigint)", "selection_record(text,uuid,uuid,bigint,bigint)", "credential_values(uuid,bigint,bigint)"} {
			check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data." + fn + "','EXECUTE'))::text")
		}
		for _, permission := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"} {
			check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data.node_secret_manifests','" + permission + "'))::text")
		}
	}
	for _, raw := range []string{`null`, `{}`, `[null]`, `[[]]`, `[3]`, `[{"field":"notes","version":1,"present":true}]`, `[{"field":"inlinePassword","version":0,"present":true}]`, `[{"field":"inlinePassword","version":9223372036854775808,"present":true}]`, `[{"field":"inlinePassword","version":1,"present":true,"extra":false}]`, `[{"field":"inlinePassword","version":1}]`, `[{"field":"inlinePassword","version":1,"present":true},{"field":"inlinePassword","version":2,"present":true}]`} {
		r := admin.ExecParams(ctx, "SELECT wormhole_data.node_fields_valid($1::jsonb,false)::text", [][]byte{[]byte(raw)}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "false" {
			t.Fatal("malformed node manifest", r.Err)
		}
	}
	fields, _ := json.Marshal([]map[string]any{{"field": "inlinePassword", "version": 1, "present": true}})
	r := admin.ExecParams(ctx, "SELECT (wormhole_data.node_fields_valid($1::jsonb,false) AND NOT wormhole_data.node_fields_valid($1::jsonb,true) AND NOT wormhole_data.node_fields_valid($1::jsonb,NULL))::text", [][]byte{fields}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("manifest tombstone rules", r.Err)
	}
}
