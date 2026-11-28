package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func resolverErrorCode(err error) string {
	return map[error]string{resolver.ErrChain: "WH016", resolver.ErrTarget: "WH017", resolver.ErrCredential: "WH018", resolver.ErrTunnel: "WH019"}[err]
}
func comparePostgresResolution(t *testing.T, ctx context.Context, admin *pgconn.PgConn, chain []vaultstore.NodeMetadata, override string, credential *vaultstore.CredentialMetadata) resolver.Plan {
	t.Helper()
	expected, goErr := resolver.Resolve(chain, override)
	if goErr == nil && credential != nil {
		expected, goErr = resolver.ApplyCredential(expected, *credential)
	}
	raw, _ := json.Marshal(chain)
	args := [][]byte{raw, []byte(override)}
	sql := "SELECT wormhole_data.resolve_chain($1::jsonb,$2)::text"
	if credential != nil {
		c, _ := json.Marshal(credential)
		args = append(args, c)
		sql = "SELECT wormhole_data.apply_credential(wormhole_data.resolve_chain($1::jsonb,$2),$3::jsonb)::text"
	}
	result := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
	if goErr != nil {
		code := resolverErrorCode(goErr)
		var pe *pgconn.PgError
		if code == "" || !errors.As(result.Err, &pe) || pe.Code != code {
			t.Fatalf("Go/SQL rejection mismatch: Go %v SQL %v", goErr, result.Err)
		}
		return resolver.Plan{}
	}
	if result.Err != nil || len(result.Rows) != 1 {
		t.Fatal("SQL resolution", result.Err)
	}
	var actual resolver.Plan
	if err := json.Unmarshal(result.Rows[0][0], &actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("plan mismatch: got %+v want %+v", actual, expected)
	}
	return actual
}

func testPostgresResolver(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
			t.Fatal("resolver migration rejection", err)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.ResolverMigration("testscope", testHintID)
	wrong, _ := deploy.ResolverMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.apply_credential(jsonb,jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	r := admin.ExecParams(ctx, "SELECT (schema_version=21 AND to_regprocedure('wormhole_data.resolve_chain(jsonb,text)') IS NULL)::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("partial resolver migration", r.Err)
	}
	script("DROP FUNCTION wormhole_data.apply_credential(jsonb,jsonb)")
	script(migration)
	reject(migration, "55000")
	r = admin.ExecParams(ctx, "SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_data.resolve_chain(jsonb,text)','EXECUTE') AND NOT has_function_privilege('wh_testscope_enroll','wormhole_data.resolve_chain(jsonb,text)','EXECUTE'))::text", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("resolver ACL", r.Err)
	}
	raw, err := os.ReadFile("../resolver/testdata/conformance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name       string                         `json:"name"`
		Chain      []vaultstore.NodeMetadata      `json:"chain"`
		Override   string                         `json:"overrideCredentialId"`
		Credential *vaultstore.CredentialMetadata `json:"credential"`
		Expected   resolver.Plan                  `json:"expected"`
		Error      string                         `json:"error"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 40 {
		t.Fatal("missing shared conformance cases")
	}
	for _, f := range fixtures {
		t.Run("SQLResolver/"+f.Name, func(t *testing.T) {
			actual := comparePostgresResolution(t, ctx, admin, f.Chain, f.Override, f.Credential)
			if f.Error == "" && actual != f.Expected {
				t.Fatal("shared fixture expectation differs")
			}
		})
	}
	// PostgreSQL has no Go-style backslash-v escape. A literal v must not be trimmed.
	for _, value := range []string{"vserverv", "\vserver\v", "\u0085\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000server\u3000", "\ufeffserver\ufeff"} {
		r := admin.ExecParams(ctx, "SELECT wormhole_data.resolver_text($1)", [][]byte{[]byte(value)}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != strings.TrimSpace(value) {
			t.Fatal("Unicode trim divergence", r.Err)
		}
	}
	testPostgresResolverValidation(t, ctx, admin, fixtures[0].Chain[0])
	testPostgresResolverDepth(t, ctx, admin)
	// SQL NULL must not bypass the saved/override kind check.
	for _, kind := range []any{nil, "", "none"} {
		plan, _ := json.Marshal(map[string]any{"protocol": 0, "credential": map[string]any{"kind": kind, "id": testHintID}, "username": "", "domain": ""})
		credential, _ := json.Marshal(map[string]any{"id": testHintID, "protocol": "ssh", "username": "test-user"})
		result := admin.ExecParams(ctx, "SELECT wormhole_data.apply_credential($1::jsonb,$2::jsonb)", [][]byte{plan, credential}, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(result.Err, &pe) || pe.Code != "WH018" {
			t.Fatal("invalid credential kind", result.Err)
		}
	}

}

func testPostgresResolverValidation(t *testing.T, ctx context.Context, admin *pgconn.PgConn, base vaultstore.NodeMetadata) {
	t.Helper()
	raw, _ := json.Marshal(base)
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	compare := func(name string, input map[string]any) {
		t.Helper()
		wire, _ := json.Marshal(input)
		decoder := json.NewDecoder(bytes.NewReader(wire))
		decoder.DisallowUnknownFields()
		var node vaultstore.NodeMetadata
		goValid := decoder.Decode(&node) == nil && node.Validate() == nil
		result := admin.ExecParams(ctx, "SELECT wormhole_data.resolver_node_valid($1::jsonb)::text", [][]byte{wire}, nil, nil, nil).Read()
		if result.Err != nil || len(result.Rows) != 1 || (string(result.Rows[0][0]) == "true") != goValid {
			t.Fatalf("node validation differs for %s: Go valid %v, SQL %v", name, goValid, result.Err)
		}
		if goValid {
			comparePostgresResolution(t, ctx, admin, []vaultstore.NodeMetadata{node}, "", nil)
		}
	}
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := field.Tag.Get("json")
		kind := field.Type.Kind()
		if kind == reflect.Pointer {
			kind = field.Type.Elem().Kind()
		}
		values := []any{nil, map[string]any{}, []any{}}
		switch kind {
		case reflect.Bool:
			values = append(values, true, false, "true", 1)
		case reflect.Int, reflect.Int64:
			for _, number := range []string{"-9223372036854775809", "-9223372036854775808", "-1", "0", "1", "2", "3", "4", "5", "6", "7", "8", "15", "16", "24", "32", "65535", "65536", "2147483647", "2147483648", "9223372036854775807", "9223372036854775808", "1.5"} {
				values = append(values, json.Number(number))
			}
			values = append(values, "1", true)
		case reflect.String:
			values = append(values, "", "node", base.ID, base.ID+"\n", base.ID+"\r", uuid.NewString(), "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "\n", "\u0001", "\u0085", "\u00a0", "node\u0085tail", strings.Repeat("\U0001f680", 256), strings.Repeat("x", 257), strings.Repeat("x", 16385), "SHA256:"+strings.Repeat("A", 43), "SHA256:"+strings.Repeat("A", 43)+"\n", "SHA256:"+strings.Repeat("A", 42)+"B", true, 1)
		}
		for j, value := range values {
			candidate := make(map[string]any, len(object))
			for k, v := range object {
				candidate[k] = v
			}
			candidate[name] = value
			compare(name+"/"+string(rune('a'+j)), candidate)
		}
	}
	object["unknownField"] = true
	compare("unknown-field", object)
}

func testPostgresResolverDepth(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	for _, depth := range []int{vaultstore.MaxNodeDepth, vaultstore.MaxNodeDepth + 1} {
		chain := make([]vaultstore.NodeMetadata, depth)
		for i := range chain {
			chain[i] = vaultstore.NodeMetadata{ID: uuid.NewString(), Name: "node", Kind: 0}
			if i > 0 {
				chain[i-1].ParentID = &chain[i].ID
			}
		}
		protocol, host := 0, "deep.example"
		chain[0].Kind = 1
		chain[0].Protocol = &protocol
		chain[depth-1].Host = &host
		comparePostgresResolution(t, ctx, admin, chain, "", nil)
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[]"), []byte("[null]"), []byte("[1]")} {
		result := admin.ExecParams(ctx, "SELECT wormhole_data.resolve_chain($1::jsonb,'')", [][]byte{raw}, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(result.Err, &pe) || pe.Code != "WH016" {
			t.Fatal("invalid chain payload", result.Err)
		}
	}
}
