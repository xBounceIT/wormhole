package sharedpg

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/resolver"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func testPostgresSlots(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
			t.Fatal("slot migration", err)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("slot state", r.Err)
		}
	}
	migration, err := deploy.CredentialSlotsMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := deploy.CredentialSlotsMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.resolve_slot(jsonb,text,jsonb,jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=23)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.resolve_slot(jsonb,text,jsonb,jsonb)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.resolve_slot(jsonb,text,jsonb,jsonb)','EXECUTE'))::text")
	}
	raw, err := os.ReadFile("../resolver/testdata/slots-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name     string                        `json:"name"`
		Plan     resolver.Plan                 `json:"plan"`
		User     string                        `json:"userId"`
		Slot     resolver.CredentialSlot       `json:"slot"`
		Value    *resolver.CredentialSlotValue `json:"value"`
		Expected resolver.Plan                 `json:"expected"`
		Error    string                        `json:"error"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 30 {
		t.Fatal("missing shared slot fixtures")
	}
	query := "SELECT wormhole_data.resolve_slot($1::jsonb,$2,$3::jsonb,$4::jsonb)::text"
	for _, f := range fixtures {
		plan, _ := json.Marshal(f.Plan)
		slot, _ := json.Marshal(f.Slot)
		value, _ := json.Marshal(f.Value)
		want, goErr := resolver.ResolveSlot(f.Plan, f.User, f.Slot, f.Value)
		if (goErr != nil) != (f.Error != "") || (goErr == nil && want != f.Expected) {
			t.Fatal(f.Name, "fixture drift", goErr)
		}
		r := admin.ExecParams(ctx, query, [][]byte{plan, []byte(f.User), slot, value}, nil, nil, nil).Read()
		if goErr != nil {
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != "WH018" || len(r.Rows) != 0 {
				t.Fatal(f.Name, "slot rejection", r.Err)
			}
		} else {
			if r.Err != nil || len(r.Rows) != 1 {
				t.Fatal(f.Name, r.Err)
			}
			var got resolver.Plan
			if err = json.Unmarshal(r.Rows[0][0], &got); err != nil || got != want {
				t.Fatal(f.Name, "Go/SQL slot mismatch", err)
			}
			credential := vaultstore.CredentialMetadata{ID: want.Credential.ID, Protocol: resolver.CredentialProtocol(want.Protocol), Username: " personal ", Domain: " domain "}
			applied, e := resolver.ApplyCredential(want, credential)
			if e != nil {
				t.Fatal(e)
			}
			credentialJSON, _ := json.Marshal(credential)
			r = admin.ExecParams(ctx, "SELECT wormhole_data.apply_credential(wormhole_data.resolve_slot($1::jsonb,$2,$3::jsonb,$4::jsonb),$5::jsonb)::text", [][]byte{plan, []byte(f.User), slot, value, credentialJSON}, nil, nil, nil).Read()
			if r.Err != nil || len(r.Rows) != 1 {
				t.Fatal("slot identity", r.Err)
			}
			if err = json.Unmarshal(r.Rows[0][0], &got); err != nil || got != applied || got.Username != "personal" || got.Domain != "domain" {
				t.Fatal("slot mixed account", err)
			}
		}
	}
	// Raw SQL callers cannot use missing fields or wrong JSON types to bypass guards.
	f := fixtures[0]
	plan, _ := json.Marshal(f.Plan)
	slot, _ := json.Marshal(f.Slot)
	for _, index := range []int{0, 1, 2} {
		args := [][]byte{plan, []byte(f.User), slot, nil}
		args[index] = nil
		r := admin.ExecParams(ctx, query, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "WH018" || len(r.Rows) != 0 {
			t.Fatal("SQL NULL required input", index, r.Err)
		}
	}
	for _, index := range []int{0, 1, 2, 3} {
		bad := []string{"null", "{}", "[]", "true", "1", "\"text\""}
		if index == 1 {
			bad = []string{"", "bad", uuid.Nil.String()}
		}
		for _, input := range bad {
			if index == 3 && input == "null" {
				continue
			} // explicit JSON null is absent assignment
			args := [][]byte{plan, []byte(f.User), slot, nil}
			args[index] = []byte(input)
			r := admin.ExecParams(ctx, query, args, nil, nil, nil).Read()
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != "WH018" || len(r.Rows) != 0 {
				t.Fatal("slot raw input", index, input, r.Err)
			}
		}
	}
	for _, field := range []string{"resolverVersion", "protocol", "nodeId", "credential"} {
		var obj map[string]any
		json.Unmarshal(plan, &obj)
		delete(obj, field)
		bad, _ := json.Marshal(obj)
		r := admin.ExecParams(ctx, query, [][]byte{bad, []byte(f.User), slot, nil}, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "WH018" {
			t.Fatal("missing plan field", field, r.Err)
		}
	}
	for _, field := range []string{"id", "protocol", "defaultCredentialId", "allowSelfService"} {
		var obj map[string]any
		json.Unmarshal(slot, &obj)
		delete(obj, field)
		bad, _ := json.Marshal(obj)
		r := admin.ExecParams(ctx, query, [][]byte{plan, []byte(f.User), bad, nil}, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "WH018" {
			t.Fatal("missing slot field", field, r.Err)
		}
	}
	// SQL NULL, like Go nil, means no personal assignment, and uses the default.
	r := admin.ExecParams(ctx, query, [][]byte{plan, []byte(f.User), slot, nil}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 {
		t.Fatal("SQL NULL assignment", r.Err)
	}
	var got resolver.Plan
	if err = json.Unmarshal(r.Rows[0][0], &got); err != nil || got != f.Expected {
		t.Fatal("SQL NULL default", err)
	}
}
