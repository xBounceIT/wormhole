package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresRuntimeStateMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
			t.Fatal("runtime migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.RuntimeStateMigration("testscope", testHintID)
	wrong, _ := deploy.RuntimeStateMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.runtime_state(bytea) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	r := admin.ExecParams(ctx, "SELECT (schema_version=37)::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("runtime migration rollback", r.Err)
	}
	script("DROP FUNCTION wormhole_api_v1.runtime_state(bytea)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "enroll"} {
		r := admin.ExecParams(ctx, "SELECT has_function_privilege('wh_testscope_"+role+"','wormhole_api_v1.runtime_state(bytea)','EXECUTE')::text", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != map[string]string{"user": "true", "enroll": "false"}[role] {
			t.Fatal("runtime API ACL", r.Err)
		}
	}
}

func testPostgresRuntimeState(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, f connectionFixture) {
	t.Helper()
	exec := func(sql string, args ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	counts := func() []byte {
		r := exec("SELECT jsonb_build_array((SELECT count(*) FROM wormhole_data.audit_log WHERE action='begin_use'),(SELECT count(*) FROM wormhole_data.use_tickets))::text")
		return bytes.Clone(r.Rows[0][0])
	}
	before := counts()
	read := func() {
		t.Helper()
		input, e := native.RuntimeState(ctx)
		if e != nil {
			t.Fatal("real runtime state", e)
		}
		next, e := f.s.VerifyRuntimeState(ctx, input)
		if e != nil || next.Revision == 0 {
			t.Fatal("verified runtime state", e)
		}
	}
	read()
	if !bytes.Equal(before, counts()) {
		t.Fatal("runtime state issued or consumed a ticket")
	}
	var capability []byte
	if e := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(capability)
	rows, e := native.Query(ctx, runtimeStateSQL, [][]byte{capability})
	if e != nil {
		t.Fatal(e)
	}
	defer wipeQueryRows(rows)
	var wire map[string]json.RawMessage
	if len(rows) != 1 || len(rows[0]) != 7 || string(rows[0][6]) != "true" || json.Unmarshal(rows[0][5], &wire) != nil || len(wire) != 3 || wire["profile"] == nil || wire["account"] == nil || wire["formatVersion"] == nil {
		t.Fatal("unexpected runtime state projection")
	}
	// Even with a valid capability, a bare administrator is not its device.
	r := admin.ExecParams(ctx, runtimeStateSQL, [][]byte{capability}, nil, nil, nil).Read()
	var pe *pgconn.PgError
	if !errors.As(r.Err, &pe) || pe.Code != "WH001" || len(r.Rows) != 0 {
		t.Fatal("bare administrator admitted", r.Err)
	}
	// Node/account Use permissions are irrelevant to this public own-state API.
	exec("UPDATE wormhole_data.boundary_grants SET permissions=1 WHERE boundary_id=ANY($1::uuid[])", []byte("{"+f.records.Credential.Credential.Boundary.String()+"}"))
	read()
	exec("UPDATE wormhole_data.boundary_grants SET permissions=2 WHERE boundary_id=ANY($1::uuid[])", []byte("{"+f.records.Credential.Credential.Boundary.String()+"}"))
	denied := func(code string) {
		t.Helper()
		// Probe the SQL gate directly so this fixture can restore the row and
		// continue. The typed RuntimeState API retires failed connections.
		owned, opCtx, release, e := native.lease(ctx, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		r := owned.(*pgconn.PgConn).ExecParams(opCtx, runtimeStateSQL, [][]byte{capability}, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("unavailable account returned runtime state", r.Err)
		}
	}
	user, device := []byte(native.admission.UserID.String()), []byte(native.admission.DeviceID.String())
	exec("UPDATE wormhole_data.users SET disabled=true WHERE id=$1::uuid", user)
	denied("WH001")
	exec("UPDATE wormhole_data.users SET disabled=false WHERE id=$1::uuid", user)
	read()
	exec("UPDATE wormhole_data.devices SET status='revoked' WHERE id=$1::uuid", device)
	denied("WH001")
	exec("UPDATE wormhole_data.devices SET status='active' WHERE id=$1::uuid", device)
	read()
	state := exec("DELETE FROM wormhole_data.user_key_states WHERE user_id=$1::uuid RETURNING state_sequence::text,encode(signed_state,'hex')", user)
	if len(state.Rows) != 1 {
		t.Fatal("missing own state fixture")
	}
	denied("WH010")
	exec("INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,$2::bigint,decode($3,'hex'))", user, state.Rows[0][0], state.Rows[0][1])
	read()
	if !bytes.Equal(before, counts()) {
		t.Fatal("runtime error path changed release audit/tickets")
	}
}
