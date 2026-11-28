package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func testPostgresConnectionPlanMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
			t.Fatal("plan migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.ConnectionPlanMigration("testscope", testHintID)
	wrong, _ := deploy.ConnectionPlanMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.connection_plan(bytea,uuid) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	r := admin.ExecParams(ctx, "SELECT (schema_version=36)::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("plan migration rollback", r.Err)
	}
	script("DROP FUNCTION wormhole_api_v1.connection_plan(bytea,uuid)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "enroll"} {
		r := admin.ExecParams(ctx, "SELECT has_function_privilege('wh_testscope_"+role+"','wormhole_api_v1.connection_plan(bytea,uuid)','EXECUTE')::text", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != map[string]string{"user": "true", "enroll": "false"}[role] {
			t.Fatal("plan API grant", r.Err)
		}
	}
}

func testPostgresSerialConnectionPlan(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, f connectionFixture) {
	t.Helper()
	protocol, baud, parity, host := 5, 19200, 2, "COM42"
	id := uuid.New()
	node := vaultstore.NodeMetadata{ID: id.String(), Name: "Rack console", Kind: 1, Protocol: &protocol, Host: &host, SerialBaudRate: &baud, SerialParity: &parity}
	leaf := f.records.Chain[0]
	seal, err := sharedcatalog.SignNode(f.s.WorkspaceID, leaf.Node.Boundary, node, 1, leaf.Author.Key, f.key)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, params ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, params, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	exec(`INSERT INTO wormhole_data.nodes(id, kind, name, sort_order, protocol, host, serial_baud_rate, serial_parity,
  boundary_id, row_version, seal_suite, seal_signer_key_id, seal_signer_key_version, seal)
 VALUES($1::uuid,1,$2,0,5,$3,19200,2,$4::uuid,1,2,$5::uuid,$6::integer,pg_catalog.decode($7,'hex'))`,
		[]byte(node.ID), []byte(node.Name), []byte(host), []byte(leaf.Node.Boundary.String()),
		[]byte(seal.SignerKeyID), []byte(strconv.FormatUint(uint64(seal.SignerKeyVersion), 10)), hex.AppendEncode(nil, seal.Signature))
	exec(`INSERT INTO wormhole_data.grants(node_id,user_id,permissions) VALUES($1::uuid,$2::uuid,3)`, []byte(node.ID), []byte(f.s.UserID.String()))
	defer exec(`DELETE FROM wormhole_data.nodes WHERE id=$1::uuid`, []byte(node.ID))
	defer exec(`DELETE FROM wormhole_data.grants WHERE node_id=$1::uuid`, []byte(node.ID))
	input, err := native.ConnectionPlan(ctx, id)
	if err != nil {
		t.Fatal("PostgreSQL serial plan unavailable", err)
	}
	_, resolved, err := f.s.VerifyConnectionPlan(ctx, id, input)
	want := vault.DefaultSerialSettings()
	want.BaudRate, want.Parity = baud, parity
	if err != nil || resolved.Plan.Host != host || resolved.Plan.Protocol != protocol || resolved.Plan.Port != 0 || resolved.SerialSettings != want {
		t.Fatal("PostgreSQL serial plan differed from the signed metadata", resolved, err)
	}
	if mask, err := native.NodePermissions(ctx, id); err != nil || mask != permissions.View|permissions.Use {
		t.Fatal("PostgreSQL did not grant serial Use", mask, err)
	}
	exec(`UPDATE wormhole_data.grants SET permissions=1 WHERE node_id=$1::uuid`, []byte(node.ID))
	if mask, err := native.NodePermissions(ctx, id); err != nil || mask != permissions.View {
		t.Fatal("PostgreSQL did not revoke serial Use", mask, err)
	}
}

func testPostgresConnectionPlan(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, f connectionFixture, g *UnverifiedCredentialRelease) {
	t.Helper()
	exec := func(sql string, p ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, p, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	counts := func() []byte {
		r := exec("SELECT jsonb_build_array((SELECT count(*) FROM wormhole_data.audit_log WHERE action='begin_use'),(SELECT count(*) FROM wormhole_data.use_tickets))::text")
		return bytes.Clone(r.Rows[0][0])
	}
	before := counts()
	read := func() {
		t.Helper()
		input, e := native.ConnectionPlan(ctx, f.node())
		if e != nil {
			t.Fatal("real metadata plan", e)
		}
		next, p, e := f.s.VerifyConnectionPlan(ctx, f.node(), input)
		if e != nil || p.Plan != g.metadata.plan || len(p.Revision) != 64 || f.s.ValidateAdvance(next) != nil {
			t.Fatal("real verified plan", e)
		}
	}
	read()
	testPostgresRuntimeState(t, ctx, admin, native, f)
	if !bytes.Equal(before, counts()) {
		t.Fatal("planning issued or consumed a release ticket")
	}
	// Signed metadata planning must remain independent of encrypted storage.
	// Remove only this fixture's ciphertext/copies, then restore exact rows.
	ids := []string{}
	for _, copy := range g.roots {
		ids = append(ids, copy.Binding.Key.ID.String())
	}
	owners := []string{}
	for _, a := range g.accounts {
		owners = append(owners, a.values[0].Binding.OwnerID.String())
		for _, copy := range a.copies {
			ids = append(ids, copy.Binding.Key.ID.String())
		}
	}
	keyArray := []byte("{" + strings.Join(ids, ",") + "}")
	ownerArray := []byte("{" + strings.Join(owners, ",") + "}")
	copies := exec("SELECT to_jsonb(c)::text FROM wormhole_data.key_copies c WHERE c.key_id=ANY($1::uuid[])", keyArray).Rows
	values := exec("SELECT to_jsonb(v)::text FROM wormhole_data.secret_values v WHERE v.owner_id=ANY($1::uuid[])", ownerArray).Rows
	script("BEGIN")
	exec("DELETE FROM wormhole_data.key_copies WHERE key_id=ANY($1::uuid[])", keyArray)
	exec("DELETE FROM wormhole_data.secret_values WHERE owner_id=ANY($1::uuid[])", ownerArray)
	script("COMMIT")
	read()
	for _, pair := range []struct {
		table string
		rows  [][][]byte
	}{{"key_copies", copies}, {"secret_values", values}} {
		for _, row := range pair.rows {
			exec("INSERT INTO wormhole_data."+pair.table+" SELECT * FROM jsonb_populate_record(NULL::wormhole_data."+pair.table+",$1::jsonb)", row[0])
		}
	}
	if !bytes.Equal(before, counts()) {
		t.Fatal("metadata requested a secret release")
	}
	// A pre-existing committed ticket survives metadata reads unchanged.
	intent, e := native.BeginUse(ctx, f.node(), "ui")
	if e != nil {
		t.Fatal(e)
	}
	afterBegin := counts()
	read()
	read()
	if !bytes.Equal(afterBegin, counts()) {
		t.Fatal("plan changed a use ticket")
	}
	if _, e := native.FetchSecret(ctx, *intent); e != nil {
		t.Fatal("plan spent pending ticket", e)
	}
	var capability []byte
	if e := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); e != nil {
		t.Fatal(e)
	}
	defer vault.Wipe(capability)
	for _, account := range g.accounts {
		exec("UPDATE wormhole_data.boundary_grants SET permissions=8 WHERE boundary_id=$1::uuid", []byte(account.boundary.String()))
		rows, e := native.Query(ctx, connectionPlanSQL, [][]byte{capability, []byte(f.node().String())})
		wipeQueryRows(rows)
		if e != ErrQuery {
			t.Fatal("account Use required for plan", e)
		}
		exec("UPDATE wormhole_data.boundary_grants SET permissions=2 WHERE boundary_id=$1::uuid", []byte(account.boundary.String()))
	}
	// Inspect actual wire keys, not a synthetic serialization of the native type.
	rows, e := native.Query(ctx, connectionPlanSQL, [][]byte{capability, []byte(f.node().String())})
	if e != nil {
		t.Fatal(e)
	}
	defer wipeQueryRows(rows)
	var wire map[string]json.RawMessage
	if len(rows) != 1 || len(rows[0]) != 7 || json.Unmarshal(rows[0][6], &wire) != nil || len(wire) != 4 || wire["metadata"] == nil || wire["account"] == nil || wire["profile"] == nil || wire["formatVersion"] == nil {
		t.Fatal("plan exposed unexpected material")
	}
	for _, a := range g.accounts {
		for _, v := range a.values {
			cipher, _ := vault.EncodeSharedEnvelope(v.Envelope)
			if bytes.Contains(rows[0][6], hex.AppendEncode(nil, cipher)) {
				t.Fatal("plan returned ciphertext")
			}
		}
	}
	script("BEGIN; SET LOCAL SESSION AUTHORIZATION \"wh_testscope_d_" + native.admission.DeviceID.String() + "\"")
	r := admin.ExecParams(ctx, connectionPlanSQL, [][]byte{capability, nil}, nil, nil, nil).Read()
	var pe *pgconn.PgError
	if !errors.As(r.Err, &pe) || pe.Code != "22023" || len(r.Rows) != 0 {
		t.Fatal("null plan", r.Err)
	}
	script("ROLLBACK")
}
