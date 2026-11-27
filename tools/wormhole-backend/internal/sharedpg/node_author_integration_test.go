package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresNodeAuthor(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, node uuid.UUID, signer string) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	reject := func(sql, state string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != state {
			t.Fatalf("expected %s: %v", state, err)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.NodeAuthorMigration("testscope", testHintID)
	wrong, _ := deploy.NodeAuthorMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	r := admin.ExecParams(ctx, "SELECT (schema_version=17 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='wormhole_data.keys'::regclass AND tgname='tree_changed'))::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("migration rollback", r.Err)
	}
	script("DROP FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	var capability []byte
	if err := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	page := func() *UnverifiedTreePage {
		t.Helper()
		p, err := native.TreePage(ctx, TreeCursor{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	query := func(id uuid.UUID, p *UnverifiedTreePage) ([][][]byte, error) {
		return native.Query(ctx, "SELECT * FROM wormhole_api_v1.node_author(decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint)", [][]byte{capability, []byte(id.String()), []byte(strconv.FormatUint(p.Epoch, 10)), []byte(strconv.FormatUint(p.ChangeSeq, 10))})
	}
	if _, err := query(node, page()); err != ErrAccountRevision {
		t.Fatal("ownerless key", err)
	}
	exec("UPDATE wormhole_data.keys SET owner_id=$1::uuid WHERE key_id=$2::uuid", []byte(testHintID), []byte(signer))
	exec("INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,1,decode('01','hex')) ON CONFLICT(user_id) DO UPDATE SET state_sequence=1,signed_state=decode('01','hex')", []byte(testHintID))
	snapshot := page()
	rows, err := query(node, snapshot)
	if err != nil || len(rows) != 1 || len(rows[0]) != 15 || string(rows[0][2]) != testHintID || string(rows[0][5]) != signer || rows[0][9] != nil {
		t.Fatal("public state without certificate", err)
	}
	for _, value := range rows[0][9:] {
		if value != nil {
			t.Fatal("partial certificate")
		}
	}
	// Current state remains available even with retired keys; clients must verify
	// its signature and preserve a revocation sequence, not trust DB status.
	exec("UPDATE wormhole_data.keys SET status='retired',public_key=decode(repeat('11',32),'hex'),cert_signer_key_id=$1::uuid,cert_signer_key_version=1,cert_revision=2,cert_signature=decode(repeat('22',64),'hex') WHERE key_id=$1::uuid", []byte(signer))
	if _, err := query(node, snapshot); err != ErrTreeSnapshotChanged {
		t.Fatal("key change kept snapshot", err)
	}
	rows, err = query(node, page())
	if err != nil || string(rows[0][9]) != "1" || string(rows[0][13]) != "2" {
		t.Fatal("certificate projection", err)
	}
	snapshot = page()
	script("UPDATE wormhole_data.user_key_states SET state_sequence=state_sequence+1")
	if _, err := query(node, snapshot); err != ErrTreeSnapshotChanged {
		t.Fatal("state change kept snapshot", err)
	}
	if _, err := query(uuid.New(), page()); err != ErrTreeMetadata {
		t.Fatal("missing node", err)
	}
	script("UPDATE wormhole_data.grants SET permissions=30")
	if _, err := query(node, page()); err != ErrTreeMetadata {
		t.Fatal("hidden author exposed", err)
	}
	script("UPDATE wormhole_data.grants SET permissions=31")
	snapshot = page()
	script("BEGIN; UPDATE wormhole_data.user_key_states SET state_sequence=state_sequence")
	if _, err := query(node, snapshot); err != ErrChangeInProgress {
		t.Fatal("uncommitted state accepted", err)
	}
	script("ROLLBACK")
	if _, err := query(node, page()); err != nil {
		t.Fatal(err)
	}
	r = admin.ExecParams(ctx, "SELECT (NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.node_author(bytea,uuid,bigint,bigint)'::regprocedure AND a.grantee=0))::text", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("author ACL", r.Err)
	}
	stateRows, state, _ := unlockStateFixture(t)
	raw, _ := hex.DecodeString(string(stateRows[0][0]))
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,1,'org-sign','pending',1) ON CONFLICT DO NOTHING", []byte(state.Signer.ID.String()))
	exec("UPDATE wormhole_data.keys SET cert_signer_key_id=$1::uuid WHERE key_id=$2::uuid", []byte(state.Signer.ID.String()), []byte(signer))
	exec("UPDATE wormhole_data.user_key_states SET state_sequence=4,signed_state=$1", raw)
	snapshot = page()
	material, err := native.NodeAuthor(ctx, node, snapshot.Epoch, snapshot.ChangeSeq)
	if err != nil || material.Certificate == nil || material.State.Sequence != 4 || material.Key.ID.String() != signer {
		t.Fatal("native author material", err)
	}
	script("UPDATE wormhole_data.user_key_states SET state_sequence=state_sequence")
	if _, err := native.NodeAuthor(ctx, node, snapshot.Epoch, snapshot.ChangeSeq); err != ErrTreeSnapshotChanged {
		t.Fatal("native stale snapshot", err)
	}
	testPostgresCatalogChanges(t, ctx, admin, native, node)
	testPostgresUseIntent(t, ctx, admin, native, node)
}
