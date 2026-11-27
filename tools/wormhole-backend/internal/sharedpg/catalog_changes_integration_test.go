package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func testPostgresCatalogChanges(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, root uuid.UUID) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
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
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("change state", r.Err)
		}
	}
	migration, _ := deploy.CatalogChangesMigration("testscope", testHintID)
	wrong, _ := deploy.CatalogChangesMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_api_v1.get_changes_since(bytea,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=18 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='wormhole_data' AND c.relname='catalog_changes'))::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_api_v1.get_changes_since(bytea,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	read := func(epoch, seq uint64) *CatalogChanges {
		t.Helper()
		r, err := native.ChangesSince(ctx, epoch, seq)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	initial := read(0, 0)
	if !initial.Reset || len(initial.Nodes) != 0 {
		t.Fatal("initial reset")
	}
	unchanged := read(initial.Epoch, initial.ChangeSeq)
	if unchanged.Reset || len(unchanged.Nodes) != 0 {
		t.Fatal("unchanged")
	}
	script("UPDATE wormhole_data.nodes SET name=name WHERE id='" + root.String() + "'")
	changed := read(initial.Epoch, initial.ChangeSeq)
	if changed.Reset || len(changed.Nodes) != 1 || changed.Nodes[0] != root {
		t.Fatal("visible incremental node", changed)
	}
	// Repeated updates coalesce, and rollback restores both sequence and journal.
	script("UPDATE wormhole_data.nodes SET name=name WHERE id='" + root.String() + "'")
	if r := read(initial.Epoch, initial.ChangeSeq); len(r.Nodes) != 1 || r.Reset {
		t.Fatal("coalescing")
	}
	current := read(0, 0)
	script("BEGIN; UPDATE wormhole_data.nodes SET name=name")
	if _, err := native.ChangesSince(ctx, current.Epoch, current.ChangeSeq); err != ErrChangeInProgress {
		t.Fatal("dirty changes", err)
	}
	script("ROLLBACK")
	if r := read(current.Epoch, current.ChangeSeq); r.ChangeSeq != current.ChangeSeq || len(r.Nodes) != 0 {
		t.Fatal("rollback")
	}
	// Permission revocation returns no removed IDs, then hidden updates remain hidden.
	script("UPDATE wormhole_data.grants SET permissions=30")
	revoked := read(current.Epoch, current.ChangeSeq)
	if !revoked.Reset || len(revoked.Nodes) != 0 {
		t.Fatal("revocation reset")
	}
	script("UPDATE wormhole_data.nodes SET name=name")
	if r := read(revoked.Epoch, revoked.ChangeSeq); r.Reset || len(r.Nodes) != 0 {
		t.Fatal("hidden node leaked")
	}
	script("UPDATE wormhole_data.grants SET permissions=31")
	current = read(0, 0)
	script("UPDATE wormhole_data.nodes SET owner_user_id='" + testHintID + "' WHERE id='" + root.String() + "'")
	if r := read(current.Epoch, current.ChangeSeq); !r.Reset || len(r.Nodes) != 0 {
		t.Fatal("structural reset")
	}
	current = read(0, 0)
	script("INSERT INTO wormhole_data.nodes(id,parent_id,kind,name) SELECT gen_random_uuid(),'" + root.String() + "',1,'catalog-change-fixture' FROM generate_series(1,33)")
	if r := read(current.Epoch, current.ChangeSeq); !r.Reset || len(r.Nodes) != 0 {
		t.Fatal("response bound")
	}
	current = read(0, 0)
	script("INSERT INTO wormhole_data.nodes(id,parent_id,kind,name) SELECT gen_random_uuid(),'" + root.String() + "',1,'catalog-change-fixture' FROM generate_series(1,4097)")
	check("SELECT (count(*)=0)::text FROM wormhole_data.catalog_changes")
	if r := read(current.Epoch, current.ChangeSeq); !r.Reset {
		t.Fatal("journal bound")
	}
	current = read(0, 0)
	script("UPDATE wormhole_data.keys SET status=status")
	if r := read(current.Epoch, current.ChangeSeq); !r.Reset {
		t.Fatal("key reset")
	}
	if _, err := native.ChangesSince(ctx, current.Epoch+1, 0); err != ErrTreeSnapshotChanged {
		t.Fatal("future epoch", err)
	}
	if _, err := native.ChangesSince(ctx, current.Epoch, current.ChangeSeq+100); err != ErrTreeSnapshotChanged {
		t.Fatal("future sequence", err)
	}
	current = read(0, 0)
	script("DELETE FROM wormhole_data.nodes WHERE name='catalog-change-fixture'")
	if r := read(current.Epoch, current.ChangeSeq); !r.Reset || len(r.Nodes) != 0 {
		t.Fatal("deletion exposed tombstones")
	}
	var capability []byte
	if err := native.capability.With(func(b []byte) error { capability = hex.AppendEncode(nil, b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	for _, cursor := range [][2][]byte{{nil, []byte("0")}, {[]byte("0"), nil}, {[]byte("-1"), []byte("0")}, {[]byte("1"), []byte("-1")}, {[]byte("0"), []byte("1")}} {
		rows, err := native.Query(ctx, "SELECT * FROM wormhole_api_v1.get_changes_since(decode($1,'hex'),$2::bigint,$3::bigint)", [][]byte{capability, cursor[0], cursor[1]})
		wipeQueryRows(rows)
		if err == nil {
			t.Fatal("invalid SQL cursor accepted")
		}
	}
	check("SELECT (NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.get_changes_since(bytea,bigint,bigint)','EXECUTE') AND NOT has_table_privilege('wh_testscope_user','wormhole_data.catalog_changes','SELECT') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.get_changes_since(bytea,bigint,bigint)'::regprocedure AND a.grantee=0))::text")
}
