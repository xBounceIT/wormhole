package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// Called with a real audited device session after migration16 conformance.
func testPostgresTreeSnapshot(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, root, leaf uuid.UUID) {
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
	}
	// Remove the deliberately invalid deep branch from the preceding graph tests.
	exec("DELETE FROM wormhole_data.nodes WHERE id<>$1::uuid AND id<>$2::uuid", []byte(root.String()), []byte(leaf.String()))
	migration, _ := deploy.TreeSnapshotMigration("testscope", testHintID)
	wrong, _ := deploy.TreeSnapshotMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("ROLLBACK")
	script("ALTER TABLE wormhole_data.nodes ADD COLUMN seal bytea")
	reject(migration, "42701")
	script("ROLLBACK")
	r := admin.ExecParams(ctx, "SELECT (schema_version=16 AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='wormhole_data' AND table_name='nodes' AND column_name='name'))::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("tree migration rollback", r.Err)
	}
	script("ALTER TABLE wormhole_data.nodes DROP COLUMN seal")
	script(migration)
	reject(migration, "55000")
	script("ROLLBACK")
	var capability []byte
	if err := native.capability.With(func(value []byte) error { capability = hex.AppendEncode(nil, value); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(capability)
	query := func(after, epoch, sequence, limit []byte) ([][][]byte, error) {
		return native.Query(ctx, `SELECT * FROM wormhole_api_v1.get_tree(pg_catalog.decode($1,'hex'),$2::uuid,$3::bigint,$4::bigint,$5::integer)`, [][]byte{capability, after, epoch, sequence, limit})
	}
	first := func() [][][]byte {
		t.Helper()
		rows, err := query(nil, nil, nil, []byte("1"))
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if _, err := query(nil, nil, nil, []byte("1")); err != ErrTreeMetadata {
		t.Fatal("unsealed metadata released", err)
	}
	signer := uuid.NewString()
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,1,'user-sign','pending',1)", []byte(signer))
	exec("UPDATE wormhole_data.nodes SET name='Node',boundary_id=$1::uuid,seal_suite=2,seal_signer_key_id=$2::uuid,seal_signer_key_version=1,seal=decode(repeat('11',64),'hex')", []byte(root.String()), []byte(signer))
	exec("UPDATE wormhole_data.nodes SET kind=1,protocol=0,host='example.test',username='',port=0,use_inline_password=false,sort_order=9223372036854775807 WHERE id=$1::uuid", []byte(leaf.String()))
	ids := []string{root.String(), leaf.String()}
	sort.Strings(ids)
	rows := first()
	validate := func(rows [][][]byte, wantID string, wantMore bool) {
		t.Helper()
		if len(rows) != 1 || len(rows[0]) != 15 || string(rows[0][0]) != testHintID || string(rows[0][1]) != testHintID || string(rows[0][4]) != "1" || string(rows[0][5]) != map[bool]string{true: "t", false: "f"}[wantMore] {
			t.Fatal("invalid page headers")
		}
		var node vaultstore.NodeMetadata
		decoder := json.NewDecoder(bytes.NewReader(rows[0][6]))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&node) != nil || node.Validate() != nil || node.ID != wantID {
			t.Fatal("invalid node projection")
		}
		// Compare complete field sets, including explicit NULLs, with the Go model.
		expected, _ := json.Marshal(node)
		var actualFields, expectedFields map[string]json.RawMessage
		json.Unmarshal(rows[0][6], &actualFields)
		json.Unmarshal(expected, &expectedFields)
		if len(actualFields) != len(expectedFields) {
			t.Fatal("metadata fields drifted")
		}
		for key := range expectedFields {
			if _, ok := actualFields[key]; !ok {
				t.Fatal("missing field", key)
			}
		}
		if node.ID == leaf.String() && (node.Port == nil || *node.Port != 0 || node.Username == nil || *node.Username != "" || node.UseInlinePassword == nil || *node.UseInlinePassword || node.SortOrder != 9223372036854775807) {
			t.Fatal("inheritance values or integer precision changed")
		}
		if string(rows[0][7]) != "31" || string(rows[0][8]) != root.String() || string(rows[0][10]) != "2" || string(rows[0][11]) != signer || len(rows[0][14]) != 130 {
			t.Fatal("seal/permission projection changed")
		}
	}
	validate(rows, ids[0], true)
	// Reserved encrypted metadata must never fall back to the clear projection.
	exec("UPDATE wormhole_data.nodes SET encrypted_metadata=decode(repeat('11',16),'hex'),metadata_key_id=$1::uuid,metadata_key_version=1,name_blind_index=decode(repeat('22',32),'hex')", []byte(signer))
	if _, err := native.TreePage(ctx, TreeCursor{}, 1); err == nil {
		t.Fatal("encrypted metadata fell back to clear projection")
	}
	exec("UPDATE wormhole_data.nodes SET encrypted_metadata=NULL,metadata_key_id=NULL,metadata_key_version=NULL,name_blind_index=NULL")
	rows = first()
	page, err := native.TreePage(ctx, TreeCursor{}, 1)
	if err != nil || page.Next == nil || len(page.Nodes) != 1 || page.Nodes[0].Metadata.ID != ids[0] {
		t.Fatal("native first page", err)
	}
	last, err := native.TreePage(ctx, *page.Next, 1)
	if err != nil || last.Next != nil || len(last.Nodes) != 1 || last.Nodes[0].Metadata.ID != ids[1] {
		t.Fatal("native continuation", err)
	}
	next, err := query([]byte(ids[0]), rows[0][2], rows[0][3], []byte("1"))
	if err != nil {
		t.Fatal(err)
	}
	validate(next, ids[1], false)
	empty, err := query([]byte(ids[1]), rows[0][2], rows[0][3], []byte("1"))
	if err != nil || len(empty) != 1 || len(empty[0]) != 15 || empty[0][6] != nil || string(empty[0][5]) != "f" {
		t.Fatal("invalid empty page", err)
	}
	for i := 7; i < 15; i++ {
		if empty[0][i] != nil {
			t.Fatal("empty page retained node data")
		}
	}
	// Any permission/group/hierarchy edit invalidates continuation, even if the
	// first page's selected node is unchanged. A fresh page can still be read.
	for _, change := range []string{
		"UPDATE wormhole_data.nodes SET sort_order=sort_order",
		"UPDATE wormhole_data.grants SET row_version=row_version+1",
		"UPDATE wormhole_data.group_members SET row_version=row_version+1",
		"UPDATE wormhole_data.groups SET row_version=row_version+1",
		"UPDATE wormhole_data.users SET row_version=row_version+1",
		"UPDATE wormhole_data.workspace_meta SET epoch=epoch+1",
	} {
		snapshot := first()
		script(change)
		if _, err := query([]byte(ids[0]), snapshot[0][2], snapshot[0][3], []byte("1")); err != ErrTreeSnapshotChanged {
			t.Fatal("stale continuation accepted", err)
		}
		first()
	}
	for _, args := range [][][]byte{
		{nil, nil, nil, nil}, {nil, nil, nil, []byte("0")}, {nil, nil, nil, []byte("33")}, {nil, []byte("1"), nil, []byte("1")},
		{[]byte(ids[0]), nil, []byte("1"), []byte("1")}, {[]byte(ids[0]), []byte("0"), []byte("1"), []byte("1")},
		{[]byte(ids[0]), []byte("1"), []byte("-1"), []byte("1")}, {[]byte(uuid.Nil.String()), []byte("1"), []byte("1"), []byte("1")},
	} {
		if _, err := query(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatal("malformed page accepted")
		}
	}
	// View is required independently of Use/Write/Reveal/Manage.
	exec("UPDATE wormhole_data.grants SET permissions=30")
	none, err := query(nil, nil, nil, []byte("32"))
	if err != nil || len(none) != 1 || none[0][6] != nil {
		t.Fatal("hidden node leaked", err)
	}
	exec("UPDATE wormhole_data.grants SET permissions=31")
	script("BEGIN; UPDATE wormhole_data.nodes SET sort_order=sort_order")
	if _, err := query(nil, nil, nil, []byte("1")); err != ErrChangeInProgress {
		t.Fatal("uncommitted page accepted", err)
	}
	script("ROLLBACK")
	first()
	// Existing enrollment roles retain no access to the new endpoint.
	r = admin.ExecParams(ctx, `SELECT (NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.get_tree(bytea,uuid,bigint,bigint,integer)','EXECUTE') AND NOT has_function_privilege('wh_testscope_user','wormhole_data.tree_changed()','EXECUTE') AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.get_tree(bytea,uuid,bigint,bigint,integer)'::regprocedure AND a.grantee=0))::text`, nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("tree API ACL", r.Err)
	}
	testPostgresNodeAuthor(t, ctx, admin, native, root, signer)
}
