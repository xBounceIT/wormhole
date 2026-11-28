package sharedpg

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func testPostgresResolutionChain(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
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
			t.Fatal("chain state", r.Err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatal("chain migration rejection", err)
		}
		script("ROLLBACK")
	}
	before, err := native.TreePage(ctx, TreeCursor{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	var leaf, root uuid.UUID
	for _, n := range before.Nodes {
		if n.Metadata.Kind == 1 {
			leaf = uuid.MustParse(n.Metadata.ID)
		} else if n.Metadata.ParentID == nil {
			root = uuid.MustParse(n.Metadata.ID)
		}
	}
	if leaf == uuid.Nil || root == uuid.Nil {
		t.Fatal("chain fixture missing")
	}
	oldAuthor, err := native.NodeAuthor(ctx, leaf, before.Epoch, before.ChangeSeq)
	if err != nil {
		t.Fatal(err)
	}
	migration, _ := deploy.ResolutionChainMigration("testscope", testHintID)
	wrong, _ := deploy.ResolutionChainMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.resolution_chain(uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=22 AND to_regprocedure('wormhole_data.node_metadata(wormhole_data.nodes)') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.resolution_chain(uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	after, err := native.TreePage(ctx, TreeCursor{}, 32)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("display projection changed", err)
	}
	author, err := native.NodeAuthor(ctx, leaf, after.Epoch, after.ChangeSeq)
	if err != nil || !reflect.DeepEqual(oldAuthor, author) {
		t.Fatal("public author projection changed", err)
	}
	for _, function := range []string{"node_metadata(wormhole_data.nodes)", "node_author_material(uuid,integer)", "resolution_chain(uuid,bigint,bigint)"} {
		check("SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_data." + function + "','EXECUTE') AND NOT has_function_privilege('wh_testscope_enroll','wormhole_data." + function + "','EXECUTE') AND NOT has_function_privilege('wh_testscope_admin','wormhole_data." + function + "','EXECUTE'))::text")
	}
	query := `SELECT depth::text,node_id::text,node::text,boundary_id::text,row_version::text,seal_suite::text,
 seal_signer_key_id::text,seal_signer_key_version::text,seal_capability_id::text,encode(seal,'hex'),
 author_id::text,signing_key_id::text,signing_key_version::text,state_sequence::text,encode(signed_state,'hex'),
 suite::text,encode(public_key,'hex'),cert_signer_key_id::text,cert_signer_key_version::text,cert_revision::text,encode(cert_signature,'hex')
 FROM wormhole_data.resolution_chain($1::uuid,$2::bigint,$3::bigint) ORDER BY depth`
	snapshot := func() [][]byte {
		t.Helper()
		r := admin.ExecParams(ctx, "SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 {
			t.Fatal(r.Err)
		}
		return r.Rows[0]
	}
	read := func(id uuid.UUID) *pgconn.Result {
		v := snapshot()
		return admin.ExecParams(ctx, query, [][]byte{[]byte(id.String()), v[0], v[1]}, nil, nil, nil).Read()
	}
	denied := func(id uuid.UUID, code string) {
		t.Helper()
		r := read(id)
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("chain rejection/partial result", r.Err)
		}
	}
	result := read(leaf)
	if result.Err != nil || len(result.Rows) != 2 {
		t.Fatal("complete chain", result.Err)
	}
	for i, row := range result.Rows {
		if len(row) != 21 || string(row[0]) != strconv.Itoa(i) {
			t.Fatal("chain ordering")
		}
		var metadata vaultstore.NodeMetadata
		if err := json.Unmarshal(row[2], &metadata); err != nil || metadata.Validate() != nil {
			t.Fatal("chain metadata", err)
		}
		found := false
		for _, n := range after.Nodes {
			if n.Metadata.ID == metadata.ID {
				found = reflect.DeepEqual(n.Metadata, metadata) && string(row[3]) == n.Boundary.String() && string(row[6]) == n.Seal.SignerKeyID
			}
		}
		if !found || string(row[10]) != author.State.UserID.String() || row[14] == nil {
			t.Fatal("chain projection drift")
		}
	}
	// All request components are mandatory and bounded before reading metadata.
	valid := snapshot()
	for _, args := range [][][]byte{
		{nil, valid[0], valid[1]}, {[]byte(uuid.Nil.String()), valid[0], valid[1]},
		{[]byte(leaf.String()), nil, valid[1]}, {[]byte(leaf.String()), []byte("0"), valid[1]},
		{[]byte(leaf.String()), valid[0], nil}, {[]byte(leaf.String()), valid[0], []byte("-1")},
	} {
		r := admin.ExecParams(ctx, query, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "22023" || len(r.Rows) != 0 {
			t.Fatal("invalid chain request", r.Err)
		}
	}
	denied(root, "WH016")
	denied(uuid.New(), "WH014")
	stale := snapshot()
	script("UPDATE wormhole_data.nodes SET name=name")
	r := admin.ExecParams(ctx, query, [][]byte{[]byte(leaf.String()), stale[0], stale[1]}, nil, nil, nil).Read()
	var pe *pgconn.PgError
	if !errors.As(r.Err, &pe) || pe.Code != "WH013" {
		t.Fatal("stale snapshot", r.Err)
	}
	for _, mode := range []string{"cycle", "unsealed", "encrypted", "author", "missing-cert", "bad-metadata", "api", "missing-state", "not-ready"} {
		script("BEGIN")
		switch mode {
		case "cycle":
			script("UPDATE wormhole_data.nodes SET parent_id='" + leaf.String() + "' WHERE id='" + root.String() + "'")
		case "unsealed":
			script("UPDATE wormhole_data.nodes SET boundary_id=NULL,seal_suite=NULL,seal_signer_key_id=NULL,seal_signer_key_version=NULL,seal_capability_id=NULL,seal=NULL WHERE id='" + root.String() + "'")
		case "encrypted":
			script("UPDATE wormhole_data.nodes SET encrypted_metadata=decode(repeat('00',16),'hex'),metadata_key_id=seal_signer_key_id,metadata_key_version=seal_signer_key_version,name_blind_index=decode(repeat('00',32),'hex') WHERE id='" + root.String() + "'")
		case "author":
			script("UPDATE wormhole_data.keys SET kind='org-sign' WHERE key_id='" + author.Key.ID.String() + "'")
		case "missing-cert":
			script("UPDATE wormhole_data.keys SET cert_signer_key_id=NULL,cert_signer_key_version=NULL,cert_signature=NULL,cert_revision=NULL WHERE key_id='" + author.Key.ID.String() + "'")
		case "bad-metadata":
			script("UPDATE wormhole_data.nodes SET protocol=999 WHERE id='" + root.String() + "'")
		case "missing-state":
			script("DELETE FROM wormhole_data.user_key_states")
		case "not-ready":
			script("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
		case "api":
			script("UPDATE wormhole_data.workspace_meta SET resolver_version=2")
		}
		if mode == "missing-cert" {
			result := read(leaf)
			if result.Err != nil || len(result.Rows) != 2 {
				t.Fatal("missing certificate state", result.Err)
			}
			for _, row := range result.Rows {
				if row[14] == nil {
					t.Fatal("discarded signed state")
				}
				for _, v := range row[15:] {
					if v != nil {
						t.Fatal("partial certificate")
					}
				}
			}
		} else {
			denied(leaf, map[string]string{"cycle": "WH016", "unsealed": "WH014", "encrypted": "0A000", "author": "WH010", "bad-metadata": "WH016", "api": "WH004", "missing-state": "WH010", "not-ready": "WH002"}[mode])
		}
		script("ROLLBACK")
	}
	// Build complete chains at and above the bound using fixture metadata only.
	for _, depth := range []int{128, 129} {
		script("BEGIN")
		script("DO $test$ DECLARE parent uuid:='" + root.String() + "'; fresh uuid; i integer; BEGIN FOR i IN 1.." + strconv.Itoa(depth-2) + " LOOP fresh:=gen_random_uuid(); INSERT INTO wormhole_data.nodes SELECT (jsonb_populate_record(NULL::wormhole_data.nodes,to_jsonb(n)||jsonb_build_object('id',fresh,'parent_id',parent))).* FROM wormhole_data.nodes n WHERE n.id='" + root.String() + "'; parent:=fresh; END LOOP; UPDATE wormhole_data.nodes SET parent_id=parent WHERE id='" + leaf.String() + "'; END $test$")
		if depth == 128 {
			result := read(leaf)
			if result.Err != nil || len(result.Rows) != 128 {
				t.Fatal("max chain depth", result.Err)
			}
			// Exercise JSON escaping overhead using individually valid field sizes.
			script("UPDATE wormhole_data.user_key_states SET signed_state=decode(repeat('00',4096),'hex')")
			script("UPDATE wormhole_data.nodes SET host=repeat(chr(92),16384),http_path=repeat(chr(92),16384)")
			denied(leaf, "54000")
		} else {
			denied(leaf, "WH016")
		}
		script("ROLLBACK")
	}
}
