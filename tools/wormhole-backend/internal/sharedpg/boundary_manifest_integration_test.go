package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const boundaryProjectionTestSQL = `SELECT workspace_id::text,boundary_id::text,epoch::text,change_seq::text,version::text,encode(body,'hex'),signer_key_id::text,signer_key_version::text,encode(signature,'hex') FROM wormhole_data.boundary_manifest($1::uuid,$2::bigint,$3::bigint)`

func testPostgresBoundaryManifest(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, e := admin.Exec(ctx, sql).ReadAll(); e != nil {
			t.Fatal(e)
		}
	}
	exec := func(sql string, args ...[]byte) *pgconn.Result {
		t.Helper()
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return r
	}
	check := func(sql string) {
		t.Helper()
		r := exec(sql)
		if len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("manifest state")
		}
	}
	rejectMigration := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("manifest migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.BoundaryManifestsMigration("testscope", testHintID)
	wrong, _ := deploy.BoundaryManifestsMigration("testscope", uuid.NewString())
	rejectMigration(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.boundary_manifest(uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	rejectMigration(migration, "42723")
	check("SELECT (schema_version=29 AND to_regclass('wormhole_data.boundary_manifests') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.boundary_manifest(uuid,bigint,bigint)")
	script(migration)
	rejectMigration(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data.boundary_manifests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.boundary_manifest(uuid,bigint,bigint)','EXECUTE'))::text")
	}
	_, _, trust, m, org := boundaryTrustFixture(t)
	script("BEGIN")
	defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite,public_key) VALUES($1::uuid,$2::int,'org-sign','pending',1,decode($3,'hex'))", []byte(m.Signer.ID.String()), []byte(strconv.Itoa(int(m.Signer.Version))), hex.AppendEncode(nil, trust.PublicKey))
	exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(m.BoundaryID.String()))
	raw, e := vault.EncodeBoundaryManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	exec("INSERT INTO wormhole_data.boundary_manifests(boundary_id,version,body,signer_key_id,signer_key_version,signature) VALUES($1::uuid,$2::bigint,decode($3,'hex'),$4::uuid,$5::int,decode($6,'hex'))", []byte(m.BoundaryID.String()), []byte(strconv.FormatUint(m.Revision, 10)), hex.AppendEncode(nil, raw), []byte(m.Signer.ID.String()), []byte(strconv.Itoa(int(m.Signer.Version))), hex.AppendEncode(nil, m.Signature))
	args := func() ([][]byte, uint64, uint64) {
		t.Helper()
		r := exec("SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta")
		epoch, e1 := strconv.ParseUint(string(r.Rows[0][0]), 10, 64)
		seq, e2 := strconv.ParseUint(string(r.Rows[0][1]), 10, 64)
		if e1 != nil || e2 != nil {
			t.Fatal("snapshot")
		}
		return [][]byte{[]byte(m.BoundaryID.String()), r.Rows[0][0], r.Rows[0][1]}, epoch, seq
	}
	read := func() (*vault.BoundaryManifest, error) {
		t.Helper()
		a, epoch, seq := args()
		r := exec(boundaryProjectionTestSQL, a...)
		return parseBoundaryProjection(r.Rows, native.admission, m.BoundaryID, epoch, seq)
	}
	got, e := read()
	if e != nil || !reflect.DeepEqual(*got, m) {
		t.Fatal("SQL manifest drift", e)
	}
	accepted, e := trust.AdvanceBoundary(m.BoundaryID, *got)
	if e != nil || len(accepted.Catalog) != 3 {
		t.Fatal("SQL manifest authentication", e)
	}
	deny := func(sql, code string, a ...[]byte) {
		t.Helper()
		script("SAVEPOINT bad_manifest")
		r := admin.ExecParams(ctx, sql, a, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("manifest rejection", code, r.Err)
		}
		script("ROLLBACK TO SAVEPOINT bad_manifest; RELEASE SAVEPOINT bad_manifest")
	}
	for _, sql := range []string{"UPDATE wormhole_data.boundary_manifests SET version=0", "UPDATE wormhole_data.boundary_manifests SET body=decode('','hex')", "UPDATE wormhole_data.boundary_manifests SET body=decode(repeat('00',8193),'hex')", "UPDATE wormhole_data.boundary_manifests SET signature=decode(repeat('00',63),'hex')"} {
		deny(sql, "23514")
	}
	deny("INSERT INTO wormhole_data.boundary_manifests SELECT * FROM wormhole_data.boundary_manifests", "23505")
	for _, column := range []string{"boundary_id", "signer_key_id"} {
		deny("UPDATE wormhole_data.boundary_manifests SET "+column+"=$1::uuid", "23503", []byte(uuid.NewString()))
	}
	base, _, _ := args()
	for col := range base {
		invalid := append([][]byte(nil), base...)
		invalid[col] = nil
		deny(boundaryProjectionTestSQL, "22023", invalid...)
	}
	for _, bad := range []struct {
		col     int
		v, code string
	}{{0, uuid.Nil.String(), "22023"}, {0, uuid.NewString(), "WH010"}, {1, "0", "22023"}, {2, "-1", "22023"}, {2, "0", "WH013"}} {
		a := append([][]byte(nil), base...)
		a[bad.col] = []byte(bad.v)
		deny(boundaryProjectionTestSQL, bad.code, a...)
	}
	for _, mode := range []string{"header-version", "body-corrupt", "signature", "inactive", "root-rollback", "provisioning", "version"} {
		script("SAVEPOINT manifest_mutation")
		switch mode {
		case "header-version":
			exec("UPDATE wormhole_data.boundary_manifests SET version=version+1")
		case "body-corrupt":
			exec("UPDATE wormhole_data.boundary_manifests SET body=decode('00','hex')")
		case "signature":
			exec("UPDATE wormhole_data.boundary_manifests SET signature=decode(repeat('00',64),'hex')")
		case "inactive", "root-rollback":
			changed := m
			changed.Revision++
			if mode == "inactive" {
				changed.Active = false
				exec("UPDATE wormhole_data.boundaries SET deleted=true")
			} else {
				changed.View.Key.Version--
			}
			changed, e = vault.SignBoundaryManifest(changed, org)
			if e != nil {
				t.Fatal(e)
			}
			body, e := vault.EncodeBoundaryManifest(changed)
			if e != nil {
				t.Fatal(e)
			}
			exec("UPDATE wormhole_data.boundary_manifests SET version=$1::bigint,body=decode($2,'hex'),signature=decode($3,'hex')", []byte(strconv.FormatUint(changed.Revision, 10)), hex.AppendEncode(nil, body), hex.AppendEncode(nil, changed.Signature))
		case "provisioning":
			exec("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
		case "version":
			exec("UPDATE wormhole_data.workspace_meta SET min_api=2,max_api=2")
		}
		if code := map[string]string{"provisioning": "WH002", "version": "WH004"}[mode]; code != "" {
			a, _, _ := args()
			deny(boundaryProjectionTestSQL, code, a...)
		} else {
			projected, e := read()
			switch mode {
			case "header-version", "body-corrupt", "signature":
				if e != ErrAdmissionResponse {
					t.Fatal("corrupt projection", e)
				}
			case "inactive", "root-rollback":
				if e != nil {
					t.Fatal(e)
				}
				next, e := accepted.AdvanceBoundary(m.BoundaryID, *projected)
				want := vault.ErrPolicy
				if mode == "root-rollback" {
					want = vault.ErrRollback
				}
				if e != want || next.Catalog["boundary/"+m.BoundaryID.String()].Revision != m.Revision+1 || accepted.ValidateAdvance(next) != nil {
					t.Fatal("manifest observation lost", e)
				}
			}
		}
		script("ROLLBACK TO SAVEPOINT manifest_mutation; RELEASE SAVEPOINT manifest_mutation")
	}
	script("ROLLBACK")
	for _, sql := range []string{"DELETE FROM wormhole_data.boundary_manifests", "TRUNCATE wormhole_data.boundary_manifests"} {
		script("BEGIN")
		script(sql)
		if _, e := native.TreePage(ctx, TreeCursor{}, 32); e != ErrChangeInProgress {
			t.Fatal("manifest writer did not protect snapshot", e)
		}
		script("ROLLBACK")
	}
}
