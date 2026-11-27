package sharedpg

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func testPostgresCredentialCatalog(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
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
			t.Fatal("credential catalog rejection", err)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("credential catalog state", r.Err)
		}
	}
	migration, _ := deploy.CredentialCatalogMigration("testscope", testHintID)
	wrong, _ := deploy.CredentialCatalogMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE TABLE wormhole_data.user_node_overrides(collision integer)")
	reject(migration, "42P07")
	check("SELECT (schema_version=24 AND to_regclass('wormhole_data.credential_profiles') IS NULL AND to_regprocedure('wormhole_data.credential_fields_valid(jsonb,text,text,boolean)') IS NULL)::text FROM wormhole_data.workspace_meta")
	script("DROP TABLE wormhole_data.user_node_overrides")
	script(migration)
	reject(migration, "55000")
	tables := []string{"credential_profiles", "credential_slots", "credential_slot_values", "user_node_overrides"}
	for _, table := range tables {
		for _, role := range []string{"user", "admin", "enroll"} {
			check("SELECT (NOT has_table_privilege('wh_testscope_" + role + "','wormhole_data." + table + "','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))::text")
		}
	}
	check("SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_data.credential_fields_valid(jsonb,text,text,boolean)','EXECUTE'))::text")
	material := admin.ExecParams(ctx, "SELECT key_id::text,key_version::text FROM wormhole_data.keys WHERE kind='user-sign' ORDER BY key_version DESC LIMIT 1", nil, nil, nil, nil).Read()
	if material.Err != nil || len(material.Rows) != 1 {
		t.Fatal("catalog signer fixture", material.Err)
	}
	signer, err := uuid.Parse(string(material.Rows[0][0]))
	if err != nil {
		t.Fatal(err)
	}
	version, err := strconv.Atoi(string(material.Rows[0][1]))
	if err != nil {
		t.Fatal(err)
	}
	profile, personal, slot, binding, boundary := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	cols := "boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal"
	vals := "'" + boundary + "',2,'" + signer.String() + "'," + strconv.Itoa(version) + ",decode(repeat('00',64),'hex')"
	profileInsert := func(id, owner, name string) string {
		return "INSERT INTO wormhole_data.credential_profiles(id,owner_user_id,name,protocol,kind,provider," + cols + ") VALUES('" + id + "'," + owner + ",'" + name + "','ssh','password','local'," + vals + ")"
	}
	script(profileInsert(profile, "NULL", "Account"))
	script(profileInsert(personal, "'"+testHintID+"'", "Account"))
	reject(profileInsert(uuid.NewString(), "NULL", "Account"), "23505")
	reject(profileInsert(uuid.NewString(), "'"+testHintID+"'", "Account"), "23505")
	script("INSERT INTO wormhole_data.credential_slots(id,name,protocol,default_credential_id," + cols + ") VALUES('" + slot + "','Login','ssh','" + profile + "'," + vals + ")")
	script("INSERT INTO wormhole_data.credential_slot_values(id,slot_id,user_id,credential_id," + cols + ") VALUES('" + binding + "','" + slot + "','" + testHintID + "','" + personal + "'," + vals + ")")
	script("INSERT INTO wormhole_data.user_node_overrides(user_id,node_id,credential_id," + cols + ") SELECT '" + testHintID + "',id,'" + personal + "'," + vals + " FROM wormhole_data.nodes WHERE kind=1 LIMIT 1")
	reject("INSERT INTO wormhole_data.credential_slot_values(id,slot_id,user_id,credential_id,"+cols+") SELECT '"+uuid.NewString()+"',slot_id,user_id,credential_id,"+cols+" FROM wormhole_data.credential_slot_values", "23505")
	reject("INSERT INTO wormhole_data.user_node_overrides SELECT * FROM wormhole_data.user_node_overrides", "23505")
	// Every write participates in the same catalog snapshot and invalidation reset.
	for _, table := range tables {
		before := admin.ExecParams(ctx, "SELECT change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
		if before.Err != nil || len(before.Rows) != 1 {
			t.Fatal(before.Err)
		}
		seq, err := strconv.ParseInt(string(before.Rows[0][0]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		script("UPDATE wormhole_data." + table + " SET row_version=row_version+1")
		check("SELECT (change_seq=" + strconv.FormatInt(seq+1, 10) + " AND catalog_reset_seq=change_seq)::text FROM wormhole_data.workspace_meta")
		script("BEGIN")
		script("UPDATE wormhole_data." + table + " SET row_version=row_version+1")
		if _, err := native.TreePage(ctx, TreeCursor{}, 32); err != ErrChangeInProgress {
			t.Fatal("mixed concurrent catalog snapshot", table, err)
		}
		script("ROLLBACK")
		check("SELECT (change_seq=" + strconv.FormatInt(seq+1, 10) + ")::text FROM wormhole_data.workspace_meta")
	}
	// Statement triggers include encrypted values and key copies, including no-op
	// writes: readers must serialize with the transaction before its row changes.
	for _, statement := range []string{"UPDATE wormhole_data.secret_values SET owner_id=owner_id", "UPDATE wormhole_data.key_copies SET issuer_key_id=issuer_key_id"} {
		before := admin.ExecParams(ctx, "SELECT change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
		if before.Err != nil || len(before.Rows) != 1 {
			t.Fatal(before.Err)
		}
		seq, err := strconv.ParseInt(string(before.Rows[0][0]), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		script("BEGIN")
		script(statement)
		check("SELECT (change_seq=" + strconv.FormatInt(seq+1, 10) + " AND catalog_reset_seq=change_seq)::text FROM wormhole_data.workspace_meta")
		if _, err := native.TreePage(ctx, TreeCursor{}, 32); err != ErrChangeInProgress {
			t.Fatal("mixed key/cipher snapshot", err)
		}
		script("ROLLBACK")
		check("SELECT (change_seq=" + strconv.FormatInt(seq, 10) + ")::text FROM wormhole_data.workspace_meta")
	}
	prior := admin.ExecParams(ctx, "SELECT change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
	if prior.Err != nil || len(prior.Rows) != 1 {
		t.Fatal(prior.Err)
	}
	priorSeq, err := strconv.ParseInt(string(prior.Rows[0][0]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	// Constraint failures must preserve the prior revision and snapshot.
	for _, update := range []string{
		"UPDATE wormhole_data.credential_profiles SET name=''",
		"UPDATE wormhole_data.credential_profiles SET name=chr(160)",
		"UPDATE wormhole_data.credential_profiles SET protocol='http'",
		"UPDATE wormhole_data.credential_profiles SET protocol='rdp',kind='sshKey'",
		"UPDATE wormhole_data.credential_profiles SET provider='bitwarden'",
		"UPDATE wormhole_data.credential_profiles SET bitwarden_item_id='item'",
		"UPDATE wormhole_data.credential_profiles SET username=repeat('x',2049)",
		"UPDATE wormhole_data.credential_profiles SET fields='{}'",
		"UPDATE wormhole_data.credential_profiles SET seal=decode('00','hex')",
		"UPDATE wormhole_data.credential_profiles SET row_version=0",
		"UPDATE wormhole_data.credential_profiles SET boundary_id='00000000-0000-0000-0000-000000000000'",
		"UPDATE wormhole_data.credential_slots SET protocol='sftp'",
		"UPDATE wormhole_data.credential_slot_values SET credential_id=NULL",
		"UPDATE wormhole_data.user_node_overrides SET credential_id=NULL",
	} {
		reject(update, "23514")
	}
	reject("UPDATE wormhole_data.credential_slots SET default_credential_id='"+uuid.NewString()+"'", "23503")
	reject("UPDATE wormhole_data.credential_slot_values SET user_id='"+uuid.NewString()+"'", "23503")
	reject("DELETE FROM wormhole_data.credential_profiles WHERE id='"+personal+"'", "23503")
	check("SELECT (change_seq=" + strconv.FormatInt(priorSeq, 10) + ")::text FROM wormhole_data.workspace_meta")
	script("BEGIN")
	script(`UPDATE wormhole_data.credential_profiles SET fields='[{"field":"password","version":1,"present":true}]'`)
	// A tombstone must not advertise live secret fields.
	reject("UPDATE wormhole_data.credential_profiles SET deleted=true", "23514")
	script("BEGIN")
	script("UPDATE wormhole_data.credential_profiles SET provider='bitwarden',bitwarden_item_id='item'")
	check("SELECT bool_and(provider='bitwarden' AND fields='[]'::jsonb)::text FROM wormhole_data.credential_profiles")
	script("ROLLBACK")
	// Tombstoning a binding removes the reference without forgetting its revision.
	script("BEGIN")
	script("UPDATE wormhole_data.credential_slot_values SET deleted=true,credential_id=NULL,row_version=row_version+1")
	script("UPDATE wormhole_data.user_node_overrides SET deleted=true,credential_id=NULL,row_version=row_version+1")
	check("SELECT (deleted AND credential_id IS NULL AND row_version=3)::text FROM wormhole_data.credential_slot_values")
	script("ROLLBACK")
	// Names can be reused after deletion; the original ID remains reserved.
	script("BEGIN")
	script("UPDATE wormhole_data.credential_profiles SET deleted=true WHERE id='" + profile + "'")
	script(profileInsert(uuid.NewString(), "NULL", "Account"))
	script("ROLLBACK")
	reject(profileInsert(profile, "NULL", "Different"), "23505")

	// Compare the field-manifest invariant with the existing native aggregate.
	for _, kind := range []string{"password", "sshKey"} {
		for _, provider := range []string{"local", "bitwarden"} {
			for _, deleted := range []bool{false, true} {
				for _, fields := range [][]vaultstore.CredentialField{
					{}, {{Field: "password", Version: 1, Present: true}}, {{Field: "password", Version: 1, Present: false}},
					{{Field: "certificate", Version: 1, Present: true}, {Field: "passphrase", Version: 2, Present: true}, {Field: "privateKey", Version: 3, Present: true}},
					{{Field: "privateKey", Version: 1}, {Field: "certificate", Version: 1}},
					{{Field: "password", Version: 1}, {Field: "password", Version: 2}},
					{{Field: "unknown", Version: 1}}, {{Field: "password", Version: 0}}, {{Field: "password", Version: 1 << 63}},
					{{Field: "certificate", Version: 1}, {Field: "passphrase", Version: 1}, {Field: "password", Version: 1}, {Field: "privateKey", Version: 1}, {Field: "extra", Version: 1}},
				} {
					c := vaultstore.Credential{CredentialMetadata: vaultstore.CredentialMetadata{ID: profile, Name: "Account", Protocol: "ssh", Kind: kind, Provider: provider}, RowVersion: 3, Deleted: deleted, Fields: fields, Seal: make([]byte, 32)}
					if provider == "bitwarden" {
						c.BitwardenItemID = "item"
					}
					// The helper covers fields only; unsupported BW sshKey metadata is separately
					// rejected by the table's provider/kind CHECK, not by this field validator.
					expected := c.Validate() == nil
					if provider == "bitwarden" && kind == "sshKey" {
						continue
					}
					raw, _ := json.Marshal(fields)
					r := admin.ExecParams(ctx, "SELECT wormhole_data.credential_fields_valid($1::jsonb,$2,$3,$4::boolean)::text", [][]byte{raw, []byte(kind), []byte(provider), []byte(strconv.FormatBool(deleted))}, nil, nil, nil).Read()
					if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != strconv.FormatBool(expected) {
						t.Fatal("Go/SQL manifest mismatch", kind, provider, deleted, string(raw), r.Err)
					}
				}
			}
		}
	}
	for _, args := range [][][]byte{
		{nil, []byte("password"), []byte("local"), []byte("false")},
		{[]byte("[]"), nil, []byte("local"), []byte("false")},
		{[]byte("[]"), []byte("password"), nil, []byte("false")},
		{[]byte("[]"), []byte("password"), []byte("local"), nil},
		{[]byte("[]"), []byte("other"), []byte("local"), []byte("false")},
		{[]byte("[]"), []byte("password"), []byte("other"), []byte("false")},
	} {
		r := admin.ExecParams(ctx, "SELECT wormhole_data.credential_fields_valid($1::jsonb,$2,$3,$4::boolean)::text", args, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "false" {
			t.Fatal("invalid manifest context", r.Err)
		}
	}
	for _, raw := range []string{"null", "{}", "[null]", "[1]", "[{}]", `[{"field":"password","version":1,"present":null}]`, `[{"field":"password","version":1.1,"present":true}]`, `[{"field":"password","version":"1","present":true}]`, `[{"field":"password","version":-1,"present":true}]`} {
		r := admin.ExecParams(ctx, "SELECT wormhole_data.credential_fields_valid($1::jsonb,'password','local',false)::text", [][]byte{[]byte(raw)}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "false" {
			t.Fatal("malformed manifest", r.Err)
		}
	}
}
