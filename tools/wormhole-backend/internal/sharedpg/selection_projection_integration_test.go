package sharedpg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedcatalog"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

const selectionProjectionTestSQL = `SELECT workspace_id::text,subject_id::text,epoch::text,change_seq::text,
 record::text,boundary_id::text,row_version::text,seal_suite::text,seal_signer_key_id::text,seal_signer_key_version::text,
 seal_capability_id::text,encode(seal,'hex'),author_id::text,signing_key_id::text,signing_key_version::text,
 state_sequence::text,encode(signed_state,'hex'),suite::text,encode(public_key,'hex'),cert_signer_key_id::text,
 cert_signer_key_version::text,cert_revision::text,encode(cert_signature,'hex')
 FROM wormhole_data.selection_record($1,$2::uuid,$3::uuid,$4::bigint,$5::bigint)`

func testPostgresSelectionProjection(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	reject := func(sql, code string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatal("projection migration rejection", err)
		}
		script("ROLLBACK")
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("projection state", r.Err)
		}
	}
	migration, _ := deploy.SelectionProjectionMigration("testscope", testHintID)
	wrong, _ := deploy.SelectionProjectionMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.selection_record(text,uuid,uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=26)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.selection_record(text,uuid,uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.selection_record(text,uuid,uuid,bigint,bigint)','EXECUTE'))::text")
	}
	_, b, trust, c, author, org, key := credentialTrustFixture(t)
	if b.WorkspaceID != native.admission.WorkspaceID || b.UserID != native.admission.UserID {
		t.Fatal("projection fixture identity")
	}
	c.Record.Metadata.Name = "Projection"
	c.Record.Metadata.Username = "login"
	c.Record.Metadata.Domain = "domain"
	c.Record.Metadata.PrivateKeyName = "key.pem"
	c.Record.Metadata.CertificateName = "cert.pem"
	var err error
	c.Seal, err = sharedcatalog.SignCredential(b.WorkspaceID, c.Boundary, c.Record, 1, author.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	script("BEGIN")
	defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
	cert := author.Certificate
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite,public_key) VALUES($1::uuid,$2::integer,'org-sign','pending',1,decode($3,'hex'))", []byte(cert.Signer.ID.String()), []byte(strconv.Itoa(int(cert.Signer.Version))), hex.AppendEncode(nil, trust.PublicKey))
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES($1::uuid,$2::integer,'user-sign',$3::uuid,'pending',1,decode($4,'hex'),$5::uuid,$6::integer,$7::bigint,decode($8,'hex'))", []byte(author.Key.ID.String()), []byte(strconv.Itoa(int(author.Key.Version))), []byte(b.UserID.String()), hex.AppendEncode(nil, cert.PublicKey), []byte(cert.Signer.ID.String()), []byte(strconv.Itoa(int(cert.Signer.Version))), []byte(strconv.FormatUint(cert.Revision, 10)), hex.AppendEncode(nil, cert.Signature))
	stateRaw, err := vault.EncodeUserKeyState(*author.State)
	if err != nil {
		t.Fatal(err)
	}
	exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", []byte(strconv.FormatUint(author.State.Sequence, 10)), hex.AppendEncode(nil, stateRaw), []byte(b.UserID.String()))
	fields, _ := json.Marshal(c.Record.Fields)
	exec("INSERT INTO wormhole_data.credential_profiles(id,name,protocol,kind,provider,fields,boundary_id,row_version,seal_suite,seal_signer_key_id,seal_signer_key_version,seal,username,domain,private_key_name,certificate_name) VALUES($1::uuid,$2,'ssh','password','local',$3::jsonb,$4::uuid,1,2,$5::uuid,$6::integer,decode($7,'hex'),$8,$9,$10,$11)", []byte(c.Record.Metadata.ID), []byte(c.Record.Metadata.Name), fields, []byte(c.Boundary.String()), []byte(author.Key.ID.String()), []byte(strconv.Itoa(int(author.Key.Version))), hex.AppendEncode(nil, c.Seal.Signature), []byte(c.Record.Metadata.Username), []byte(c.Record.Metadata.Domain), []byte(c.Record.Metadata.PrivateKeyName), []byte(c.Record.Metadata.CertificateName))
	snapshot := func() (uint64, uint64) {
		t.Helper()
		r := admin.ExecParams(ctx, "SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 {
			t.Fatal(r.Err)
		}
		epoch, e := strconv.ParseUint(string(r.Rows[0][0]), 10, 64)
		seq, e2 := strconv.ParseUint(string(r.Rows[0][1]), 10, 64)
		if e != nil || e2 != nil {
			t.Fatal("snapshot numbers")
		}
		return epoch, seq
	}

	slotID := uuid.NewString()
	nodeID := uuid.NewString()
	exec("INSERT INTO wormhole_data.nodes(id,kind) VALUES($1::uuid,1)", []byte(nodeID))
	records := []sharedcatalog.SelectionRecord{
		sharedcatalog.SlotRecord{ID: slotID, Name: "Slot", Protocol: "ssh", DefaultCredentialID: c.Record.Metadata.ID, AllowSelfService: true},
		sharedcatalog.SlotValueRecord{ID: uuid.NewString(), SlotID: slotID, UserID: b.UserID.String(), CredentialID: c.Record.Metadata.ID},
		sharedcatalog.OverrideRecord{NodeID: nodeID, UserID: b.UserID.String(), CredentialID: c.Record.Metadata.ID},
	}
	for _, record := range records {
		scope, _, _ := sharedcatalog.SelectionIdentity(record)
		seal, e := sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, record, 1, author.Key, key)
		if e != nil {
			t.Fatal(e)
		}
		args := [][]byte{[]byte(c.Boundary.String()), []byte(author.Key.ID.String()), []byte(strconv.Itoa(int(author.Key.Version))), hex.AppendEncode(nil, seal.Signature)}
		var table, where string
		switch r := record.(type) {
		case sharedcatalog.SlotRecord:
			table = "credential_slots"
			where = "id='" + r.ID + "'"
			exec("INSERT INTO wormhole_data.credential_slots(boundary_id,seal_signer_key_id,seal_signer_key_version,seal,seal_suite,id,name,protocol,default_credential_id,allow_self_service) VALUES($1::uuid,$2::uuid,$3::int,decode($4,'hex'),2,$5::uuid,$6,$7,$8::uuid,true)", append(args, []byte(r.ID), []byte(r.Name), []byte(r.Protocol), []byte(r.DefaultCredentialID))...)
		case sharedcatalog.SlotValueRecord:
			table = "credential_slot_values"
			where = "id='" + r.ID + "'"
			exec("INSERT INTO wormhole_data.credential_slot_values(boundary_id,seal_signer_key_id,seal_signer_key_version,seal,seal_suite,id,slot_id,user_id,credential_id) VALUES($1::uuid,$2::uuid,$3::int,decode($4,'hex'),2,$5::uuid,$6::uuid,$7::uuid,$8::uuid)", append(args, []byte(r.ID), []byte(r.SlotID), []byte(r.UserID), []byte(r.CredentialID))...)
		case sharedcatalog.OverrideRecord:
			table = "user_node_overrides"
			where = "node_id='" + r.NodeID + "' AND user_id='" + r.UserID + "'"
			exec("INSERT INTO wormhole_data.user_node_overrides(boundary_id,seal_signer_key_id,seal_signer_key_version,seal,seal_suite,node_id,user_id,credential_id) VALUES($1::uuid,$2::uuid,$3::int,decode($4,'hex'),2,$5::uuid,$6::uuid,$7::uuid)", append(args, []byte(r.NodeID), []byte(r.UserID), []byte(r.CredentialID))...)
		}
		requestArgs := func() ([][]byte, uint64, uint64) {
			epoch, seq := snapshot()
			var user []byte
			if scope.User != uuid.Nil {
				user = []byte(scope.User.String())
			}
			return [][]byte{[]byte(scope.Kind), []byte(scope.Subject.String()), user, []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(seq, 10))}, epoch, seq
		}
		read := func() (*UnverifiedSelection, *UnverifiedNodeAuthor) {
			t.Helper()
			args, epoch, seq := requestArgs()
			r := admin.ExecParams(ctx, selectionProjectionTestSQL, args, nil, nil, nil).Read()
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			got, a, e := parseSelectionProjection(r.Rows, native.admission, scope, epoch, seq)
			if e != nil {
				t.Fatal(e)
			}
			return got, a
		}
		got, a := read()
		if !reflect.DeepEqual(got.Record, record) || !reflect.DeepEqual(*a, author) {
			t.Fatal("selection SQL/Go drift")
		}
		accepted, e := trust.AdvanceSelection(*got, *a)
		if e != nil {
			t.Fatal("signature", e)
		}
		deny := func(args [][]byte, code string) {
			t.Helper()
			script("SAVEPOINT bad_selection")
			r := admin.ExecParams(ctx, selectionProjectionTestSQL, args, nil, nil, nil).Read()
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
				t.Fatal("selection rejection", code, r.Err)
			}
			script("ROLLBACK TO SAVEPOINT bad_selection; RELEASE SAVEPOINT bad_selection")
		}
		for _, col := range []int{0, 1, 3, 4} {
			args, _, _ := requestArgs()
			args[col] = nil
			deny(args, "22023")
		}
		for _, invalid := range []struct {
			col   int
			value string
			code  string
		}{{0, "bad", "22023"}, {1, uuid.Nil.String(), "22023"}, {1, uuid.NewString(), "WH018"}, {3, "0", "22023"}, {4, "-1", "22023"}, {4, "0", "WH013"}} {
			args, _, _ := requestArgs()
			args[invalid.col] = []byte(invalid.value)
			deny(args, invalid.code)
		}
		args, _, _ = requestArgs()
		if scope.Kind == "slot" {
			args[2] = []byte(b.UserID.String())
		} else {
			args[2] = nil
		}
		deny(args, "22023")
		if scope.Kind != "slot" {
			args, _, _ := requestArgs()
			args[2] = []byte(uuid.NewString())
			deny(args, "WH018")
			args, _, _ = requestArgs()
			args[2] = []byte(uuid.Nil.String())
			deny(args, "22023")
		}
		for _, mode := range []string{"tamper", "tombstone", "missing-state", "missing-certificate", "revoked", "provisioning", "version"} {
			script("SAVEPOINT selection_mutation")
			switch mode {
			case "tamper":
				script("UPDATE wormhole_data." + table + " SET boundary_id='" + uuid.NewString() + "' WHERE " + where)
			case "tombstone":
				v := reflect.New(reflect.TypeOf(record)).Elem()
				v.Set(reflect.ValueOf(record))
				v.FieldByName("Deleted").SetBool(true)
				extra := ""
				if scope.Kind != "slot" {
					v.FieldByName("CredentialID").SetString("")
					extra = ",credential_id=NULL"
				} else {
					v.FieldByName("DefaultCredentialID").SetString("")
					extra = ",default_credential_id=NULL"
				}
				seal, e := sharedcatalog.SignSelection(b.WorkspaceID, c.Boundary, v.Interface().(sharedcatalog.SelectionRecord), 2, author.Key, key)
				if e != nil {
					t.Fatal(e)
				}
				exec("UPDATE wormhole_data."+table+" SET deleted=true,row_version=2,seal=decode($1,'hex')"+extra+" WHERE "+where, hex.AppendEncode(nil, seal.Signature))
			case "missing-state":
				script("DELETE FROM wormhole_data.user_key_states WHERE user_id='" + b.UserID.String() + "'")
			case "missing-certificate", "revoked":
				exec("UPDATE wormhole_data.keys SET cert_signature=NULL,cert_revision=NULL,cert_signer_key_id=NULL,cert_signer_key_version=NULL WHERE key_id=$1::uuid", []byte(author.Key.ID.String()))
				if mode == "revoked" {
					state := *author.State
					state.Sequence++
					state.Active = false
					state, e = vault.SignUserKeyState(state, org)
					if e != nil {
						t.Fatal(e)
					}
					raw, e := vault.EncodeUserKeyState(state)
					if e != nil {
						t.Fatal(e)
					}
					exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", []byte(strconv.FormatUint(state.Sequence, 10)), hex.AppendEncode(nil, raw), []byte(b.UserID.String()))
				}
			case "provisioning":
				script("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
			case "version":
				script("UPDATE wormhole_data.workspace_meta SET min_api=2,max_api=2")
			}
			if code := map[string]string{"missing-state": "WH010", "provisioning": "WH002", "version": "WH004"}[mode]; code != "" {
				args, _, _ := requestArgs()
				deny(args, code)
			} else {
				projected, material := read()
				next, e := accepted.AdvanceSelection(*projected, *material)
				switch mode {
				case "tamper":
					if e != vault.ErrAuthentication {
						t.Fatal("tamper", e)
					}
				case "tombstone":
					floor := scope.Kind + "/" + scope.Subject.String()
					if scope.User != uuid.Nil {
						floor += "/" + scope.User.String()
					}
					if e != vaultstore.ErrMissing || next.Catalog[floor].Revision != 2 {
						t.Fatal("tombstone", e)
					}
				case "missing-certificate":
					if e == nil || material.Certificate != nil || next.Revision == 0 {
						t.Fatal("certificate", e)
					}
				case "revoked":
					if e != vault.ErrPolicy || next.Catalog["author/"+b.UserID.String()].Revision != author.State.Sequence+1 {
						t.Fatal("revocation", e)
					}
				}
			}
			script("ROLLBACK TO SAVEPOINT selection_mutation; RELEASE SAVEPOINT selection_mutation")
		}
	}
}
