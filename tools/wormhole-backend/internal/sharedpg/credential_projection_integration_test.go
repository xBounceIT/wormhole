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

const credentialProjectionTestSQL = `SELECT workspace_id::text,credential_id::text,epoch::text,change_seq::text,
 record::text,boundary_id::text,row_version::text,seal_suite::text,seal_signer_key_id::text,seal_signer_key_version::text,
 seal_capability_id::text,encode(seal,'hex'),author_id::text,signing_key_id::text,signing_key_version::text,
 state_sequence::text,encode(signed_state,'hex'),suite::text,encode(public_key,'hex'),cert_signer_key_id::text,
 cert_signer_key_version::text,cert_revision::text,encode(cert_signature,'hex')
 FROM wormhole_data.credential_record($1::uuid,$2::bigint,$3::bigint)`

func testPostgresCredentialProjection(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
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
	migration, _ := deploy.CredentialProjectionMigration("testscope", testHintID)
	wrong, _ := deploy.CredentialProjectionMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.credential_record(uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=25)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.credential_record(uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.credential_record(uuid,bigint,bigint)','EXECUTE'))::text")
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
	id := uuid.MustParse(c.Record.Metadata.ID)
	read := func() (*UnverifiedCredential, *UnverifiedNodeAuthor) {
		t.Helper()
		epoch, seq := snapshot()
		r := admin.ExecParams(ctx, credentialProjectionTestSQL, [][]byte{[]byte(id.String()), []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(seq, 10))}, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		got, a, e := parseCredentialProjection(r.Rows, native.admission, id, epoch, seq)
		if e != nil {
			t.Fatal(e)
		}
		return got, a
	}
	got, a := read()
	if !reflect.DeepEqual(*got, c) || !reflect.DeepEqual(*a, author) {
		t.Fatal("SQL/Go credential projection drift")
	}
	accepted, err := trust.AdvanceCredential(*got, *a)
	if err != nil || len(accepted.Catalog) != 3 {
		t.Fatal("real SQL signature verification", err)
	}
	deny := func(args [][]byte, code string) {
		t.Helper()
		script("SAVEPOINT bad_request")
		r := admin.ExecParams(ctx, credentialProjectionTestSQL, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("projection request rejection", r.Err)
		}
		script("ROLLBACK TO SAVEPOINT bad_request; RELEASE SAVEPOINT bad_request")
	}
	epoch, seq := snapshot()
	args := [][]byte{[]byte(id.String()), []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(seq, 10))}
	missing := append([][]byte(nil), args...)
	missing[0] = []byte(uuid.NewString())
	deny(missing, "WH018")
	for i := 0; i < 3; i++ {
		invalid := append([][]byte(nil), args...)
		invalid[i] = nil
		deny(invalid, "22023")
	}
	for i, value := range []string{uuid.Nil.String(), "0", "-1"} {
		invalid := append([][]byte(nil), args...)
		invalid[i] = []byte(value)
		deny(invalid, "22023")
	}
	script("UPDATE wormhole_data.credential_profiles SET row_version=row_version WHERE id='" + id.String() + "'")
	deny(args, "WH013")
	for _, mode := range []string{"provisioning", "version", "missing-state", "missing-certificate", "revocation", "personal-owner", "bitwarden", "tamper", "tombstone"} {
		script("SAVEPOINT mutation")
		switch mode {
		case "provisioning":
			script("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
		case "version":
			script("UPDATE wormhole_data.workspace_meta SET resolver_version=2")
		case "missing-state":
			script("DELETE FROM wormhole_data.user_key_states")
		case "missing-certificate", "revocation":
			exec("UPDATE wormhole_data.keys SET cert_signer_key_id=NULL,cert_signer_key_version=NULL,cert_revision=NULL,cert_signature=NULL WHERE key_id=$1::uuid", []byte(author.Key.ID.String()))
			if mode == "revocation" {
				revoked := *author.State
				revoked.Sequence++
				revoked.Active = false
				revoked, e := vault.SignUserKeyState(revoked, org)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := vault.EncodeUserKeyState(revoked)
				if e != nil {
					t.Fatal(e)
				}
				exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", []byte(strconv.FormatUint(revoked.Sequence, 10)), hex.AppendEncode(nil, raw), []byte(b.UserID.String()))
			}
		case "personal-owner", "bitwarden":
			changed := c
			if mode == "personal-owner" {
				changed.Record.Metadata.OwnerUserID = b.UserID.String()
			} else {
				changed.Record.Metadata.Provider = "bitwarden"
				changed.Record.Metadata.BitwardenItemID = "item-id"
				changed.Record.Metadata.BitwardenItemName = "item-name"
				changed.Record.Metadata.BitwardenFieldPath = "field-path"
				changed.Record.Metadata.PrivateKeyName = ""
				changed.Record.Metadata.CertificateName = ""
				changed.Record.Fields = []vaultstore.CredentialField{}
			}
			seal, e := sharedcatalog.SignCredential(b.WorkspaceID, changed.Boundary, changed.Record, 2, author.Key, key)
			if e != nil {
				t.Fatal(e)
			}
			f, _ := json.Marshal(changed.Record.Fields)
			exec("UPDATE wormhole_data.credential_profiles SET owner_user_id=NULLIF($1,'')::uuid,provider=$2,bitwarden_item_id=$3,bitwarden_item_name=$4,bitwarden_field_path=$5,private_key_name=$6,certificate_name=$7,fields=$8::jsonb,row_version=2,seal=decode($9,'hex') WHERE id=$10::uuid", []byte(changed.Record.Metadata.OwnerUserID), []byte(changed.Record.Metadata.Provider), []byte(changed.Record.Metadata.BitwardenItemID), []byte(changed.Record.Metadata.BitwardenItemName), []byte(changed.Record.Metadata.BitwardenFieldPath), []byte(changed.Record.Metadata.PrivateKeyName), []byte(changed.Record.Metadata.CertificateName), f, hex.AppendEncode(nil, seal.Signature), []byte(id.String()))
		case "tamper":
			exec("UPDATE wormhole_data.credential_profiles SET username='redirected' WHERE id=$1::uuid", []byte(id.String()))
		case "tombstone":
			tomb := c
			tomb.Record.Deleted = true
			tomb.Record.Fields = []vaultstore.CredentialField{{Field: "password", Version: 2, Present: false}}
			seal, e := sharedcatalog.SignCredential(b.WorkspaceID, tomb.Boundary, tomb.Record, 2, author.Key, key)
			if e != nil {
				t.Fatal(e)
			}
			f, _ := json.Marshal(tomb.Record.Fields)
			exec("UPDATE wormhole_data.credential_profiles SET deleted=true,fields=$1::jsonb,row_version=2,seal=decode($2,'hex') WHERE id=$3::uuid", f, hex.AppendEncode(nil, seal.Signature), []byte(id.String()))
		}
		if code := map[string]string{"provisioning": "WH002", "version": "WH004", "missing-state": "WH010"}[mode]; code != "" {
			epoch, seq = snapshot()
			deny([][]byte{[]byte(id.String()), []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(seq, 10))}, code)
		} else {
			projected, material := read()
			next, e := accepted.AdvanceCredential(*projected, *material)
			switch mode {
			case "missing-certificate":
				if material.Certificate != nil || e == nil || next.Revision == 0 {
					t.Fatal("revocation material discarded", e)
				}
			case "revocation":
				if e != vault.ErrPolicy || next.Catalog["author/"+b.UserID.String()].Revision != author.State.Sequence+1 {
					t.Fatal("SQL revocation lost", e)
				}
			case "personal-owner", "bitwarden":
				if e != nil || next.Catalog["credential/"+id.String()].Revision != 2 {
					t.Fatal("alternate credential metadata drift", mode, e)
				}
			case "tamper":
				if e != vault.ErrAuthentication {
					t.Fatal("database tamper accepted", e)
				}
			case "tombstone":
				if e != vaultstore.ErrMissing || next.Catalog["credential/"+id.String()].Revision != 2 {
					t.Fatal("tombstone floor missing", e)
				}
			}
		}
		script("ROLLBACK TO SAVEPOINT mutation; RELEASE SAVEPOINT mutation")
	}
}
