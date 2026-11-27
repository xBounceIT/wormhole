package sharedpg

import (
	"bytes"
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

const credentialValuesTestSQL = `SELECT workspace_id::text,credential_id::text,epoch::text,change_seq::text,field,row_version::text,dek_id::text,dek_version::text,encode(envelope,'hex') FROM wormhole_data.credential_values($1::uuid,$2::bigint,$3::bigint)`

func testPostgresCredentialValues(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
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
	migration, _ := deploy.CredentialValuesMigration("testscope", testHintID)
	wrong, _ := deploy.CredentialValuesMigration("testscope", uuid.NewString())
	reject(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.credential_values(uuid,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	reject(migration, "42723")
	check("SELECT (schema_version=31)::text FROM wormhole_data.workspace_meta")
	script("DROP FUNCTION wormhole_data.credential_values(uuid,bigint,bigint)")
	script(migration)
	reject(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		check("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.credential_values(uuid,bigint,bigint)','EXECUTE'))::text")
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
	exec("INSERT INTO wormhole_data.boundaries(id) VALUES($1::uuid)", []byte(c.Boundary.String()))
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

	dek := vault.KeyRef{ID: uuid.New(), Version: 2}
	valueBinding := vault.SharedValueBinding{WorkspaceID: b.WorkspaceID, OwnerKind: "credential", OwnerID: uuid.MustParse(c.Record.Metadata.ID), Field: "password", Version: c.Record.Fields[0].Version, DEK: dek}
	keyBytes := bytes.Repeat([]byte{23}, 32)
	defer vault.Wipe(keyBytes)
	value, e := vault.SealSharedValue(keyBytes, valueBinding, []byte("secret-from-pg"))
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := vault.EncodeSharedEnvelope(value)
	if e != nil {
		t.Fatal(e)
	}
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite) VALUES($1::uuid,2,'dek','pending',1)", []byte(dek.ID.String()))
	exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) VALUES('credential',$1::uuid,'password',$2::uuid,2,decode($3,'hex'),$4::bigint)", []byte(c.Record.Metadata.ID), []byte(dek.ID.String()), hex.AppendEncode(nil, encoded), []byte(strconv.FormatUint(valueBinding.Version, 10)))
	args := func() ([][]byte, uint64, uint64) {
		epoch, seq := snapshot()
		return [][]byte{[]byte(c.Record.Metadata.ID), []byte(strconv.FormatUint(epoch, 10)), []byte(strconv.FormatUint(seq, 10))}, epoch, seq
	}
	read := func() ([]UnverifiedSharedValue, error) {
		t.Helper()
		a, epoch, seq := args()
		r := admin.ExecParams(ctx, credentialValuesTestSQL, a, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		return parseCredentialValues(r.Rows, native.admission, c.Record, epoch, seq)
	}
	values, e := read()
	if e != nil || len(values) != 1 || values[0].Binding != valueBinding || !reflect.DeepEqual(values[0].Envelope, value) {
		t.Fatal("SQL/native value drift", e)
	}
	authenticated, e := trust.AdvanceCredential(c, author)
	if e != nil || trust.ValidateAdvance(authenticated) != nil {
		t.Fatal("selected credential auth", e)
	}
	_, _, _, manifest, _ := boundaryTrustFixture(t)
	manifest.WorkspaceID = b.WorkspaceID
	manifest.BoundaryID = c.Boundary
	manifest.Signer = author.State.Signer
	manifest, e = vault.SignBoundaryManifest(manifest, org)
	if e != nil {
		t.Fatal(e)
	}
	manifestTrust := vault.BoundaryTrust{WorkspaceID: b.WorkspaceID, BoundaryID: c.Boundary, Signer: manifest.Signer, Organisation: trust.PublicKey, MinimumRevision: 1}
	copy, e := vault.SealKeyCopy(keyBytes, vault.KeyCopyBinding{WorkspaceID: b.WorkspaceID, Key: dek, Holder: manifest.Secret.Key, Issuer: manifest.Signer}, manifest.Secret.Public, org.Seed())
	if e != nil {
		t.Fatal(e)
	}
	rootSeed := bytes.Repeat([]byte{4}, 32)
	defer vault.Wipe(rootSeed)
	plaintext, e := vault.OpenSharedValue(rootSeed, manifest.Secret.Key, values[0].Binding, copy, vault.KeyCopyTrust{Issuer: manifest.Signer, Public: trust.PublicKey}, values[0].Envelope, manifest, manifestTrust)
	if e != nil || !bytes.Equal(plaintext, []byte("secret-from-pg")) {
		t.Fatal("SQL value authentication/decryption", e)
	}
	vault.Wipe(plaintext)
	deny := func(query, code string, a ...[]byte) {
		t.Helper()
		script("SAVEPOINT bad_value")
		r := admin.ExecParams(ctx, query, a, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("credential value rejection", code, r.Err)
		}
		script("ROLLBACK TO SAVEPOINT bad_value; RELEASE SAVEPOINT bad_value")
	}
	base, _, _ := args()
	for col := range base {
		invalid := append([][]byte(nil), base...)
		invalid[col] = nil
		deny(credentialValuesTestSQL, "22023", invalid...)
	}
	for _, bad := range []struct {
		col     int
		v, code string
	}{{0, uuid.Nil.String(), "22023"}, {0, uuid.NewString(), "WH018"}, {1, "0", "22023"}, {2, "-1", "22023"}, {2, "0", "WH013"}} {
		a := append([][]byte(nil), base...)
		a[bad.col] = []byte(bad.v)
		deny(credentialValuesTestSQL, bad.code, a...)
	}
	for _, mode := range []string{"missing", "version", "wrong-kind", "extra", "corrupt", "deleted", "absent", "oversize", "aggregate", "provisioning", "api"} {
		script("SAVEPOINT value_mutation")
		switch mode {
		case "missing":
			exec("DELETE FROM wormhole_data.secret_values WHERE owner_id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "version":
			exec("UPDATE wormhole_data.secret_values SET row_version=row_version+1 WHERE owner_id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "wrong-kind":
			exec("UPDATE wormhole_data.keys SET kind='boundary-secret' WHERE key_id=$1::uuid", []byte(dek.ID.String()))
		case "extra":
			exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) SELECT owner_kind,owner_id,'ignored',dek_id,dek_version,envelope,row_version FROM wormhole_data.secret_values WHERE owner_id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "corrupt":
			exec("UPDATE wormhole_data.secret_values SET envelope=decode(repeat('00',16),'hex') WHERE owner_id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "deleted":
			exec("UPDATE wormhole_data.credential_profiles SET deleted=true,fields='[]'::jsonb WHERE id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "absent":
			exec("UPDATE wormhole_data.credential_profiles SET fields='[{\"field\":\"password\",\"version\":1,\"present\":false}]'::jsonb WHERE id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "oversize":
			exec("UPDATE wormhole_data.secret_values SET envelope=decode(repeat('00',6291457),'hex') WHERE owner_id=$1::uuid", []byte(c.Record.Metadata.ID))
		case "aggregate":
			fields, _ := json.Marshal([]vaultstore.CredentialField{{Field: "certificate", Version: 1, Present: true}, {Field: "privateKey", Version: 1, Present: true}})
			exec("UPDATE wormhole_data.credential_profiles SET kind='sshKey',fields=$1::jsonb WHERE id=$2::uuid", fields, []byte(c.Record.Metadata.ID))
			for _, field := range []string{"certificate", "privateKey"} {
				exec("INSERT INTO wormhole_data.secret_values(owner_kind,owner_id,field,dek_id,dek_version,envelope,row_version) VALUES('credential',$1::uuid,$2,$3::uuid,2,decode(repeat('00',5242880),'hex'),1)", []byte(c.Record.Metadata.ID), []byte(field), []byte(dek.ID.String()))
			}
		case "provisioning":
			exec("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
		case "api":
			exec("UPDATE wormhole_data.workspace_meta SET min_api=2,max_api=2")
		}
		if code := map[string]string{"missing": "WH010", "version": "WH010", "wrong-kind": "WH010", "deleted": "WH018", "oversize": "54000", "aggregate": "54000", "provisioning": "WH002", "api": "WH004"}[mode]; code != "" {
			a, _, _ := args()
			deny(credentialValuesTestSQL, code, a...)
		} else {
			values, e := read()
			switch mode {
			case "extra":
				if e != nil || len(values) != 1 || values[0].Binding != valueBinding {
					t.Fatal("unmanifested field included", e)
				}
			case "corrupt", "absent":
				if e != ErrAdmissionResponse {
					t.Fatal("unexpected/missing ciphertext accepted", e)
				}
			}
		}
		script("ROLLBACK TO SAVEPOINT value_mutation; RELEASE SAVEPOINT value_mutation")
	}
}
