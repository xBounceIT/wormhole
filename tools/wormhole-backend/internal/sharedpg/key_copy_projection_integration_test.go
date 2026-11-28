package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const keyCopyProjectionTestSQL = `SELECT workspace_id::text,epoch::text,change_seq::text,key_id::text,key_version::text,holder_key_id::text,holder_key_version::text,suite::text,encode(enc,'hex'),encode(ciphertext,'hex'),issuer_key_id::text,issuer_key_version::text,encode(signature,'hex'),issuer_kind,author_id::text,state_sequence::text,encode(signed_state,'hex'),cert_suite::text,encode(cert_public,'hex'),cert_signer_id::text,cert_signer_version::text,cert_revision::text,encode(cert_signature,'hex') FROM wormhole_data.key_copy_record($1::uuid,$2::int,$3::uuid,$4::int,$5::bigint,$6::bigint)`

func testPostgresKeyCopyProjection(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
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
	rejectMigration := func(sql, code string) {
		t.Helper()
		_, e := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(e, &pe) || pe.Code != code {
			t.Fatal("copy migration", e)
		}
		script("ROLLBACK")
	}
	migration, _ := deploy.KeyCopyProjectionMigration("testscope", testHintID)
	wrong, _ := deploy.KeyCopyProjectionMigration("testscope", uuid.NewString())
	rejectMigration(wrong, "55000")
	script("CREATE FUNCTION wormhole_data.key_copy_record(uuid,int,uuid,int,bigint,bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
	rejectMigration(migration, "42723")
	r := exec("SELECT (schema_version=32)::text FROM wormhole_data.workspace_meta")
	if string(r.Rows[0][0]) != "true" {
		t.Fatal("copy migration rollback")
	}
	script("DROP FUNCTION wormhole_data.key_copy_record(uuid,int,uuid,int,bigint,bigint)")
	script(migration)
	rejectMigration(migration, "55000")
	for _, role := range []string{"user", "admin", "enroll"} {
		r := exec("SELECT (NOT has_function_privilege('wh_testscope_" + role + "','wormhole_data.key_copy_record(uuid,int,uuid,int,bigint,bigint)','EXECUTE'))::text")
		if string(r.Rows[0][0]) != "true" {
			t.Fatal("copy ACL")
		}
	}
	_, b, trust, _, a, org, key := credentialTrustFixture(t)
	script("BEGIN")
	defer func() { _, _ = admin.Exec(context.Background(), "ROLLBACK").ReadAll() }()
	n := func(v uint64) []byte { return []byte(strconv.FormatUint(v, 10)) }
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite,public_key) VALUES($1::uuid,$2::int,'org-sign','pending',1,decode($3,'hex'))", []byte(a.State.Signer.ID.String()), n(uint64(a.State.Signer.Version)), hex.AppendEncode(nil, trust.PublicKey))
	c := a.Certificate
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES($1::uuid,$2::int,'user-sign',$3::uuid,'pending',1,decode($4,'hex'),$5::uuid,$6::int,$7::bigint,decode($8,'hex'))", []byte(a.Key.ID.String()), n(uint64(a.Key.Version)), []byte(b.UserID.String()), hex.AppendEncode(nil, c.PublicKey), []byte(c.Signer.ID.String()), n(uint64(c.Signer.Version)), n(c.Revision), hex.AppendEncode(nil, c.Signature))
	state, e := vault.EncodeUserKeyState(*a.State)
	if e != nil {
		t.Fatal(e)
	}
	exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", n(a.State.Sequence), hex.AppendEncode(nil, state), []byte(b.UserID.String()))
	recipient, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	data := bytes.Repeat([]byte{23}, 32)
	defer vault.Wipe(data)
	binding := vault.KeyCopyBinding{WorkspaceID: b.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: vault.KeyRef{ID: uuid.New(), Version: 1}, Issuer: a.Key}
	for _, ref := range []struct {
		ref  vault.KeyRef
		kind string
	}{{binding.Key, "dek"}, {binding.Holder, "user-enc"}} {
		exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,status,suite,public_key) VALUES($1::uuid,$2::int,$3,'pending',2,decode($4,'hex'))", []byte(ref.ref.ID.String()), n(uint64(ref.ref.Version)), []byte(ref.kind), hex.AppendEncode(nil, recipient.PublicKey().Bytes()))
	}
	copy, e := vault.SealKeyCopy(data, binding, recipient.PublicKey().Bytes(), key.Seed())
	if e != nil {
		t.Fatal(e)
	}
	exec("INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,1,$2::uuid,1,2,decode($3,'hex'),decode($4,'hex'),$5::uuid,$6::int,decode($7,'hex'))", []byte(binding.Key.ID.String()), []byte(binding.Holder.ID.String()), hex.AppendEncode(nil, copy.Envelope.Enc), hex.AppendEncode(nil, copy.Envelope.Ciphertext), []byte(binding.Issuer.ID.String()), n(uint64(binding.Issuer.Version)), hex.AppendEncode(nil, copy.Signature))
	args := func() ([][]byte, uint64, uint64) {
		r := exec("SELECT epoch::text,change_seq::text FROM wormhole_data.workspace_meta")
		epoch, e1 := strconv.ParseUint(string(r.Rows[0][0]), 10, 64)
		seq, e2 := strconv.ParseUint(string(r.Rows[0][1]), 10, 64)
		if e1 != nil || e2 != nil {
			t.Fatal("snapshot")
		}
		return [][]byte{[]byte(binding.Key.ID.String()), n(uint64(binding.Key.Version)), []byte(binding.Holder.ID.String()), n(uint64(binding.Holder.Version)), r.Rows[0][0], r.Rows[0][1]}, epoch, seq
	}
	read := func() *UnverifiedKeyCopy {
		t.Helper()
		args, epoch, seq := args()
		r := exec(keyCopyProjectionTestSQL, args...)
		got, e := parseKeyCopyProjection(r.Rows, AdmissionRequest{WorkspaceID: b.WorkspaceID, UserID: b.UserID}, binding.Key, binding.Holder, epoch, seq)
		if e != nil {
			t.Fatal(e)
		}
		return got
	}
	got := read()
	if got.Author == nil || got.Binding != binding {
		t.Fatal("copy drift")
	}
	accepted, e := trust.AdvanceKeyCopy(got.Binding, got.Copy, got.Author)
	if e != nil || trust.ValidateAdvance(accepted) != nil {
		t.Fatal("copy member signature", e)
	}
	opened, e := vault.OpenKeyCopy(recipient.Bytes(), got.Binding, got.Copy, got.Author.Certificate.PublicKey)
	if e != nil || !bytes.Equal(opened, data) {
		t.Fatal("DB copy HPKE open", e)
	}
	vault.Wipe(opened)
	deny := func(args [][]byte, code string) {
		t.Helper()
		script("SAVEPOINT bad_copy")
		r := admin.ExecParams(ctx, keyCopyProjectionTestSQL, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code || len(r.Rows) != 0 {
			t.Fatal("copy rejection", code, r.Err)
		}
		script("ROLLBACK TO SAVEPOINT bad_copy; RELEASE SAVEPOINT bad_copy")
	}
	base, _, _ := args()
	for col := range base {
		bad := append([][]byte(nil), base...)
		bad[col] = nil
		deny(bad, "22023")
	}
	for _, bad := range []struct {
		col     int
		v, code string
	}{{0, uuid.Nil.String(), "22023"}, {0, uuid.NewString(), "WH010"}, {1, "0", "22023"}, {2, uuid.Nil.String(), "22023"}, {2, uuid.NewString(), "WH010"}, {3, "0", "22023"}, {4, "0", "22023"}, {5, "-1", "22023"}, {5, "0", "WH013"}} {
		v := append([][]byte(nil), base...)
		v[bad.col] = []byte(bad.v)
		deny(v, bad.code)
	}
	for _, mode := range []string{"org", "suite", "enc", "ciphertext", "issuer-kind", "missing-cert", "missing-state", "revoked", "provisioning", "api"} {
		script("SAVEPOINT copy_mutation")
		switch mode {
		case "org":
			alternate := binding
			alternate.Issuer = a.State.Signer
			orgCopy, e := vault.SealKeyCopy(data, alternate, recipient.PublicKey().Bytes(), org.Seed())
			if e != nil {
				t.Fatal(e)
			}
			exec("UPDATE wormhole_data.key_copies SET issuer_key_id=$1::uuid,issuer_key_version=$2::int,enc=decode($3,'hex'),ciphertext=decode($4,'hex'),signature=decode($5,'hex') WHERE key_id=$6::uuid", []byte(alternate.Issuer.ID.String()), n(uint64(alternate.Issuer.Version)), hex.AppendEncode(nil, orgCopy.Envelope.Enc), hex.AppendEncode(nil, orgCopy.Envelope.Ciphertext), hex.AppendEncode(nil, orgCopy.Signature), []byte(binding.Key.ID.String()))
		case "suite":
			exec("UPDATE wormhole_data.key_copies SET suite=1 WHERE key_id=$1::uuid", []byte(binding.Key.ID.String()))
		case "enc":
			exec("UPDATE wormhole_data.key_copies SET enc=NULL WHERE key_id=$1::uuid", []byte(binding.Key.ID.String()))
		case "ciphertext":
			exec("UPDATE wormhole_data.key_copies SET ciphertext=decode(repeat('00',49),'hex') WHERE key_id=$1::uuid", []byte(binding.Key.ID.String()))
		case "issuer-kind":
			exec("UPDATE wormhole_data.keys SET kind='group' WHERE key_id=$1::uuid", []byte(a.Key.ID.String()))
		case "missing-cert", "revoked":
			exec("UPDATE wormhole_data.keys SET cert_signer_key_id=NULL,cert_signer_key_version=NULL,cert_revision=NULL,cert_signature=NULL WHERE key_id=$1::uuid", []byte(a.Key.ID.String()))
			if mode == "revoked" {
				state := *a.State
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
				exec("UPDATE wormhole_data.user_key_states SET state_sequence=$1::bigint,signed_state=decode($2,'hex') WHERE user_id=$3::uuid", n(state.Sequence), hex.AppendEncode(nil, raw), []byte(b.UserID.String()))
			}
		case "missing-state":
			exec("DELETE FROM wormhole_data.user_key_states WHERE user_id=$1::uuid", []byte(b.UserID.String()))
		case "provisioning":
			exec("UPDATE wormhole_data.workspace_meta SET state='provisioning'")
		case "api":
			exec("UPDATE wormhole_data.workspace_meta SET min_api=2,max_api=2")
		}
		if code := map[string]string{"suite": "WH010", "enc": "WH010", "ciphertext": "WH010", "issuer-kind": "WH010", "missing-state": "WH010", "provisioning": "WH002", "api": "WH004"}[mode]; code != "" {
			args, _, _ := args()
			deny(args, code)
		} else {
			projected := read()
			observed, e := accepted.AdvanceKeyCopy(projected.Binding, projected.Copy, projected.Author)
			switch mode {
			case "org":
				if e != nil || projected.Author != nil {
					t.Fatal("DB org copy", e)
				}
			case "missing-cert":
				if e == nil || projected.Author.Certificate != nil || observed.Revision == 0 {
					t.Fatal("DB missing certificate", e)
				}
			case "revoked":
				if e != vault.ErrPolicy || observed.Catalog["author/"+b.UserID.String()].Revision != a.State.Sequence+1 {
					t.Fatal("copy revocation lost", e)
				}
			}
		}
		script("ROLLBACK TO SAVEPOINT copy_mutation; RELEASE SAVEPOINT copy_mutation")
	}
}
