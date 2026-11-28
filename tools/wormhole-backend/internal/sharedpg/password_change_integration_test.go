package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresPasswordChangeIntegration(t *testing.T) {
	s, adminSecret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(sql string) {
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
			t.Fatalf("expected %s got %v", state, err)
		}
	}
	check := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatalf("state assertion failed: %v", r.Err)
		}
	}
	for _, generate := range []func(string, string) (string, error){deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration, deploy.SessionProofMigration} {
		sql, _ := generate("testscope", testHintID)
		exec(sql)
	}
	migration, _ := deploy.PasswordChangeMigration("testscope", testHintID)
	wrong, _ := deploy.PasswordChangeMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrong, "55000")
	exec("ROLLBACK")
	exec("CREATE TABLE wormhole_data.user_key_wraps(collision integer)")
	reject(migration, "42P07")
	exec("ROLLBACK")
	check("SELECT (schema_version=4)::text FROM wormhole_data.workspace_meta")
	exec("DROP TABLE wormhole_data.user_key_wraps")
	exec(migration)
	reject(migration, "55000")
	exec("ROLLBACK")
	accountMigration, _ := deploy.AccountKeysMigration("testscope", testHintID)
	wrongAccountMigration, _ := deploy.AccountKeysMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrongAccountMigration, "55000")
	exec("ROLLBACK")
	exec(accountMigration)
	reject(accountMigration, "55000")
	exec("ROLLBACK")
	certificateMigration, _ := deploy.AccountCertificatesMigration("testscope", testHintID)
	wrongCertificateMigration, _ := deploy.AccountCertificatesMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrongCertificateMigration, "55000")
	exec("ROLLBACK")
	exec(certificateMigration)
	reject(certificateMigration, "55000")
	exec("ROLLBACK")
	stateMigration, _ := deploy.AccountStateMigration("testscope", testHintID)
	wrongStateMigration, _ := deploy.AccountStateMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrongStateMigration, "55000")
	exec("ROLLBACK")
	exec(stateMigration)
	reject(stateMigration, "55000")
	exec("ROLLBACK")
	tlsMigration, _ := deploy.TLSTrustMigration("testscope", testHintID)
	wrongTLS, _ := deploy.TLSTrustMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(wrongTLS, "55000")
	exec("ROLLBACK")
	exec(tlsMigration)
	reject(tlsMigration, "55000")
	exec("ROLLBACK")
	ids := []string{testHintID, "22345678-1234-4234-8234-123456789abc", "32345678-1234-4234-8234-123456789abc", "42345678-1234-4234-8234-123456789abc"}
	roles := make([]string, len(ids))
	for i, id := range ids {
		roles[i] = "wh_testscope_d_" + id
		exec("SET ROLE wh_testscope_owner; CREATE ROLE \"" + roles[i] + "\" LOGIN CONNECTION LIMIT 3; RESET ROLE; GRANT wh_testscope_user TO \"" + roles[i] + "\"")
	}
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + ids[0] + "','password-test'),('" + ids[3] + "','unrelated'); UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea,require_tls=false")
	for i, id := range ids {
		user := ids[0]
		if i == 3 {
			user = ids[3]
		}
		exec("INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES ('" + id + "','" + user + "','" + roles[i] + "','active')")
	}
	exec("UPDATE wormhole_data.devices SET status='revoked' WHERE id='" + ids[2] + "'; ALTER ROLE \"" + roles[2] + "\" NOLOGIN")
	const pending = "52345678-1234-4234-8234-123456789abc"
	exec("INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES ('" + pending + "','" + ids[0] + "','wh_testscope_d_" + pending + "','pending')")
	oldMaster, newMaster := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	oldMaterial, _ := vault.DeriveKey(oldMaster, nil, vault.PurposeLogin)
	defer vault.Wipe(oldMaterial)
	newMaterial, _ := vault.DeriveKey(newMaster, nil, vault.PurposeLogin)
	defer vault.Wipe(newMaterial)
	oldVerifier, _ := NewSCRAMVerifier(oldMaterial)
	defer vault.Wipe(oldVerifier)
	newVerifier, _ := NewSCRAMVerifier(newMaterial)
	defer vault.Wipe(newVerifier)
	// Cross-check SQL syntax validation against the native bounded canonical parser.
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	corpus := [][]byte{oldVerifier, newVerifier, nil, []byte("bad"), append(bytes.Clone(newVerifier), '\n')}
	for _, cost := range []string{"4095", "4096", "1000000", "1000001", "04096", "+4096"} {
		for _, saltSize := range []int{15, 16, 64, 65} {
			corpus = append(corpus, []byte("SCRAM-SHA-256$"+cost+":"+base64.StdEncoding.EncodeToString(make([]byte, saltSize))+"$"+encoded+":"+encoded))
		}
	}
	for _, key := range []string{"=", encoded[:43] + "B", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33))} {
		corpus = append(corpus, []byte("SCRAM-SHA-256$4096:"+encoded+"$"+key+":"+encoded), []byte("SCRAM-SHA-256$4096:"+encoded+"$"+encoded+":"+key))
	}
	for _, value := range corpus {
		r := admin.ExecParams(ctx, "SELECT iterations::text FROM wormhole_data.parse_scram_verifier($1)", [][]byte{value}, nil, nil, nil).Read()
		if ValidateSCRAMVerifier(value) == nil {
			if r.Err != nil || len(r.Rows) != 1 {
				t.Fatal("SQL rejected a canonical verifier")
			}
		} else {
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != "WH008" {
				t.Fatal("SQL accepted a malformed verifier")
			}
		}
	}
	oldLogin, _ := EncodeLoginSecret(oldMaterial)
	defer vault.Wipe(oldLogin)
	newLogin, _ := EncodeLoginSecret(newMaterial)
	defer vault.Wipe(newLogin)
	exec(`CREATE FUNCTION pg_temp.set_password(p_role text,p_verifier text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L',p_role,p_verifier); END $$`)
	for _, role := range roles {
		r := admin.ExecParams(ctx, "SELECT pg_temp.set_password($1,$2)", [][]byte{[]byte(role), oldVerifier}, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal("test role setup failed")
		}
	}
	r := admin.ExecParams(ctx, "INSERT INTO wormhole_data.account_auth(user_id,iterations,salt,stored_key,server_key) SELECT $1::uuid,p.* FROM wormhole_data.parse_scram_verifier($2) p", [][]byte{[]byte(ids[0]), oldVerifier}, nil, nil, nil).Read()
	if r.Err != nil {
		t.Fatal("account setup failed")
	}
	keys := &vault.UserKeys{EncryptionPrivate: NewSessionProofNonce(), SigningSeed: NewSessionProofNonce()}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.UserKeyBinding{WorkspaceID: uuid.MustParse(testHintID), UserID: uuid.MustParse(ids[0]), Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, Revision: 1}
	oldWrap, err := vault.SealUserKeys(oldMaster, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PreparePasswordChange(oldMaster, newMaster, binding, oldWrap, public)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Wipe()
	nextBinding, newWrap := prepared.binding, prepared.envelope
	newVerifier = prepared.verifier
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite) VALUES ('" + binding.Encryption.ID.String() + "',1,'user-enc','" + ids[0] + "',2),('" + binding.Signing.ID.String() + "',1,'user-sign','" + ids[0] + "',1)")
	r = admin.ExecParams(ctx, `INSERT INTO wormhole_data.user_key_wraps(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,kdf_preset,ask_required,nonce,ciphertext)
VALUES($1::uuid,$2::uuid,1,$3::uuid,1,'kdf-v1',true,decode($4,'hex'),decode($5,'hex'))`, [][]byte{[]byte(ids[0]), []byte(binding.Encryption.ID.String()), []byte(binding.Signing.ID.String()), hex.AppendEncode(nil, oldWrap.Nonce), hex.AppendEncode(nil, oldWrap.Ciphertext)}, nil, nil, nil).Read()
	if r.Err != nil {
		t.Fatal(err)
	}
	open := func(index int, material, login []byte) *Session {
		t.Helper()
		settings := s
		settings.DeviceRole = roles[index]
		native := NewSession()
		t.Cleanup(func() { _ = native.Close(context.Background()) })
		if err := native.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
			t.Fatal(err)
		}
		request := admissionRequest()
		request.DeviceID = uuid.MustParse(ids[index])
		if _, err := native.AuthenticateSession(ctx, request, material); err != nil {
			t.Fatal(err)
		}
		return native
	}
	first, second := open(0, oldMaterial, oldLogin), open(1, oldMaterial, oldLogin)
	testPostgresTLSTrustRead(t, ctx, admin, first)
	first = open(0, oldMaterial, oldLogin)
	if _, err := first.Query(ctx, "SELECT * FROM wormhole_api_v1.tls_trust_bundle(decode(repeat('00',32),'hex'))", nil); err != ErrAuthentication {
		t.Fatal("TLS capability forgery", err)
	}
	first = open(0, oldMaterial, oldLogin)
	// Recovery must use a fresh audited proof on the SAME device, not merely a
	// successful SCRAM login. Its device-row lock cannot overtake an operation
	// that already validated the old capability; afterward that capability cannot
	// submit a delayed password mutation. This is the recovery ordering barrier.
	if _, err := first.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := first.AccountKeys(ctx); err != nil {
		t.Fatal(err)
	}
	blocked := NewSession()
	t.Cleanup(func() { _ = blocked.Close(context.Background()) })
	blockedSettings := s
	blockedSettings.DeviceRole = roles[0]
	if err := blocked.Open(ctx, blockedSettings, oldLogin, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.AuthenticateSession(ctx, admissionRequest(), oldMaterial); err != ErrChangeInProgress {
		t.Fatalf("fresh proof overtook active operation: %v", err)
	}
	if err := blocked.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	superseded := first
	first = open(0, oldMaterial, oldLogin)
	if receipt, err := superseded.ChangePassword(ctx, prepared, "ui"); receipt != nil || err != ErrAuthentication {
		t.Fatalf("superseded capability changed password: %v", err)
	}
	check("SELECT (auth_epoch=1)::text FROM wormhole_data.account_auth WHERE user_id='" + ids[0] + "'")
	check("SELECT (wrap_revision=1)::text FROM wormhole_data.user_key_wraps")
	if value, err := first.AccountKeyMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("uncertified account accepted")
	}
	organisation := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
	defer vault.Wipe(organisation)
	organisationPublic := organisation.Public().(ed25519.PublicKey)
	organisationRef := vault.KeyRef{ID: uuid.New(), Version: 1}
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,suite) VALUES ('" + organisationRef.ID.String() + "',1,'org-sign',1)")
	certificates := []vault.UserKeyCertificate{
		{FormatVersion: vault.FormatVersion, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: binding.Encryption, Kind: "user-enc", Suite: 2, PublicKey: public.Encryption, Revision: 3, Signer: organisationRef},
		{FormatVersion: vault.FormatVersion, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: binding.Signing, Kind: "user-sign", Suite: 1, PublicKey: public.Signing, Revision: 3, Signer: organisationRef},
	}
	installCertificate := func(c vault.UserKeyCertificate) {
		t.Helper()
		r := admin.ExecParams(ctx, `UPDATE wormhole_data.keys SET public_key=decode($2,'hex'),cert_signer_key_id=$3::uuid,cert_signer_key_version=1,cert_revision=3,cert_signature=decode($4,'hex') WHERE key_id=$1::uuid`, [][]byte{[]byte(c.Key.ID.String()), hex.AppendEncode(nil, c.PublicKey), []byte(c.Signer.ID.String()), hex.AppendEncode(nil, c.Signature)}, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	for i, c := range certificates {
		var err error
		certificates[i], err = vault.SignUserKeyCertificate(c, organisation)
		if err != nil {
			t.Fatal(err)
		}
		installCertificate(certificates[i])
	}
	material, err := first.AccountKeyMaterial(ctx)
	if err != nil || material.EncryptionCertificate == nil || material.SigningCertificate == nil {
		t.Fatalf("certificate retrieval failed: %v", err)
	}
	openedMaterial, err := vault.OpenCertifiedUserKeys(oldMaster, binding, material.Envelope, *material.EncryptionCertificate, *material.SigningCertificate, organisationRef, organisationPublic, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial.Wipe()
	// Ordinary row mutations must not silently change the signed cert revision.
	exec("UPDATE wormhole_data.keys SET row_version=row_version+1")
	material, err = first.AccountKeyMaterial(ctx)
	if err != nil || material.EncryptionCertificate.Revision != 3 {
		t.Fatal("mutable row revision substituted for certificate revision")
	}
	for _, key := range []string{binding.Encryption.ID.String(), binding.Signing.ID.String()} {
		exec("UPDATE wormhole_data.keys SET cert_revision=NULL WHERE key_id='" + key + "'")
		if value, err := first.AccountKeyMaterial(ctx); value != nil || err != ErrAccountRevision {
			t.Fatal("missing certificate revision accepted")
		}
		exec("UPDATE wormhole_data.keys SET cert_revision=3 WHERE key_id='" + key + "'")
	}
	exec("UPDATE wormhole_data.keys SET cert_signature=decode(repeat('00',64),'hex') WHERE key_id='" + binding.Signing.ID.String() + "'")
	material, err = first.AccountKeyMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := vault.OpenCertifiedUserKeys(oldMaster, binding, material.Envelope, *material.EncryptionCertificate, *material.SigningCertificate, organisationRef, organisationPublic, 3, 3); value != nil || err != vault.ErrAuthentication {
		t.Fatal("database-forged certificate released private keys")
	}
	installCertificate(certificates[1])
	if value, err := first.AccountUnlockMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("missing signed account state accepted")
	}
	state := vault.UserKeyState{FormatVersion: 1, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Sequence: 4, Active: true, Encryption: binding.Encryption, Signing: binding.Signing, MinimumEncryptionCertificate: 3, MinimumSigningCertificate: 3, Signer: organisationRef}
	installState := func(s vault.UserKeyState) vault.UserKeyState {
		t.Helper()
		s, e := vault.SignUserKeyState(s, organisation)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := vault.EncodeUserKeyState(s)
		if e != nil {
			t.Fatal(e)
		}
		response := admin.ExecParams(ctx, `INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,$2::bigint,decode($3,'hex')) ON CONFLICT(user_id) DO UPDATE SET state_sequence=EXCLUDED.state_sequence,signed_state=EXCLUDED.signed_state`, [][]byte{[]byte(s.UserID.String()), []byte(strconv.FormatUint(s.Sequence, 10)), hex.AppendEncode(nil, raw)}, nil, nil, nil).Read()
		if response.Err != nil {
			t.Fatal(response.Err)
		}
		return s
	}
	state = installState(state)
	reject("UPDATE wormhole_data.user_key_states SET state_sequence=0", "23514")
	reject("UPDATE wormhole_data.user_key_states SET signed_state=''::bytea", "23514")
	reject("UPDATE wormhole_data.user_key_states SET signed_state=decode(repeat('00',4097),'hex')", "23514")
	check("SELECT (NOT EXISTS(SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a WHERE p.oid IN ('wormhole_api_v1.account_key_state(bytea)'::regprocedure,'wormhole_api_v1.account_unlock_material(bytea)'::regprocedure) AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text")
	stateTrust := vault.UserKeyTrust{WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Signer: organisationRef, Organisation: organisationPublic, MinimumSequence: 4, MinimumWrappingRevision: 1}
	unlockMaterial, err := first.AccountUnlockMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial, err = vault.OpenCurrentUserKeys(oldMaster, binding, unlockMaterial.Envelope, *unlockMaterial.EncryptionCertificate, *unlockMaterial.SigningCertificate, *unlockMaterial.State, stateTrust)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial.Wipe()
	if _, err := first.Query(ctx, "SELECT * FROM wormhole_data.user_key_states", nil); err != ErrQuery {
		t.Fatal("private account state table exposed")
	}
	exec("BEGIN; SELECT 1 FROM wormhole_data.user_key_states FOR UPDATE")
	if value, err := first.AccountKeyState(ctx); value != nil || err != ErrChangeInProgress {
		t.Fatal("state contention did not fail NOWAIT")
	}
	exec("ROLLBACK")
	revoked := state
	revoked.Active = false
	revoked.Sequence++
	revoked = installState(revoked)
	exec("UPDATE wormhole_data.keys SET cert_revision=NULL WHERE key_id='" + binding.Encryption.ID.String() + "'")
	readRevocation, err := first.AccountKeyState(ctx)
	if err != nil || readRevocation.Active || vault.VerifyUserKeyState(*readRevocation, stateTrust) != nil {
		t.Fatal("revocation unavailable without certificates")
	}
	if value, err := first.AccountUnlockMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("missing certificates silently bypassed")
	}
	stateTrust.MinimumSequence = revoked.Sequence
	if err := vault.VerifyUserKeyState(state, stateTrust); err != vault.ErrRollback {
		t.Fatal("previous active state replayed")
	}
	exec("UPDATE wormhole_data.keys SET cert_revision=3 WHERE key_id='" + binding.Encryption.ID.String() + "'")
	state.Sequence = 6
	state = installState(state)
	stateTrust.MinimumSequence = state.Sequence
	testPostgresAccountEnrollment(t, ctx, admin, first)
	first = open(0, oldMaterial, oldLogin)
	exec("BEGIN; SELECT 1 FROM wormhole_data.keys WHERE key_id='" + binding.Encryption.ID.String() + "' FOR UPDATE")
	if value, err := first.AccountKeyMaterial(ctx); value != nil || err != ErrChangeInProgress {
		t.Fatal("contended certificate read did not fail NOWAIT")
	}
	exec("ROLLBACK")
	check("SELECT (NOT EXISTS(SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.account_key_material(bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text")
	fetched, err := first.AccountKeys(ctx)
	if err != nil || fetched.Binding != binding || fetched.KDF != vault.KDFV1 || !fetched.ASKRequired || !bytes.Equal(fetched.Envelope.Ciphertext, oldWrap.Ciphertext) || !bytes.Equal(fetched.Envelope.Nonce, oldWrap.Nonce) {
		t.Fatalf("native account wrapper retrieval failed: %v", err)
	}
	if rows, err := first.Query(ctx, accountKeysSQL, [][]byte{[]byte(strings.Repeat("00", 32))}); err != ErrAuthentication || rows != nil {
		t.Fatal("account wrapper accepted an invalid capability")
	}
	// An authentication failure deliberately invalidates the native owner.
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	first = open(0, oldMaterial, oldLogin)
	// A wrapper belonging to a different account is never a fallback for a
	// missing current-user row, even though its ciphertext is otherwise valid.
	exec("UPDATE wormhole_data.user_key_wraps SET user_id='" + ids[3] + "'")
	if value, err := first.AccountKeys(ctx); err != ErrAccountRevision || value != nil {
		t.Fatal("another user's capsule used as fallback")
	}
	exec("UPDATE wormhole_data.user_key_wraps SET user_id='" + ids[0] + "'")
	for _, key := range []string{binding.Encryption.ID.String(), binding.Signing.ID.String()} {
		exec("UPDATE wormhole_data.keys SET status='retired' WHERE key_id='" + key + "'")
		if value, err := first.AccountKeys(ctx); err != ErrAccountRevision || value != nil {
			t.Fatal("inactive account key exposed")
		}
		exec("UPDATE wormhole_data.keys SET status='active' WHERE key_id='" + key + "'")
	}
	check("SELECT (NOT EXISTS(SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.account_keys(bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text")
	var cap []byte
	if err := first.capability.With(func(value []byte) error { cap = hex.AppendEncode(nil, value); return nil }); err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(cap)
	const changeSQL = "SELECT wrap_revision::text,auth_epoch::text FROM wormhole_api_v1.change_password(decode($1,'hex'),$2::bigint,$3,decode($4,'hex'),decode($5,'hex'),$6)"
	params := [][]byte{cap, []byte("1"), newVerifier, hex.AppendEncode(nil, newWrap.Nonce), hex.AppendEncode(nil, newWrap.Ciphertext), []byte("ui")}
	change := func(values [][]byte, want error) {
		t.Helper()
		rows, err := first.Query(ctx, changeSQL, values)
		if err != want {
			t.Fatalf("password change error: got %v want %v", err, want)
		}
		if want == nil && (len(rows) != 1 || string(rows[0][0]) != "2" || string(rows[0][1]) != "2") {
			t.Fatal("wrong resulting revisions")
		}
	}
	unchanged := func() {
		t.Helper()
		check("SELECT (auth_epoch=1)::text FROM wormhole_data.account_auth WHERE user_id='" + ids[0] + "'")
		check("SELECT (wrap_revision=1 AND ask_required AND kdf_preset='kdf-v1')::text FROM wormhole_data.user_key_wraps")
		for _, role := range roles {
			r := admin.ExecParams(ctx, "SELECT (rolpassword=$2)::text FROM pg_authid WHERE rolname=$1", [][]byte{[]byte(role), oldVerifier}, nil, nil, nil).Read()
			if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
				t.Fatal("partial device password update")
			}
		}
	}
	if _, err := first.Query(ctx, "SELECT * FROM wormhole_data.user_key_wraps", nil); err != ErrQuery {
		t.Fatal("private wrappers exposed")
	}
	for _, bad := range []string{"", "private-marker", string(bytes.Replace(newVerifier, []byte("4096:"), []byte("04096:"), 1)), string(bytes.Replace(newVerifier, []byte("4096:"), []byte("4095:"), 1)), string(newVerifier) + "\n", strings.Repeat("x", 257)} {
		values := append([][]byte(nil), params...)
		values[2] = []byte(bad)
		change(values, ErrPasswordChangePayload)
	}
	for _, bad := range []struct {
		index int
		value []byte
		want  error
	}{{1, []byte("0"), ErrPasswordChangePayload}, {1, []byte("2"), ErrAccountRevision}, {3, nil, ErrPasswordChangePayload}, {4, []byte("00"), ErrPasswordChangePayload}, {5, []byte("bad"), ErrPasswordChangePayload}} {
		values := append([][]byte(nil), params...)
		values[bad.index] = bad.value
		change(values, bad.want)
	}
	unchanged()
	exec("ALTER ROLE \"" + roles[1] + "\" CREATEDB")
	change(params, ErrDeviceCredentials)
	unchanged()
	exec("ALTER ROLE \"" + roles[1] + "\" NOCREATEDB")
	exec("UPDATE wormhole_data.user_key_wraps SET wrap_revision=9223372036854775807")
	exhausted := append([][]byte(nil), params...)
	exhausted[1] = []byte("9223372036854775807")
	change(exhausted, ErrAccountRevision)
	exec("UPDATE wormhole_data.user_key_wraps SET wrap_revision=1")
	exec("UPDATE wormhole_data.keys SET owner_id='" + ids[3] + "' WHERE key_id='" + binding.Encryption.ID.String() + "'")
	if value, err := first.AccountKeys(ctx); err != ErrAccountRevision || value != nil {
		t.Fatal("wrapper with foreign key owner exposed")
	}
	change(params, ErrPasswordChangePayload)
	exec("UPDATE wormhole_data.keys SET owner_id='" + ids[0] + "' WHERE key_id='" + binding.Encryption.ID.String() + "'")
	// A late device-role failure must roll back earlier successful ALTER ROLEs.
	exec("REVOKE ADMIN OPTION FOR \"" + roles[1] + "\" FROM wh_testscope_owner")
	change(params, ErrDeviceCredentials)
	unchanged()
	exec("GRANT \"" + roles[1] + "\" TO wh_testscope_owner WITH ADMIN TRUE, SET FALSE, INHERIT FALSE")
	// Audit failure happens after role/wrapper/epoch writes: all must roll back.
	exec(`CREATE FUNCTION wormhole_data.test_fail_password_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='change_password' THEN RAISE EXCEPTION 'synthetic failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER test_fail_password_audit BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.test_fail_password_audit()`)
	change(params, ErrAuditUnavailable)
	if receipt, err := first.ChangePassword(ctx, prepared, "ui"); receipt != nil || err != ErrAuditUnavailable || first.capability == nil {
		t.Fatal("native rejection did not preserve the session")
	}
	unchanged()
	exec("DROP TRIGGER test_fail_password_audit ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.test_fail_password_audit()")
	// A concurrent account reader makes the NOWAIT upgrade refuse the change.
	if _, err := second.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	var otherCap []byte
	_ = second.capability.With(func(value []byte) error { otherCap = hex.AppendEncode(nil, value); return nil })
	defer vault.Wipe(otherCap)
	if _, err := second.Query(ctx, authenticatedSessionStartSQL, [][]byte{[]byte("1"), []byte("1.2.3"), []byte("ui"), otherCap}); err != nil {
		t.Fatal(err)
	}
	change(params, ErrChangeInProgress)
	if _, err := second.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	unchanged()
	// Explicit client rollback also restores every role and account record.
	if _, err := first.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	if receipt, err := first.ChangePassword(ctx, prepared, "ui"); receipt != nil || err != ErrConfiguration {
		t.Fatal("native password change accepted an existing transaction")
	}
	change(params, nil)
	if _, err := first.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	unchanged()
	receipt, err := first.ChangePassword(ctx, prepared, "ui")
	if err != nil || receipt == nil || receipt.WrappingRevision != 2 || receipt.AuthEpoch != 2 || first.capability != nil {
		t.Fatalf("native password change failed: %v", err)
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("old session survived committed password change")
	}
	if receipt, err := first.ChangePassword(ctx, prepared, "ui"); receipt != nil || err != ErrAuthentication {
		t.Fatal("retired session resubmitted password change")
	}
	check("SELECT (auth_epoch=2)::text FROM wormhole_data.account_auth")
	check("SELECT (wrap_revision=2 AND ask_required AND kdf_preset='kdf-v1')::text FROM wormhole_data.user_key_wraps")
	check("SELECT (count(*)=0)::text FROM wormhole_data.device_admissions")
	check("SELECT (count(*)=1)::text FROM wormhole_data.audit_log WHERE action='change_password'")
	check("SELECT (NOT rolcanlogin)::text FROM pg_roles WHERE rolname='" + roles[2] + "'")
	for i, role := range roles {
		expected := newVerifier
		if i == 3 {
			expected = oldVerifier
		}
		r := admin.ExecParams(ctx, "SELECT (rolpassword=$2)::text FROM pg_authid WHERE rolname=$1", [][]byte{[]byte(role), expected}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("incorrect role password replacement")
		}
	}
	if _, err := second.Query(ctx, authenticatedSessionStartSQL, [][]byte{[]byte("1"), []byte("1.2.3"), []byte("ui"), otherCap}); err != ErrAuthentication {
		t.Fatal("old admission survived password change")
	}
	settings := s
	settings.DeviceRole = roles[0]
	if c, err := Connect(ctx, settings, oldLogin); err != ErrAuthentication {
		if c != nil {
			_ = c.Close(ctx)
		}
		t.Fatal("old login accepted after password change")
	}
	fresh := open(0, newMaterial, newLogin)
	unlockMaterial, err = fresh.AccountUnlockMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial, err = vault.OpenCurrentUserKeys(newMaster, nextBinding, unlockMaterial.Envelope, *unlockMaterial.EncryptionCertificate, *unlockMaterial.SigningCertificate, *unlockMaterial.State, stateTrust)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial.Wipe()
	material, err = fresh.AccountKeyMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial, err = vault.OpenCertifiedUserKeys(newMaster, nextBinding, material.Envelope, *material.EncryptionCertificate, *material.SigningCertificate, organisationRef, organisationPublic, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	openedMaterial.Wipe()
	fetched, err = fresh.AccountKeys(ctx)
	if err != nil || fetched.Binding != nextBinding || !bytes.Equal(fetched.Envelope.Ciphertext, newWrap.Ciphertext) {
		t.Fatalf("updated wrapper unavailable: %v", err)
	}
	_ = fresh.Close(ctx)
	r = admin.ExecParams(ctx, "SELECT encode(nonce,'hex'),encode(ciphertext,'hex') FROM wormhole_data.user_key_wraps", nil, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 {
		t.Fatal("cannot read test wrapper")
	}
	persisted := newWrap
	persisted.Nonce, _ = hex.DecodeString(string(r.Rows[0][0]))
	persisted.Ciphertext, _ = hex.DecodeString(string(r.Rows[0][1]))
	opened, err := vault.OpenUserKeys(newMaster, nextBinding, persisted, public)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	if !bytes.Equal(opened.EncryptionPrivate, keys.EncryptionPrivate) || !bytes.Equal(opened.SigningSeed, keys.SigningSeed) {
		t.Fatal("password change rotated private keys")
	}
	if old, err := vault.OpenUserKeys(oldMaster, nextBinding, persisted, public); err == nil || old != nil {
		t.Fatal("old master opened new wrapper")
	}
}
