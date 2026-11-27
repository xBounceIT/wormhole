package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func TestPostgresSessionProofIntegration(t *testing.T) {
	s, secret := postgresTestCluster(t)
	adminSettings := s
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	exec := func(c *pgconn.PgConn, sql string) {
		t.Helper()
		if _, err := c.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(c *pgconn.PgConn, sql, state string) {
		t.Helper()
		_, err := c.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != state {
			t.Fatalf("expected %s got %v", state, err)
		}
	}
	for _, generate := range []func(string, string) (string, error){deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration} {
		sql, _ := generate("testscope", testHintID)
		exec(admin, sql)
	}
	role := "wh_testscope_d_" + testHintID
	exec(admin, "CREATE ROLE \""+role+"\" LOGIN CONNECTION LIMIT 3 PASSWORD '"+postgresTestVerifier(secret)+"'; GRANT wh_testscope_user TO \""+role+"\"")
	exec(admin, "INSERT INTO wormhole_data.users(id,login_name) VALUES ('"+testHintID+"','proof-test'); INSERT INTO wormhole_data.devices(id,user_id,role_name,status) VALUES ('"+testHintID+"','"+testHintID+"','"+role+"','active'); UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea,require_tls=false")
	s.DeviceRole = role
	device, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close(context.Background())
	other, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(context.Background())
	const legacyAdmit = "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui')"
	// Fixed synthetic capabilities are test data only, not live credentials.
	const admit = "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui',decode(repeat('0b',32),'hex'))"
	const otherAdmit = "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui',decode(repeat('0c',32),'hex'))"
	// Compile and exercise the old API before replacement. Cached plans must not
	// retain the old, identity-only guard after the upgrade.
	exec(device, legacyAdmit)
	migration, _ := deploy.SessionProofMigration("testscope", testHintID)
	wrong, _ := deploy.SessionProofMigration("testscope", "22345678-1234-4234-8234-123456789abc")
	reject(admin, wrong, "55000")
	exec(admin, "ROLLBACK")
	exec(admin, "CREATE TABLE wormhole_data.account_auth(collision integer)")
	reject(admin, migration, "42P07")
	exec(admin, "ROLLBACK")
	if r := admin.ExecParams(ctx, "SELECT (schema_version=3 AND to_regprocedure('wormhole_data.current_backend_start()') IS NULL)::text FROM wormhole_data.workspace_meta", nil, nil, nil, nil).Read(); r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("migration did not roll back atomically")
	}
	exec(admin, "DROP TABLE wormhole_data.account_auth")
	// A DBA-held metadata lock is enough to refuse the migration immediately.
	exec(admin, "BEGIN; SELECT * FROM wormhole_data.workspace_meta FOR UPDATE")
	locker, err := Connect(ctx, adminSettings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(context.Background())
	reject(locker, migration, "55P03")
	exec(locker, "ROLLBACK")
	exec(admin, "ROLLBACK")
	exec(admin, "BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('wormhole/schema/"+testHintID+"',0))")
	reject(locker, migration, "55P03")
	exec(locker, "ROLLBACK")
	exec(admin, "ROLLBACK")
	exec(admin, migration)
	exec(admin, `SET ROLE wh_testscope_owner;
CREATE FUNCTION wormhole_api_v1.test_active(p_capability bytea) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS 'SELECT EXISTS(SELECT 1 FROM wormhole_data.require_device(p_capability))';
GRANT EXECUTE ON FUNCTION wormhole_api_v1.test_active(bytea) TO wh_testscope_user;
RESET ROLE`)
	const active = "SELECT wormhole_api_v1.test_active(decode(repeat('0b',32),'hex'))"
	reject(admin, migration, "55000")
	exec(admin, "ROLLBACK")
	reject(device, legacyAdmit, "WH007")
	reject(device, admit, "WH007")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH007")
	for _, name := range []string{"account_auth", "session_challenges", "device_admissions"} {
		reject(device, "SELECT * FROM wormhole_data."+name, "42501")
	}
	reject(device, "SELECT wormhole_data.identify_device()", "42501")
	reject(device, "SELECT wormhole_data.current_backend_start()", "42501")
	setAccount := func(material []byte, epoch int) {
		t.Helper()
		login, _ := EncodeLoginSecret(material)
		salt := bytes.Repeat([]byte{3}, 64)
		v := buildSCRAMVerifier(login, salt)
		_, keys, _ := bytes.Cut(v, []byte("$"))
		_, keys, _ = bytes.Cut(keys, []byte("$"))
		stored, server, _ := bytes.Cut(keys, []byte(":"))
		result := admin.ExecParams(ctx, `INSERT INTO wormhole_data.account_auth(user_id,auth_epoch,iterations,salt,stored_key,server_key)
VALUES($1::uuid,$2::bigint,4096,decode($3,'hex'),decode($4,'base64'),decode($5,'base64'))
ON CONFLICT(user_id) DO UPDATE SET auth_epoch=EXCLUDED.auth_epoch,salt=EXCLUDED.salt,stored_key=EXCLUDED.stored_key,server_key=EXCLUDED.server_key`, [][]byte{[]byte(testHintID), []byte(strconv.Itoa(epoch)), []byte(hex.EncodeToString(salt)), stored, server}, nil, nil, nil).Read()
		if result.Err != nil {
			t.Fatal("test credential setup failed")
		}
	}
	material := bytes.Repeat([]byte{7}, 32)
	setAccount(material, 1)
	for _, assignment := range []string{"auth_epoch=0", "iterations=4095", "iterations=1000001", "salt=''::bytea", "stored_key=''::bytea", "server_key=''::bytea"} {
		reject(admin, "UPDATE wormhole_data.account_auth SET "+assignment, "23514")
	}
	for _, sql := range []string{
		"SELECT wormhole_data.scram_hmac(NULL,''::bytea)",
		"SELECT wormhole_data.scram_hmac(''::bytea,''::bytea)",
		"SELECT wormhole_data.scram_hmac(decode(repeat('00',32),'hex'),NULL)",
		"SELECT wormhole_data.scram_hmac(decode(repeat('00',32),'hex'),decode(repeat('00',1025),'hex'))",
	} {
		reject(admin, sql, "WH007")
	}
	challenge := func(c *pgconn.PgConn) SessionProofChallenge {
		t.Helper()
		nonce := NewSessionProofNonce()
		capability := bytes.Repeat([]byte{11}, 32)
		if c == other {
			capability = bytes.Repeat([]byte{12}, 32)
		}
		commitment := sha256.Sum256(capability)
		r := c.ExecParams(ctx, `SELECT workspace_id::text,user_id::text,device_id::text,auth_epoch::text,backend_pid::text,expires_at::text,encode(server_nonce,'hex'),encode(salt,'hex'),iterations::text FROM wormhole_api_v1.session_challenge(decode($1,'hex'),decode($2,'hex'))`, [][]byte{[]byte(hex.EncodeToString(nonce)), []byte(hex.EncodeToString(commitment[:]))}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 9 {
			t.Fatalf("challenge failed: %v", r.Err)
		}
		row := r.Rows[0]
		epoch, _ := strconv.ParseUint(string(row[3]), 10, 64)
		pid, _ := strconv.ParseInt(string(row[4]), 10, 32)
		expiry, _ := strconv.ParseInt(string(row[5]), 10, 64)
		server, _ := hex.DecodeString(string(row[6]))
		salt, _ := hex.DecodeString(string(row[7]))
		iterations, _ := strconv.Atoi(string(row[8]))
		return SessionProofChallenge{Binding: SessionProofBinding{WorkspaceID: uuid.MustParse(string(row[0])), UserID: uuid.MustParse(string(row[1])), DeviceID: uuid.MustParse(string(row[2])), Epoch: epoch, BackendPID: int32(pid), ExpiresAt: expiry, CapabilityHash: commitment}, ClientNonce: nonce, ServerNonce: server, Salt: salt, Iterations: iterations}
	}
	prove := func(c *pgconn.PgConn, challenge SessionProofChallenge, key []byte, want string) {
		t.Helper()
		p, err := ProveSession(key, challenge.Binding, challenge.ClientNonce, challenge)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Wipe()
		r := c.ExecParams(ctx, "SELECT encode(wormhole_api_v1.session_prove(decode($1,'hex')),'base64')", [][]byte{[]byte(hex.EncodeToString(p.Client))}, nil, nil, nil).Read()
		if want != "" {
			var pe *pgconn.PgError
			if !errors.As(r.Err, &pe) || pe.Code != want {
				t.Fatalf("expected %s from proof, got %v", want, r.Err)
			}
			return
		}
		if r.Err != nil || len(r.Rows) != 1 {
			t.Fatalf("proof failed: %v", r.Err)
		}
		response, err := base64.StdEncoding.DecodeString(string(r.Rows[0][0]))
		if err != nil || p.VerifyServer(response) != nil {
			t.Fatal("server signature mismatch")
		}
	}
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(NULL,decode(repeat('11',32),'hex'))", "WH007")
	reject(device, "SELECT wormhole_api_v1.session_prove(NULL)", "WH007")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(''::bytea,decode(repeat('11',32),'hex'))", "WH007")
	reject(device, "SELECT wormhole_api_v1.session_prove(''::bytea)", "WH007")
	for _, value := range []string{"NULL", "''::bytea", "decode(repeat('00',32),'hex')", "decode(repeat('11',33),'hex')"} {
		reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),"+value+")", "WH007")
	}
	for _, value := range []string{"NULL", "''::bytea", "decode(repeat('0b',31),'hex')", "decode(repeat('0b',33),'hex')"} {
		reject(device, "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui',"+value+")", "WH007")
	}
	exec(admin, "UPDATE wormhole_data.workspace_meta SET state='provisioning'")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH002")
	exec(admin, "UPDATE wormhole_data.workspace_meta SET state='ready',require_tls=true")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH003")
	exec(admin, "UPDATE wormhole_data.workspace_meta SET require_tls=false")
	c := challenge(device)
	altered := c
	altered.Binding.CapabilityHash[0] ^= 1
	prove(device, altered, material, "WH007")
	prove(other, c, material, "WH007") // Same role, different connection.
	prove(device, c, bytes.Repeat([]byte{8}, 32), "WH007")
	prove(device, c, material, "")
	reject(device, active, "WH007") // Proof alone must not bypass audited admission.
	for _, sql := range []string{
		"SELECT * FROM wormhole_api_v1.session_start(1,'bad','ui',decode(repeat('0b',32),'hex'))",
		"SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','bad',decode(repeat('0b',32),'hex'))",
		"SELECT * FROM wormhole_api_v1.session_start(NULL,'1.2.3','ui',decode(repeat('0b',32),'hex'))",
	} {
		reject(device, sql, "22023")
	}
	reject(device, "SELECT * FROM wormhole_api_v1.session_start(2,'1.2.3','ui',decode(repeat('0b',32),'hex'))", "WH004")
	exec(admin, "UPDATE wormhole_data.workspace_meta SET state='provisioning'")
	reject(device, admit, "WH002")
	exec(admin, "UPDATE wormhole_data.workspace_meta SET state='ready',require_tls=true")
	reject(device, admit, "WH003")
	exec(admin, "UPDATE wormhole_data.workspace_meta SET require_tls=false")
	exec(admin, `CREATE FUNCTION wormhole_data.test_audit_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit error'; END $$;
CREATE TRIGGER test_audit_fail BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.test_audit_fail()`)
	reject(device, admit, "WH005")
	reject(device, active, "WH007")
	if r := admin.ExecParams(ctx, "SELECT (count(*)=1)::text FROM wormhole_data.sessions", nil, nil, nil, nil).Read(); r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("failed audit leaked a session row")
	}
	exec(admin, "DROP TRIGGER test_audit_fail ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.test_audit_fail()")
	exec(device, admit)
	exec(device, active)
	prove(device, c, material, "WH007") // Consumed challenge.
	reject(other, otherAdmit, "WH007")
	// Model a pooler routing the legitimate logical client to a different backend.
	exec(other, admit)
	// And routing an unauthenticated logical client to the previously admitted one.
	reject(device, otherAdmit, "WH007")
	reject(device, legacyAdmit, "WH007")
	// A hash commitment is not itself a bearer credential.
	reject(device, "SELECT * FROM wormhole_api_v1.session_start(1,'1.2.3','ui',sha256(decode(repeat('0b',32),'hex')))", "WH007")
	// A fresh challenge cannot evict the already-admitted query connection.
	c = challenge(other)
	exec(device, admit)
	prove(other, c, material, "")
	reject(other, "SELECT wormhole_api_v1.test_active(decode(repeat('0c',32),'hex'))", "WH007")
	exec(other, otherAdmit)
	reject(device, admit, "WH007")
	c = challenge(device)
	exec(admin, "UPDATE wormhole_data.session_challenges SET expires_at=1")
	prove(device, c, material, "WH007")
	c = challenge(device)
	exec(admin, "UPDATE wormhole_data.session_challenges SET backend_start=backend_start-interval '1 second'")
	prove(device, c, material, "WH007")
	c = challenge(device)
	_ = challenge(device)
	prove(device, c, material, "WH007") // Replaced challenge.
	c = challenge(device)
	next := bytes.Repeat([]byte{9}, 32)
	setAccount(next, 2)
	prove(device, c, material, "WH007") // Current epoch changed after challenge.
	reject(other, otherAdmit, "WH007")  // Existing admission lost authority.
	c = challenge(device)
	prove(device, c, material, "WH007") // Pre-opened connection cannot re-admit.
	prove(device, c, next, "")
	exec(device, admit)
	exec(admin, "UPDATE wormhole_data.device_admissions SET capability_hash=decode(repeat('ff',32),'hex')")
	reject(device, admit, "WH007")
	c = challenge(device)
	prove(device, c, next, "")
	// Proof/admission replacement is transactional. Rollback restores the prior
	// admitted connection and the outstanding challenge, not a partial admission.
	c = challenge(other)
	exec(other, "BEGIN")
	prove(other, c, next, "")
	exec(other, "ROLLBACK")
	exec(device, admit)
	reject(other, otherAdmit, "WH007")
	// Admission protects the account row until the surrounding transaction ends.
	exec(device, "BEGIN")
	exec(device, admit)
	reject(admin, "SELECT * FROM wormhole_data.account_auth FOR UPDATE NOWAIT", "55P03")
	exec(device, "ROLLBACK")
	exec(admin, "UPDATE wormhole_data.account_auth SET auth_epoch=3")
	reject(device, admit, "WH007")
	// Exercise the production Go owner, not only individual SQL calls. Its whole
	// exchange is one short transaction and its capability remains native-owned.
	for _, good := range []bool{false, true} {
		native := NewSession()
		if err := native.Open(ctx, s, secret, ChangePolicy{TransactionPooler: true}); err != nil {
			t.Fatal(err)
		}
		key := material
		if good {
			key = next
		}
		response, err := native.AuthenticateSession(ctx, admissionRequest(), key)
		if !good {
			if err != ErrAuthentication || response != nil || native.capability != nil {
				t.Fatal("old credential admitted by native owner")
			}
		} else {
			if err != nil || response == nil || native.capability == nil {
				t.Fatalf("native admission failed: %v", err)
			}
			var capability []byte
			if err := native.capability.With(func(value []byte) error { capability = hex.AppendEncode(nil, value); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := native.Query(ctx, "SELECT wormhole_api_v1.test_active(decode($1,'hex'))", [][]byte{capability}); err != nil {
				t.Fatal(err)
			}
			exec(admin, "UPDATE wormhole_data.account_auth SET auth_epoch=4")
			if _, err := native.Query(ctx, "SELECT wormhole_api_v1.test_active(decode($1,'hex'))", [][]byte{capability}); err != ErrAuthentication {
				t.Fatal("old native admission survived epoch change")
			}
			clear(capability)
			select {
			case <-native.Done():
			default:
				t.Fatal("epoch change did not invalidate native owner")
			}
		}
		if err := native.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if native.capability != nil {
			t.Fatal("native capability retained after close")
		}
	}
	blocked := NewSession()
	defer blocked.Close(context.Background())
	if err := blocked.Open(ctx, s, secret, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	exec(admin, "BEGIN; LOCK TABLE wormhole_data.account_auth IN ACCESS EXCLUSIVE MODE")
	finished := make(chan error, 1)
	go func() {
		response, err := blocked.AuthenticateSession(ctx, admissionRequest(), next)
		if response != nil || err == nil {
			finished <- errors.New("cancelled exchange returned admission")
			return
		}
		finished <- err
	}()
	waiting := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		r := locker.ExecParams(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock')::text", [][]byte{[]byte(role)}, nil, nil, nil).Read()
		if r.Err != nil {
			t.Fatal(r.Err)
		}
		if len(r.Rows) == 1 && string(r.Rows[0][0]) == "true" {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("native exchange did not reach the controlled database wait")
	}
	if err := blocked.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
	if blocked.capability != nil {
		t.Fatal("cancelled exchange retained capability")
	}
	exec(admin, "ROLLBACK")
	exec(device, "BEGIN ISOLATION LEVEL REPEATABLE READ")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH006")
	exec(device, "ROLLBACK")
	exec(admin, "UPDATE wormhole_data.users SET disabled=true")
	reject(device, admit, "WH001")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH001")
	exec(admin, "UPDATE wormhole_data.users SET disabled=false; UPDATE wormhole_data.devices SET status='revoked'")
	reject(device, "SELECT wormhole_api_v1.session_prove(decode(repeat('00',32),'hex'))", "WH001")
	exec(admin, "UPDATE wormhole_data.devices SET status='active'; ALTER ROLE \""+role+"\" NOLOGIN")
	reject(device, admit, "WH001")
	reject(device, "SELECT * FROM wormhole_api_v1.session_challenge(decode(repeat('00',32),'hex'),decode(repeat('11',32),'hex'))", "WH001")
}
