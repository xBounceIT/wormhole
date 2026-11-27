package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresInvitationLoginIntegration(t *testing.T) {
	s, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
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
	reject := func(conn *pgconn.PgConn, sql, code string, args ...[]byte) {
		t.Helper()
		r := conn.ExecParams(ctx, sql, args, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != code {
			t.Fatalf("expected SQLSTATE %s, got %v", code, r.Err)
		}
	}
	for _, migration := range []func(string, string) (string, error){deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration, deploy.SessionProofMigration, deploy.PasswordChangeMigration, deploy.AccountKeysMigration, deploy.AccountCertificatesMigration, deploy.AccountStateMigration, deploy.TLSTrustMigration} {
		sql, err := migration("testscope", testHintID)
		if err != nil {
			t.Fatal(err)
		}
		exec(sql)
	}
	wrong, _ := deploy.InvitationLoginMigration("testscope", uuid.NewString())
	if _, err := admin.Exec(ctx, wrong).ReadAll(); err != nil {
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("wrong migration failure", err)
		}
	} else {
		t.Fatal("foreign migration accepted")
	}
	exec("ROLLBACK")
	migration, _ := deploy.InvitationLoginMigration("testscope", testHintID)
	exec(migration)
	if _, err := admin.Exec(ctx, migration).ReadAll(); err != nil {
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("wrong replay failure", err)
		}
	} else {
		t.Fatal("migration replay accepted")
	}
	exec("ROLLBACK")
	acl := admin.ExecParams(ctx, `SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_api_v1.enrollment_bootstrap(uuid)','EXECUTE')
AND NOT has_function_privilege('wh_testscope_admin','wormhole_api_v1.enrollment_bootstrap(uuid)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.enrollment_bootstrap(uuid)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`, nil, nil, nil, nil).Read()
	if acl.Err != nil || len(acl.Rows) != 1 || string(acl.Rows[0][0]) != "true" {
		t.Fatal("bootstrap ACL", acl.Err)
	}
	wrongCopies, _ := deploy.InvitationCopiesMigration("testscope", uuid.NewString())
	if _, err := admin.Exec(ctx, wrongCopies).ReadAll(); err != nil {
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("wrong copies migration failure", err)
		}
	} else {
		t.Fatal("foreign copies migration accepted")
	}
	exec("ROLLBACK")
	copiesMigration, _ := deploy.InvitationCopiesMigration("testscope", testHintID)
	exec(copiesMigration)
	if _, err := admin.Exec(ctx, copiesMigration).ReadAll(); err != nil {
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("wrong copies replay failure", err)
		}
	} else {
		t.Fatal("copies migration replay accepted")
	}
	exec("ROLLBACK")
	i, _ := enrollmentInvitationFixture(t)
	now := time.Now()
	i.WorkspaceID = uuid.MustParse(testHintID)
	i.Enrollment.Context.WorkspaceID = i.WorkspaceID
	i.ExpiresAt = now.Add(time.Hour).Unix()
	i.Endpoints, i.Database, i.TLS, i.CAPEM = s.Endpoints, s.Database, s.TLS, s.CAPEM
	user, key := i.Enrollment.Context.UserID.String(), i.Enrollment.Context.KeyID.String()
	sign := uuid.NewString()
	id := i.Enrollment.Context.InviteID.String()
	exec("INSERT INTO wormhole_data.users(id,login_name) VALUES ('" + user + "','" + i.LoginName + "'); UPDATE wormhole_data.workspace_meta SET require_tls=false")
	exec("INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,status,suite) VALUES ('" + key + "',1,'user-enc','" + user + "','pending',1),('" + sign + "',1,'user-sign','" + user + "','pending',1)")
	exec("INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision) VALUES ('" + id + "','" + user + "','invite',decode(repeat('00',32),'hex'),'" + user + "',clock_timestamp()+interval '1 hour','" + key + "',1,'" + sign + "',1,decode(repeat('00',16),'hex'),'{}'::bytea,1)")
	code := bytes.Repeat([]byte{31}, 16)
	role, verifier, err := i.EnrollmentVerifier(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	exec("SET ROLE wh_testscope_owner")
	r := admin.ExecParams(ctx, "SELECT wormhole_data.provision_invitation_login($1::uuid,$2::text)", [][]byte{[]byte(id), verifier}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != role {
		t.Fatal("provisioning", r.Err)
	}
	reject(admin, "SELECT wormhole_data.provision_invitation_login($1::uuid,$2::text)", "42710", []byte(id), verifier)
	exec("RESET ROLE")
	settings, login, err := i.EnrollmentLogin(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	conn, err := Connect(ctx, settings, login)
	if err != nil {
		t.Fatal("temporary login", err)
	}
	defer conn.Close(context.Background())
	bootstrap := func() {
		t.Helper()
		r := conn.ExecParams(ctx, "SELECT workspace_id::text,user_id::text,login_name,invite_id::text,bootstrap_key_id::text,bootstrap_key_version::text,octet_length(bootstrap_envelope)::text,manifest_revision::text FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", [][]byte{[]byte(id)}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || len(r.Rows[0]) != 8 {
			t.Fatal("bootstrap", r.Err)
		}
		want := []string{testHintID, user, i.LoginName, id, key, "1", "16", "1"}
		for n, value := range want {
			if string(r.Rows[0][n]) != value {
				t.Fatal("wrong bootstrap binding", n)
			}
		}
	}
	bootstrap()
	exec("ALTER ROLE \"" + role + "\" VALID UNTIL '2000-01-01'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("ALTER ROLE \"" + role + "\" VALID UNTIL 'infinity'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("ALTER ROLE \"" + role + "\" VALID UNTIL '" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "'; ALTER ROLE \"" + role + "\" CREATEROLE")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("ALTER ROLE \"" + role + "\" NOCREATEROLE")
	exec("UPDATE wormhole_data.invitation_logins SET role_oid=0 WHERE invite_id='" + id + "'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	reject(admin, "UPDATE wormhole_data.invites SET used_at=clock_timestamp() WHERE id=$1::uuid", "WH012", []byte(id))
	exec("UPDATE wormhole_data.invitation_logins SET role_oid=(SELECT oid FROM pg_roles WHERE rolname='" + role + "') WHERE invite_id='" + id + "'")
	for _, sql := range []string{"SELECT * FROM wormhole_data.invites", "SELECT wormhole_api_v1.session_challenge(NULL,NULL)", "SELECT wormhole_data.provision_invitation_login(NULL,NULL)", "SET ROLE wh_testscope_user", "SET ROLE wh_testscope_enroll", "CREATE TABLE denied(id int)"} {
		reject(conn, sql, "42501")
	}
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(uuid.NewString()))
	exec("UPDATE wormhole_data.workspace_meta SET require_tls=true")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH003", []byte(id))
	exec("UPDATE wormhole_data.workspace_meta SET require_tls=false; UPDATE wormhole_data.users SET disabled=true WHERE id='" + user + "'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("UPDATE wormhole_data.users SET disabled=false WHERE id='" + user + "'; UPDATE wormhole_data.invites SET attempts=5 WHERE id='" + id + "'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("UPDATE wormhole_data.invites SET attempts=0,created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id='" + id + "'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	exec("UPDATE wormhole_data.invites SET expires_at=clock_timestamp()+interval '1 hour' WHERE id='" + id + "'")
	bootstrap()
	// An accepted bootstrap read pins the invitation until transaction end.
	if _, err := conn.Exec(ctx, "BEGIN").ReadAll(); err != nil {
		t.Fatal(err)
	}
	bootstrap()
	exec("SET lock_timeout='100ms'")
	reject(admin, "UPDATE wormhole_data.invites SET used_at=clock_timestamp() WHERE id=$1::uuid", "55P03", []byte(id))
	exec("RESET lock_timeout")
	if _, err := conn.Exec(ctx, "ROLLBACK").ReadAll(); err != nil {
		t.Fatal(err)
	}
	testNativeInvitationBootstrap(t, ctx, admin, i, code)
	testNativeInvitationCopies(t, ctx, admin, i, code)
	// Consumption atomically disables new logins and rejects already-open sessions.
	exec("UPDATE wormhole_data.invites SET used_at=clock_timestamp() WHERE id='" + id + "'")
	reject(conn, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", "WH012", []byte(id))
	if other, err := Connect(ctx, settings, login); err == nil {
		_ = other.Close(context.Background())
		t.Fatal("consumed invitation authenticated")
	}
	r = admin.ExecParams(ctx, "SELECT (l.revoked AND NOT r.rolcanlogin AND NOT pg_has_role(l.role_name,'wh_testscope_user','MEMBER'))::text FROM wormhole_data.invitation_logins l JOIN pg_roles r ON r.oid=l.role_oid WHERE l.invite_id=$1::uuid", [][]byte{[]byte(id)}, nil, nil, nil).Read()
	if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
		t.Fatal("invitation retirement/privileges", r.Err)
	}
}

func testNativeInvitationBootstrap(t *testing.T, ctx context.Context, admin *pgconn.PgConn, i Invitation, code []byte) {
	t.Helper()
	b := invitationBootstrapFixture(t, i, code)
	envelope, err := EncodeInvitationBootstrapEnvelope(i, b.Envelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.EncodeInviteManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	params := [][]byte{hex.AppendEncode(nil, envelope), hex.AppendEncode(nil, manifest), []byte(strconv.FormatInt(i.ExpiresAt, 10)), []byte(i.Enrollment.Context.InviteID.String())}
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.invites SET bootstrap_envelope=decode($1,'hex'),manifest=decode($2,'hex'),expires_at=to_timestamp($3::bigint) WHERE id=$4::uuid", params, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
	s := NewSession()
	defer s.Close(context.Background())
	if err := s.OpenInvitation(ctx, i, code); err != nil {
		t.Fatal("native enrollment open", err)
	}
	fetched, err := s.InvitationBootstrap(ctx, i)
	if err != nil {
		t.Fatal("native bootstrap fetch", err)
	}
	opened, err := fetched.Authenticate(i, code, 1, time.Now())
	if err != nil {
		t.Fatal("native bootstrap authenticate", err)
	}
	opened.Wipe()
	// SQL transport cannot make a correctly shaped forged signature authentic.
	b.Manifest.Signature[0] ^= 1
	forged, _ := vault.EncodeInviteManifest(b.Manifest)
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.invites SET manifest=decode($1,'hex') WHERE id=$2::uuid", [][]byte{hex.AppendEncode(nil, forged), params[3]}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
	fetched, err = s.InvitationBootstrap(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := fetched.Authenticate(i, code, 1, time.Now()); opened != nil || err != vault.ErrAuthentication {
		t.Fatal("server signature trusted", err)
	}
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.invites SET bootstrap_envelope=decode(repeat('00',16),'hex') WHERE id=$1::uuid", [][]byte{params[3]}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
	if fetched, err := s.InvitationBootstrap(ctx, i); fetched != nil || err != ErrAdmissionResponse {
		t.Fatal("malformed bootstrap accepted", err)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("malformed response owner remains live")
	}
	if _, err := s.InvitationBootstrap(ctx, i); err != ErrSessionClosed {
		t.Fatal("malformed response owner reused", err)
	}
	if r := admin.ExecParams(ctx, "UPDATE wormhole_data.invites SET bootstrap_envelope=decode($1,'hex'),manifest=decode($2,'hex') WHERE id=$3::uuid", [][]byte{params[0], params[1], params[3]}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal(r.Err)
	}
}
