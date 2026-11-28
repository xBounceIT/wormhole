package sharedpg

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresInvitationEnrollmentSCRAMIntegration(t *testing.T) {
	settings, adminSecret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Connect(ctx, settings, adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	i, _ := enrollmentInvitationFixture(t)
	now := time.Now()
	i.ExpiresAt = now.Add(time.Hour).Unix()
	i.Endpoints, i.Database, i.TLS, i.CAPEM = settings.Endpoints, settings.Database, settings.TLS, settings.CAPEM
	code := bytes.Repeat([]byte{29}, vault.InviteCodeBytes)
	role, verifier, err := i.EnrollmentVerifier(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	// Test-only DDL helper; production provisioning and enrollment grants remain
	// versioned SQL work. No credential is interpolated in Go-side SQL text.
	if _, err := admin.Exec(ctx, `CREATE FUNCTION pg_temp.create_invite_login(role_name text, verifier text) RETURNS void LANGUAGE plpgsql AS $body$
BEGIN EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L',role_name,verifier); END
$body$;
CREATE FUNCTION pg_temp.expire_invite_login(role_name text) RETURNS void LANGUAGE plpgsql AS $body$
BEGIN EXECUTE pg_catalog.format('ALTER ROLE %I VALID UNTIL %L',role_name,'2000-01-01 00:00:00+00'); END
$body$;`).ReadAll(); err != nil {
		t.Fatal(err)
	}
	if r := admin.ExecParams(ctx, "SELECT pg_temp.create_invite_login($1,$2)", [][]byte{[]byte(role), verifier}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal("cannot provision synthetic invite role")
	}
	s, login, err := i.EnrollmentLogin(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(login)
	conn, err := Connect(ctx, s, login)
	if err != nil {
		t.Fatal("enrollment SCRAM login failed")
	}
	defer conn.Close(context.Background())
	if r := conn.ExecParams(ctx, "SELECT session_user::text", nil, nil, nil, nil).Read(); r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != role {
		t.Fatal("unexpected enrollment identity")
	}
	wrong := bytes.Clone(code)
	wrong[0] ^= 1
	defer vault.Wipe(wrong)
	_, badLogin, err := i.EnrollmentLogin(wrong, now)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(badLogin)
	if rejected, err := Connect(ctx, s, badLogin); err != ErrAuthentication {
		if rejected != nil {
			_ = rejected.Close(context.Background())
		}
		t.Fatal("wrong enrollment code accepted")
	}
	if r := admin.ExecParams(ctx, "SELECT pg_temp.expire_invite_login($1)", [][]byte{[]byte(role)}, nil, nil, nil).Read(); r.Err != nil {
		t.Fatal("cannot expire synthetic invite role")
	}
	if rejected, err := Connect(ctx, s, login); err != ErrAuthentication {
		if rejected != nil {
			_ = rejected.Close(context.Background())
		}
		t.Fatal("expired enrollment role accepted")
	}
	// PostgreSQL expiry only affects new logins. Enrollment SQL must additionally
	// recheck invite expiry/use on every call, including already-open connections.
	if _, err := conn.Exec(ctx, "SELECT 1").ReadAll(); err != nil {
		t.Fatal("unexpected existing-session expiry semantics")
	}
}
