package sharedpg

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

func testDeviceConfirmationMigration(t *testing.T, ctx context.Context, admin *pgconn.PgConn) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	wrong, _ := deploy.DeviceConfirmationMigration("testscope", uuid.NewString())
	rejectMigration := func(sql string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("confirmation migration", err)
		}
		script("ROLLBACK")
	}
	rejectMigration(wrong)
	migration, _ := deploy.DeviceConfirmationMigration("testscope", testHintID)
	script(migration)
	rejectMigration(migration)
}

func testEnrollmentConfirmation(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session, settings Settings, login, material []byte, device uuid.UUID, certificate []byte, binding TrustBinding, pending PendingEnrollment, verified *VerifiedEnrollment) {
	t.Helper()
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	assert := func(sql string) {
		t.Helper()
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("confirmation state", r.Err)
		}
	}
	assert(`SELECT (NOT has_table_privilege('wh_testscope_user','wormhole_data.device_confirmations','SELECT,INSERT,UPDATE,DELETE')
AND NOT has_table_privilege('wh_testscope_admin','wormhole_data.device_confirmations','SELECT,INSERT,UPDATE,DELETE')
AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.confirm_enrollment(bytea,bytea)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.confirm_enrollment(bytea,bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`)
	digest := sha256.Sum256(certificate)
	unaudited, err := Connect(ctx, settings, login)
	if err != nil {
		t.Fatal(err)
	}
	r := unaudited.ExecParams(ctx, `SELECT * FROM wormhole_api_v1.confirm_enrollment(decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'))`, nil, nil, nil, nil).Read()
	var pe *pgconn.PgError
	if !errors.As(r.Err, &pe) || pe.Code != "WH007" {
		t.Fatal("SCRAM login without audited proof confirmed", r.Err)
	}
	unaudited.Close(context.Background())
	if err := native.ConfirmEnrollment(ctx, make([]byte, 32)); err != ErrAccountRevision {
		t.Fatal("wrong certificate confirmed", err)
	}
	if _, err := native.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrConfiguration {
		t.Fatal("caller transaction accepted", err)
	}
	if _, err := native.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	script("BEGIN; SELECT 1 FROM wormhole_data.devices FOR UPDATE")
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrChangeInProgress {
		t.Fatal("device lock bypass", err)
	}
	script("ROLLBACK")
	role := `"` + settings.DeviceRole + `"`
	for _, attributes := range []string{`VALID UNTIL '2000-01-01'`, `VALID UNTIL 'infinity'`, `INHERIT`} {
		script("ALTER ROLE " + role + " " + attributes)
		if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrDeviceCredentials {
			t.Fatal("unsafe temporary role confirmed", err)
		}
		script("ALTER ROLE " + role + " NOINHERIT VALID UNTIL '2099-01-01'")
	}
	script(`CREATE FUNCTION wormhole_data.fail_confirm_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$; CREATE TRIGGER fail_confirm_audit BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.fail_confirm_audit()`)
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrAuditUnavailable {
		t.Fatal("audit failure ignored", err)
	}
	assert(`SELECT (NOT EXISTS(SELECT 1 FROM wormhole_data.device_confirmations) AND (SELECT isfinite(rolvaliduntil) FROM pg_roles WHERE rolname='` + settings.DeviceRole + `'))::text`)
	script(`DROP TRIGGER fail_confirm_audit ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.fail_confirm_audit()`)
	for n := 0; n < 2; n++ {
		confirmed, err := native.ConfirmVerifiedEnrollment(ctx, binding, pending, verified)
		if err != nil {
			t.Fatal("confirmation/reconciliation", err)
		}
		state, err := confirmed.ConfirmedActivation(binding, pending)
		if err != nil || state.Enrollment == nil {
			t.Fatal("missing confirmed activation", err)
		}
	}
	assert(`SELECT ((SELECT count(*) FROM wormhole_data.device_confirmations)=1 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='confirm_enrollment')=1 AND (SELECT rolvaliduntil='infinity'::timestamptz AND rolcanlogin AND NOT rolinherit AND NOT rolcreaterole FROM pg_roles WHERE rolname='` + settings.DeviceRole + `'))::text`)
	script("UPDATE wormhole_data.device_confirmations SET role_oid=(role_oid::bigint+1)::oid")
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrDeviceCredentials {
		t.Fatal("role OID substitution", err)
	}
	script(`UPDATE wormhole_data.device_confirmations SET role_oid=(SELECT oid FROM pg_roles WHERE rolname='` + settings.DeviceRole + `')`)
	script("ALTER ROLE " + role + " VALID UNTIL '2099-01-01'")
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrDeviceCredentials {
		t.Fatal("confirmed role modified", err)
	}
	script("ALTER ROLE " + role + " VALID UNTIL 'infinity'")
	// Simulate a malformed successful response on this disposable test database.
	// The native owner must not claim confirmation or permit further operations.
	script(`CREATE OR REPLACE FUNCTION wormhole_api_v1.confirm_enrollment(p_capability bytea,p_certificate_digest bytea) RETURNS TABLE(device_id uuid,confirmed boolean) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ SELECT '` + device.String() + `'::uuid,false $$`)
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrEnrollmentConfirmationUncertain {
		t.Fatal("malformed confirmation accepted", err)
	}
	select {
	case <-native.Done():
	default:
		t.Fatal("uncertain owner retained")
	}
	if err := native.ConfirmEnrollment(ctx, digest[:]); err != ErrSessionClosed {
		t.Fatal("uncertain owner reused", err)
	}
	// Unknown failures after dispatch are also ambiguous, never a definite abort.
	script(`CREATE OR REPLACE FUNCTION wormhole_api_v1.confirm_enrollment(p_capability bytea,p_certificate_digest bytea) RETURNS TABLE(device_id uuid,confirmed boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN RAISE EXCEPTION 'test unknown failure' USING ERRCODE='XX000'; END $$`)
	retry := NewSession()
	defer retry.Close(context.Background())
	if err := retry.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	request := admissionRequest()
	request.DeviceID = device
	if _, err := retry.AuthenticateSession(ctx, request, material); err != nil {
		t.Fatal(err)
	}
	if err := retry.ConfirmEnrollment(ctx, digest[:]); err != ErrEnrollmentConfirmationUncertain {
		t.Fatal("unknown dispatch outcome", err)
	}
	select {
	case <-retry.Done():
	default:
		t.Fatal("unknown outcome owner retained")
	}
}
