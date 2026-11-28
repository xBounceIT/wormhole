package sharedpg

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Shares an already authenticated device fixture with password-change tests so
// enrollment retrieval exercises exactly the same admission and epoch boundary.
func testPostgresAccountEnrollment(t *testing.T, ctx context.Context, admin *pgconn.PgConn, native *Session) {
	t.Helper()
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	for _, generate := range []func(string, string) (string, error){deploy.InvitationLoginMigration, deploy.InvitationCopiesMigration} {
		sql, err := generate("testscope", testHintID)
		if err != nil {
			t.Fatal(err)
		}
		script(sql)
	}
	migration, err := deploy.AccountEnrollmentMigration("testscope", testHintID)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := deploy.AccountEnrollmentMigration("testscope", uuid.NewString())
	rejectMigration := func(sql string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("migration identity/replay", err)
		}
		script("ROLLBACK")
	}
	rejectMigration(wrong)
	script(migration)
	rejectMigration(migration)
	acl := admin.ExecParams(ctx, `SELECT (
NOT has_table_privilege('wh_testscope_user','wormhole_data.user_enrollments','SELECT,INSERT,UPDATE,DELETE')
AND NOT has_table_privilege('wh_testscope_admin','wormhole_data.user_enrollments','SELECT,INSERT,UPDATE,DELETE')
AND NOT has_table_privilege('wh_testscope_enroll','wormhole_data.user_enrollments','SELECT,INSERT,UPDATE,DELETE')
AND NOT has_function_privilege('wh_testscope_enroll','wormhole_api_v1.account_enrollment_material(bytea)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.account_enrollment_material(bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`, nil, nil, nil, nil).Read()
	if acl.Err != nil || len(acl.Rows) != 1 || string(acl.Rows[0][0]) != "true" {
		t.Fatal("enrollment ACL", acl.Err)
	}
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("missing enrollment", err)
	}
	rows, trust, master := accountEnrollmentRows(t)
	parsed, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	user := []byte(parsed.Binding.UserID.String())
	enc := []byte(parsed.Binding.Encryption.ID.String())
	sign := []byte(parsed.Binding.Signing.ID.String())
	// Save and restore this synthetic account, so existing password-change tests
	// continue to exercise their original direct organisation certificates.
	script("CREATE TEMP TABLE enrollment_saved_wrap AS TABLE wormhole_data.user_key_wraps; CREATE TEMP TABLE enrollment_saved_state AS TABLE wormhole_data.user_key_states")
	exec(`UPDATE wormhole_data.keys SET status='retired' WHERE owner_id=$1::uuid AND kind IN ('user-enc','user-sign') AND status='active'`, user)
	exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite) VALUES($1::uuid,1,'user-enc',$3::uuid,2),($2::uuid,1,'user-sign',$3::uuid,1)`, enc, sign, user)
	exec(`UPDATE wormhole_data.user_key_wraps SET encryption_key_id=$2::uuid,signing_key_id=$3::uuid,nonce=decode($4,'hex'),ciphertext=decode($5,'hex') WHERE user_id=$1::uuid`, user, enc, sign, rows[0][9], rows[0][10])
	exec(`UPDATE wormhole_data.user_key_states SET signed_state=decode($2,'hex'),state_sequence=1 WHERE user_id=$1::uuid`, user, rows[0][12])
	exec(`INSERT INTO wormhole_data.user_enrollments(user_id,encryption_key_id,encryption_key_version,signing_key_id,signing_key_version,certificate) VALUES($1::uuid,$2::uuid,1,$3::uuid,1,decode($4,'hex'))`, user, enc, sign, rows[0][14])
	for _, sql := range []string{
		`UPDATE wormhole_data.user_enrollments SET certificate=''::bytea`,
		`UPDATE wormhole_data.user_enrollments SET certificate=decode(repeat('00',1064961),'hex')`,
		`UPDATE wormhole_data.user_enrollments SET signing_key_id=encryption_key_id`,
	} {
		r := admin.ExecParams(ctx, sql, nil, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != "23514" {
			t.Fatal("enrollment constraint", r.Err)
		}
	}
	material, err := native.AccountEnrollmentMaterial(ctx)
	if err != nil {
		t.Fatal("native enrollment retrieval", err)
	}
	keys, err := vault.OpenEnrolledUserKeys(master, material.Binding, material.Envelope, *material.EnrollmentCertificate, *material.State, trust, 1)
	if err != nil {
		t.Fatal("native chain unlock", err)
	}
	keys.Wipe()
	// The legacy endpoint must not reinterpret a bootstrap-signed key as org-signed.
	if value, err := native.AccountUnlockMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("legacy certification bypass", err)
	}
	script("BEGIN; SELECT 1 FROM wormhole_data.user_enrollments FOR UPDATE")
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrChangeInProgress {
		t.Fatal("enrollment lock bypass", err)
	}
	script("ROLLBACK")
	exec(`UPDATE wormhole_data.user_enrollments SET encryption_key_id=(SELECT encryption_key_id FROM enrollment_saved_wrap WHERE user_id=$1::uuid) WHERE user_id=$1::uuid`, user)
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("mixed committed selection", err)
	}
	exec(`UPDATE wormhole_data.user_enrollments SET encryption_key_id=$2::uuid WHERE user_id=$1::uuid`, user, enc)
	exec(`UPDATE wormhole_data.keys SET status='retired' WHERE key_id=$1::uuid`, sign)
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrAccountRevision {
		t.Fatal("revoked final key", err)
	}
	exec(`UPDATE wormhole_data.keys SET status='active' WHERE key_id=$1::uuid`, sign)
	c := *material.EnrollmentCertificate
	c.Rekey.Signature[0] ^= 1
	raw, err := vault.EncodeUserEnrollmentCertificate(c)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE wormhole_data.user_enrollments SET certificate=decode($2,'hex') WHERE user_id=$1::uuid`, user, hex.AppendEncode(nil, raw))
	material, err = native.AccountEnrollmentMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := vault.OpenEnrolledUserKeys(master, material.Binding, material.Envelope, *material.EnrollmentCertificate, *material.State, trust, 1); keys != nil || err != vault.ErrAuthentication {
		t.Fatal("server-forged chain", err)
	}
	exec(`UPDATE wormhole_data.user_enrollments SET certificate='{}'::bytea WHERE user_id=$1::uuid`, user)
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrAdmissionResponse {
		t.Fatal("malformed chain", err)
	}
	select {
	case <-native.Done():
	default:
		t.Fatal("malformed enrollment did not retire session")
	}
	if value, err := native.AccountEnrollmentMaterial(ctx); value != nil || err != ErrSessionClosed {
		t.Fatal("malformed enrollment session reused", err)
	}
	script(`BEGIN;
DELETE FROM wormhole_data.user_enrollments;
DELETE FROM wormhole_data.user_key_wraps;
INSERT INTO wormhole_data.user_key_wraps SELECT * FROM enrollment_saved_wrap;
DELETE FROM wormhole_data.user_key_states;
INSERT INTO wormhole_data.user_key_states SELECT * FROM enrollment_saved_state;
COMMIT;`)
	exec(`DELETE FROM wormhole_data.keys WHERE key_id IN ($1::uuid,$2::uuid)`, enc, sign)
	script(`UPDATE wormhole_data.keys k SET status='active' FROM enrollment_saved_wrap w WHERE (k.key_id=w.encryption_key_id AND k.key_version=w.encryption_key_version) OR (k.key_id=w.signing_key_id AND k.key_version=w.signing_key_version)`)
}
