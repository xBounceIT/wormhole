package sharedpg

import (
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

func testNativeInvitationCertification(t *testing.T, ctx context.Context, admin *pgconn.PgConn, i Invitation, code []byte, certificate vault.UserEnrollmentCertificate, trust vault.UserKeyTrust) {
	t.Helper()
	testDeviceConfirmationMigration(t, ctx, admin)
	script := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if r := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	rejectMigration := func(sql string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("certification migration", err)
		}
		script("ROLLBACK")
	}
	wrong, _ := deploy.InvitationCertificationMigration("testscope", uuid.NewString())
	rejectMigration(wrong)
	migration, _ := deploy.InvitationCertificationMigration("testscope", i.WorkspaceID.String())
	script(migration)
	rejectMigration(migration)
	acl := admin.ExecParams(ctx, `SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_api_v1.enrollment_certification(uuid,bigint,bytea)','EXECUTE')
AND NOT has_function_privilege('wh_testscope_admin','wormhole_api_v1.enrollment_certification(uuid,bigint,bytea)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.enrollment_certification(uuid,bigint,bytea)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`, nil, nil, nil, nil).Read()
	if acl.Err != nil || len(acl.Rows) != 1 || string(acl.Rows[0][0]) != "true" {
		t.Fatal("certification ACL", acl.Err)
	}
	profile := certificationProfile(t, i.WorkspaceID, trust.Signer)
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')`, hex.AppendEncode(nil, profile))
	native := NewSession()
	defer native.Close(context.Background())
	if err := native.OpenInvitation(ctx, i, code); err != nil {
		t.Fatal(err)
	}
	if _, err := native.InvitationCertification(ctx, i, certificate.Manifest); err != ErrAccountRevision {
		t.Fatal("missing cert accepted", err)
	}
	for _, c := range []vault.UserKeyCertificate{certificate.BootstrapEncryption, certificate.BootstrapSigning} {
		exec(`UPDATE wormhole_data.keys SET public_key=decode($2,'hex'),cert_signer_key_id=$3::uuid,cert_signer_key_version=$4::integer,cert_revision=$5::bigint,cert_signature=decode($6,'hex') WHERE key_id=$1::uuid`, []byte(c.Key.ID.String()), hex.AppendEncode(nil, c.PublicKey), []byte(c.Signer.ID.String()), []byte(strconv.FormatUint(uint64(c.Signer.Version), 10)), []byte(strconv.FormatUint(c.Revision, 10)), hex.AppendEncode(nil, c.Signature))
	}
	got, err := native.InvitationCertification(ctx, i, certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	policy, accountTrust, err := got.Verify(i, trust.Organisation, certificate.Manifest, 1, 1, 1, time.Now())
	if err != nil || policy.Profile != vault.Standard || accountTrust.Signer != trust.Signer {
		t.Fatal("native certification", err)
	}
	prepared, err := vault.PrepareUserEnrollmentCertificate(vault.UserEnrollmentCertificate{FormatVersion: 1, Manifest: certificate.Manifest, BootstrapEncryption: got.Encryption, BootstrapSigning: got.Signing, Rekey: certificate.Rekey}, i.Enrollment.Context, got.State, accountTrust, 1, time.Now())
	if err != nil || prepared.Rekey.EncryptionKeyID != certificate.Rekey.EncryptionKeyID {
		t.Fatal("certification did not prepare final chain", err)
	}
	stale := certificate.Manifest
	stale.Revision++
	if _, err := native.InvitationCertification(ctx, i, stale); err != ErrInvitation {
		t.Fatal("manifest pin ignored", err)
	}
	script("BEGIN; SELECT 1 FROM wormhole_data.user_key_states FOR UPDATE")
	if _, err := native.InvitationCertification(ctx, i, certificate.Manifest); err != ErrChangeInProgress {
		t.Fatal("state contention", err)
	}
	script("ROLLBACK")
	signed, err := vault.DecodeSignedPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature[0] ^= 1
	forged, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')`, hex.AppendEncode(nil, forged))
	got, err = native.InvitationCertification(ctx, i, certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := got.Verify(i, trust.Organisation, certificate.Manifest, 1, 1, 1, time.Now()); err == nil {
		t.Fatal("forged server policy trusted")
	}
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile='{}'::bytea`)
	if _, err := native.InvitationCertification(ctx, i, certificate.Manifest); err != ErrAdmissionResponse {
		t.Fatal("malformed policy accepted", err)
	}
	select {
	case <-native.Done():
	default:
		t.Fatal("malformed certification owner retained")
	}
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')`, hex.AppendEncode(nil, profile))
}
