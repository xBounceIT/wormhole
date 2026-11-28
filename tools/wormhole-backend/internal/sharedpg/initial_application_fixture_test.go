package sharedpg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Test-only process protocol: public invitation out, verify/stop command in.
// The synthetic separately delivered code is fixed in the protected UI test;
// neither database credentials nor account material leave this fixture.
func TestPostgresInitialApplicationFixture(t *testing.T) {
	if os.Getenv("WORMHOLE_TEST_INITIAL_APPLICATION") != "1" {
		t.Skip("subprocess fixture for protected application enrollment")
	}
	tlsMode := os.Getenv("WORMHOLE_TEST_INITIAL_TLS")
	if tlsMode != "" && tlsMode != "off" && tlsMode != "encrypted" && tlsMode != "verified" {
		t.Fatal("invalid fixture TLS mode")
	}
	s, secret := postgresTestClusterTLS(t, tlsMode == "verified" || tlsMode == "encrypted")
	if tlsMode == "encrypted" {
		s.TLS, s.CAPEM = TLSEncrypted, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	i := seedInitialApplicationInvitation(t, ctx, admin, s)
	token, err := EncodeInvitation(i, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"invitation": token}); err != nil {
		t.Fatal("public fixture reply unavailable")
	}
	input := bufio.NewReaderSize(os.Stdin, 64)
	command, err := input.ReadSlice('\n')
	if err == nil && string(command) == "rotate-untrusted-ca\n" {
		if s.TLS != TLSVerified {
			t.Fatal("TLS rotation requires a verified fixture")
		}
		rotateInitialApplicationFixtureCA(t, ctx, admin, s, secret)
		if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"rotated": true}); err != nil {
			t.Fatal("rotation reply unavailable")
		}
		command, err = input.ReadSlice('\n')
	}
	if err != nil || string(command) == "stop\n" {
		return // parent failure/EOF still runs confirmed cluster cleanup
	}
	if string(command) == "verify-unused\n" {
		rows := admin.ExecParams(ctx, `SELECT (
 (SELECT used_at IS NULL AND bootstrap_envelope IS NOT NULL FROM wormhole_data.invites WHERE id=$1::uuid)
 AND NOT EXISTS(SELECT 1 FROM wormhole_data.devices)
 AND NOT EXISTS(SELECT 1 FROM wormhole_data.user_enrollments)
 AND NOT EXISTS(SELECT 1 FROM wormhole_data.user_key_wraps)
 AND NOT EXISTS(SELECT 1 FROM wormhole_data.audit_log WHERE action='join_workspace')
 AND (SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$2)
)::text`, [][]byte{[]byte(i.Enrollment.Context.InviteID.String()), []byte("wh_testscope_i_" + i.Enrollment.Context.InviteID.String())}, nil, nil, nil).Read()
		if rows.Err != nil || len(rows.Rows) != 1 || string(rows.Rows[0][0]) != "true" {
			t.Fatal("rejected enrollment attempt changed account/device state", rows.Err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"unused": true}); err != nil {
			t.Fatal("unused confirmation unavailable")
		}
		return
	}
	if string(command) != "verify\n" {
		t.Fatal("invalid fixture command")
	}
	askRequired := os.Getenv("WORMHOLE_TEST_INITIAL_ACCOUNT_ASK") == "1"
	preset := vault.KDFLow
	if os.Getenv("WORMHOLE_TEST_INITIAL_PROFILE") == "standard" || os.Getenv("WORMHOLE_TEST_INITIAL_ASK") == "1" {
		preset = vault.KDFV1
	}
	rows := admin.ExecParams(ctx, `SELECT (
 (SELECT used_at IS NOT NULL AND bootstrap_envelope IS NULL FROM wormhole_data.invites WHERE id=$1::uuid)
 AND (SELECT count(*) FROM wormhole_data.devices WHERE status='active')=1
 AND (SELECT count(*) FROM wormhole_data.device_confirmations c
      JOIN wormhole_data.devices d ON d.id=c.device_id
      JOIN pg_catalog.pg_roles r ON r.rolname=d.role_name AND r.oid=c.role_oid
      JOIN wormhole_data.user_enrollments e ON e.user_id=d.user_id
      WHERE r.rolcanlogin AND r.rolvaliduntil='infinity'::timestamptz
        AND c.certificate_digest=pg_catalog.sha256(e.certificate))=1
 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='join_workspace')=1
 AND (SELECT count(*) FROM wormhole_data.user_key_wraps
      WHERE user_id=(SELECT user_id FROM wormhole_data.invites WHERE id=$1::uuid)
        AND ask_required=$3::boolean AND kdf_preset=$4)=1
 AND NOT (SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$2)
)::text`, [][]byte{[]byte(i.Enrollment.Context.InviteID.String()), []byte("wh_testscope_i_" + i.Enrollment.Context.InviteID.String()), []byte(strconv.FormatBool(askRequired)), []byte(preset)}, nil, nil, nil).Read()
	if rows.Err != nil || len(rows.Rows) != 1 || string(rows.Rows[0][0]) != "true" {
		t.Fatal("initial application enrollment was not independently confirmed", rows.Err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]bool{"confirmed": true}); err != nil {
		t.Fatal("fixture confirmation unavailable")
	}
}

// Change the server identity without changing the original invite/checkpoint.
// Prove the reload with a new verified connection before the client is tested.
func rotateInitialApplicationFixtureCA(t *testing.T, ctx context.Context, admin *pgconn.PgConn, s Settings, secret []byte) {
	t.Helper()
	data := postgresFixtureDataDirectory(t, ctx, admin)
	s.CAPEM = postgresTestCertificate(t, data)
	reloadPostgresFixtureTLS(t, ctx, admin, s, secret)
}

func postgresFixtureDataDirectory(t *testing.T, ctx context.Context, admin *pgconn.PgConn) string {
	t.Helper()
	rows := admin.ExecParams(ctx, `SELECT current_setting('data_directory')`, nil, nil, nil, nil).Read()
	if rows.Err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatal("fixture data directory unavailable")
	}
	data := filepath.Clean(string(rows.Rows[0][0]))
	root := filepath.Clean(os.Getenv("WORMHOLE_TEST_POSTGRES_SCRATCH"))
	relative, err := filepath.Rel(root, data)
	if err != nil || !filepath.IsAbs(root) || !filepath.IsAbs(data) || !filepath.IsLocal(relative) || filepath.Base(data) != "data" {
		t.Fatal("unexpected fixture data directory")
	}
	return data
}

func reloadPostgresFixtureTLS(t *testing.T, ctx context.Context, admin *pgconn.PgConn, s Settings, secret []byte) {
	t.Helper()
	if _, err := admin.Exec(ctx, `SELECT pg_reload_conf()`).ReadAll(); err != nil {
		t.Fatal("fixture reload unavailable", err)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		connection, err := Connect(wait, s, secret)
		if err == nil {
			if err := connection.Close(wait); err != nil {
				t.Fatal("rotated fixture verification cleanup", err)
			}
			return
		}
		select {
		case <-wait.Done():
			t.Fatal("fixture did not load the new TLS identity")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func seedInitialApplicationInvitation(t *testing.T, ctx context.Context, admin *pgconn.PgConn, s Settings) Invitation {
	t.Helper()
	for _, generate := range []func(string, string) (string, error){
		deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration,
		deploy.SessionProofMigration, deploy.PasswordChangeMigration, deploy.AccountKeysMigration,
		deploy.AccountCertificatesMigration, deploy.AccountStateMigration, deploy.TLSTrustMigration,
		deploy.InvitationLoginMigration, deploy.InvitationCopiesMigration, deploy.AccountEnrollmentMigration,
		deploy.InvitationCommitMigration, deploy.DeviceConfirmationMigration, deploy.InvitationCertificationMigration,
		deploy.NodePermissionsMigration, deploy.TreeSnapshotMigration, deploy.NodeAuthorMigration, deploy.CatalogChangesMigration,
		deploy.UseIntentsMigration, deploy.UseConsumptionMigration, deploy.ResolverMigration, deploy.ResolutionChainMigration,
		deploy.CredentialSlotsMigration, deploy.CredentialCatalogMigration, deploy.CredentialProjectionMigration, deploy.SelectionProjectionMigration,
		deploy.ConnectionResolutionMigration, deploy.BoundaryPermissionsMigration, deploy.BoundaryManifestsMigration, deploy.ConnectionSnapshotMigration,
		deploy.CredentialValuesMigration, deploy.KeyCopyProjectionMigration, deploy.CredentialReleaseGraphMigration, deploy.FetchSecretMigration,
		deploy.ReleasePolicyMigration, deploy.ConnectionPlanMigration, deploy.RuntimeStateMigration, deploy.NodeSecretManifestsMigration,
		deploy.TunnelProfilesMigration, deploy.FortinetIPsecMigration, deploy.EnrolledCatalogAuthorsMigration, deploy.TunnelFallbackMigration,
	} {
		sql, err := generate("testscope", testHintID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, sql).ReadAll(); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...[]byte) {
		t.Helper()
		if result := admin.ExecParams(ctx, sql, args, nil, nil, nil).Read(); result.Err != nil {
			t.Fatal(result.Err)
		}
	}
	code := bytes.Repeat([]byte{31}, vault.InviteCodeBytes)
	defer vault.Wipe(code)
	var bootstrap vault.Envelope
	rows, trust, _ := accountEnrollmentRowsWithBootstrap(t, func(binding vault.InviteContext, opened *vault.InviteBootstrap) {
		var err error
		bootstrap, err = vault.SealInviteBootstrap(code, binding, opened)
		if err != nil {
			t.Fatal(err)
		}
	})
	account, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	defer wipeQueryRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	certificate := *account.EnrollmentCertificate
	org := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer vault.Wipe(org)
	certificate.Manifest.ExpiresAt = time.Now().Add(time.Hour).Unix()
	certificate.Manifest, err = vault.SignInviteManifest(certificate.Manifest, org[:ed25519.SeedSize])
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.EncodeInviteManifest(certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(trust.Organisation)
	i := Invitation{FormatVersion: 2, WorkspaceID: trust.WorkspaceID, LoginName: certificate.Manifest.Context.LoginName,
		Endpoints: s.Endpoints, Database: s.Database, TLS: s.TLS, CAPEM: s.CAPEM,
		OrganisationFingerprint: fingerprint[:], ExpiresAt: certificate.Manifest.ExpiresAt,
		Enrollment: &InvitationEnrollment{RoleTag: "testscope", Context: certificate.Manifest.Context}}
	profile := vault.Default
	switch os.Getenv("WORMHOLE_TEST_INITIAL_PROFILE") {
	case "", "default":
	case "standard":
		profile = vault.Standard
	default:
		t.Fatal("invalid application fixture profile")
	}
	askRequired := os.Getenv("WORMHOLE_TEST_INITIAL_ASK") == "1"
	policyValue := vault.Policy{FormatVersion: 1, WorkspaceID: i.WorkspaceID.String(), Sequence: 1,
		Profile: profile, KDF: vault.KDFLow, LowKDFApproved: true, ASKRequired: askRequired, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	if profile == vault.Standard || askRequired {
		policyValue.KDF, policyValue.LowKDFApproved = vault.KDFV1, false
	}
	if profile == vault.Standard && s.TLS != TLSVerified {
		t.Fatal("Standard fixture requires verified TLS")
	}
	signed, err := vault.SignPolicy(policyValue, trust.Signer.ID.String(), trust.Signer.Version, org)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	user := []byte(i.Enrollment.Context.UserID.String())
	exec(`INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,$2)`, user, []byte(i.LoginName))
	exec(`UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile=decode($1,'hex'),require_tls=$2::boolean`, hex.AppendEncode(nil, policy), []byte(strconv.FormatBool(s.TLS != TLSOff)))
	exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,suite,public_key) VALUES($1::uuid,1,'org-sign',1,decode($2,'hex'))`, []byte(trust.Signer.ID.String()), hex.AppendEncode(nil, trust.Organisation))
	if os.Getenv("WORMHOLE_TEST_INITIAL_SIGNED_TLS") == "1" {
		if s.TLS != TLSVerified {
			t.Fatal("signed TLS fixture requires Verified")
		}
		block, rest := pem.Decode(s.CAPEM)
		if block == nil || len(rest) != 0 {
			t.Fatal("invalid fixture CA")
		}
		value := TLSTrustBundle{FormatVersion: 1, WorkspaceID: i.WorkspaceID, Signer: trust.Signer, Sequence: 1, CAs: [][]byte{block.Bytes}, Hosts: []string{s.Endpoints[0].Host}, Revoked: []TLSRevocation{}}
		if os.Getenv("WORMHOLE_TEST_INITIAL_LARGE_TLS") == "1" {
			for n := 0; n < 4096; n++ {
				value.Revoked = append(value.Revoked, TLSRevocation{IssuerSPKI: "1111111111111111111111111111111111111111111111111111111111111111", Serial: fmt.Sprintf("a%039x", n)})
			}
		}
		switch os.Getenv("WORMHOLE_TEST_INITIAL_TLS_FAILURE") {
		case "":
		case "revoked-peer":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			value.Revoked = []TLSRevocation{{IssuerSPKI: hex.EncodeToString(spki[:]), Serial: cert.SerialNumber.Text(16)}}
		case "wrong-signer":
			value.Signer.Version++
		default:
			t.Fatal("invalid signed TLS fixture failure")
		}
		bundle, err := SignTLSTrustBundle(value, org)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeTLSTrustBundle(bundle)
		if err != nil {
			t.Fatal(err)
		}
		i.FormatVersion, i.CAPEM = 3, nil
		i.TLSIdentity = &InvitationTLSIdentity{Organisation: trust.Organisation, Bundle: raw}
		exec(`UPDATE wormhole_data.workspace_meta SET tls_sequence=1,tls_bundle=decode($1,'hex')`, hex.AppendEncode(nil, raw))
	}
	for _, c := range []vault.UserKeyCertificate{certificate.BootstrapEncryption, certificate.BootstrapSigning} {
		exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status,public_key,cert_signer_key_id,cert_signer_key_version,cert_revision,cert_signature) VALUES($1::uuid,1,$2,$3::uuid,$4::smallint,'pending',decode($5,'hex'),$6::uuid,1,1,decode($7,'hex'))`,
			[]byte(c.Key.ID.String()), []byte(c.Kind), user, []byte(strconv.Itoa(int(c.Suite))), hex.AppendEncode(nil, c.PublicKey), []byte(trust.Signer.ID.String()), hex.AppendEncode(nil, c.Signature))
	}
	exec(`INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,1,decode($2,'hex'))`, user, rows[0][12])
	bootstrapRaw, err := EncodeInvitationBootstrapEnvelope(i, bootstrap, time.Now())
	if i.FormatVersion == 3 {
		// The seed helper originally sealed the legacy envelope before TLS was
		// selected. Reopen its synthetic native keys only to issue the v3-bound
		// envelope; no legacy envelope is stored for this fresh invitation.
		secret, e := vault.OpenInviteBootstrap(code, i.Enrollment.Context, bootstrap, i.OrganisationFingerprint)
		if e != nil {
			t.Fatal(e)
		}
		bound, e := i.SealBootstrap(code, secret, time.Now())
		secret.Wipe()
		if e != nil {
			t.Fatal(e)
		}
		bootstrapRaw, err = EncodeInvitationBootstrapEnvelope(i, bound, time.Now())
	}
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision) VALUES($1::uuid,$2::uuid,'invite',decode(repeat('00',32),'hex'),$2::uuid,to_timestamp($3::bigint),$4::uuid,1,$5::uuid,1,decode($6,'hex'),decode($7,'hex'),1)`,
		[]byte(i.Enrollment.Context.InviteID.String()), user, []byte(strconv.FormatInt(i.ExpiresAt, 10)), []byte(certificate.BootstrapEncryption.Key.ID.String()), []byte(certificate.BootstrapSigning.Key.ID.String()), hex.AppendEncode(nil, bootstrapRaw), hex.AppendEncode(nil, manifest))
	_, verifier, err := i.EnrollmentVerifier(code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	exec(`SELECT wormhole_data.provision_invitation_login($1::uuid,$2)`, []byte(i.Enrollment.Context.InviteID.String()), verifier)
	return i
}
