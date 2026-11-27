package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresInvitationCommit(t *testing.T) {
	s, adminSecret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
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
	for _, generate := range []func(string, string) (string, error){deploy.InitialMigration, deploy.SessionMigration, deploy.KeyGraphMigration, deploy.SessionProofMigration, deploy.PasswordChangeMigration, deploy.AccountKeysMigration, deploy.AccountCertificatesMigration, deploy.AccountStateMigration, deploy.TLSTrustMigration, deploy.InvitationLoginMigration, deploy.InvitationCopiesMigration, deploy.AccountEnrollmentMigration} {
		sql, err := generate("testscope", testHintID)
		if err != nil {
			t.Fatal(err)
		}
		script(sql)
	}
	wrong, _ := deploy.InvitationCommitMigration("testscope", uuid.NewString())
	rejectMigration := func(sql string) {
		t.Helper()
		_, err := admin.Exec(ctx, sql).ReadAll()
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55000" {
			t.Fatal("migration guard", err)
		}
		script("ROLLBACK")
	}
	rejectMigration(wrong)
	migration, _ := deploy.InvitationCommitMigration("testscope", testHintID)
	script(migration)
	rejectMigration(migration)
	acl := admin.ExecParams(ctx, `SELECT (NOT has_function_privilege('wh_testscope_user','wormhole_api_v1.commit_invitation(uuid,bigint,bytea,uuid,text,text,text,boolean,bytea,bytea,bytea,jsonb)','EXECUTE')
AND NOT has_function_privilege('wh_testscope_admin','wormhole_api_v1.commit_invitation(uuid,bigint,bytea,uuid,text,text,text,boolean,bytea,bytea,bytea,jsonb)','EXECUTE')
AND NOT EXISTS(SELECT 1 FROM pg_proc p,LATERAL aclexplode(p.proacl) a WHERE p.oid='wormhole_api_v1.commit_invitation(uuid,bigint,bytea,uuid,text,text,text,boolean,bytea,bytea,bytea,jsonb)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE'))::text`, nil, nil, nil, nil).Read()
	if acl.Err != nil || len(acl.Rows) != 1 || string(acl.Rows[0][0]) != "true" {
		t.Fatal("commit ACL", acl.Err)
	}
	var bootstrapEnvelope vault.Envelope
	rows, trust, master := accountEnrollmentRowsWithBootstrap(t, func(binding vault.InviteContext, bootstrap *vault.InviteBootstrap) {
		var e error
		bootstrapEnvelope, e = vault.SealInviteBootstrap(bytes.Repeat([]byte{31}, 16), binding, bootstrap)
		if e != nil {
			t.Fatal(e)
		}
	})
	account, err := parseAccountEnrollmentMaterial(rows, admissionRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	certificate := *account.EnrollmentCertificate
	keys, err := vault.OpenEnrolledUserKeys(master, account.Binding, account.Envelope, certificate, *account.State, trust, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	// Real encrypted source and replacement copy, with unchanged DEK after join.
	dek := bytes.Repeat([]byte{72}, 32)
	defer vault.Wipe(dek)
	binding := vault.KeyCopyBinding{WorkspaceID: trust.WorkspaceID, Key: vault.KeyRef{ID: uuid.New(), Version: 1}, Holder: account.State.Encryption, Issuer: trust.Signer}
	source, err := vault.SealKeyCopy(dek, binding, certificate.Manifest.Bootstrap.Encryption, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	certificate.Manifest.Copies = []vault.KeyCopyBinding{binding}
	certificate.Manifest.Issuers = []vault.InviteIssuer{{Key: trust.Signer, Public: trust.Organisation}}
	certificate.Manifest.ExpiresAt = time.Now().Add(time.Hour).Unix()
	certificate.Manifest, err = vault.SignInviteManifest(certificate.Manifest, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := vault.EncodeInviteManifest(certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	certRaw, err := vault.EncodeUserEnrollmentCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	finalBinding := binding
	finalBinding.Holder = account.Binding.Encryption
	finalBinding.Issuer = account.Binding.Signing
	replacement, err := vault.SealKeyCopy(dek, finalBinding, certificate.Rekey.Public.Encryption, keys.SigningSeed)
	if err != nil {
		t.Fatal(err)
	}
	copyJSON, _ := json.Marshal([]map[string]any{{"keyId": binding.Key.ID.String(), "keyVersion": 1, "enc": hex.EncodeToString(replacement.Envelope.Enc), "ciphertext": hex.EncodeToString(replacement.Envelope.Ciphertext), "signature": hex.EncodeToString(replacement.Signature)}})
	i, _ := enrollmentInvitationFixture(t)
	i.WorkspaceID = trust.WorkspaceID
	i.Enrollment.Context = certificate.Manifest.Context
	i.LoginName = certificate.Manifest.Context.LoginName
	i.ExpiresAt = certificate.Manifest.ExpiresAt
	i.Endpoints, i.Database, i.TLS, i.CAPEM = s.Endpoints, s.Database, s.TLS, s.CAPEM
	user := []byte(trust.UserID.String())
	invite := []byte(i.Enrollment.Context.InviteID.String())
	exec(`INSERT INTO wormhole_data.users(id,login_name) VALUES($1::uuid,$2)`, user, []byte(i.LoginName))
	exec(`UPDATE wormhole_data.workspace_meta SET state='ready',signed_profile='test'::bytea,require_tls=false`)
	exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,owner_id,suite,status) VALUES($1::uuid,1,'user-enc',$3::uuid,2,'pending'),($2::uuid,1,'user-sign',$3::uuid,1,'pending')`, []byte(account.State.Encryption.ID.String()), []byte(account.State.Signing.ID.String()), user)
	exec(`INSERT INTO wormhole_data.keys(key_id,key_version,kind,suite,status) VALUES($1::uuid,1,'org-sign',1,'active'),($2::uuid,1,'dek',1,'active')`, []byte(trust.Signer.ID.String()), []byte(binding.Key.ID.String()))
	exec(`INSERT INTO wormhole_data.key_copies(key_id,key_version,holder_key_id,holder_key_version,suite,enc,ciphertext,issuer_key_id,issuer_key_version,signature) VALUES($1::uuid,1,$2::uuid,1,2,decode($3,'hex'),decode($4,'hex'),$5::uuid,1,decode($6,'hex'))`, []byte(binding.Key.ID.String()), []byte(binding.Holder.ID.String()), hex.AppendEncode(nil, source.Envelope.Enc), hex.AppendEncode(nil, source.Envelope.Ciphertext), []byte(trust.Signer.ID.String()), hex.AppendEncode(nil, source.Signature))
	exec(`INSERT INTO wormhole_data.user_key_states(user_id,state_sequence,signed_state) VALUES($1::uuid,1,decode($2,'hex'))`, user, rows[0][12])
	exec(`INSERT INTO wormhole_data.invites(id,user_id,kind,code_hash,created_by,expires_at,bootstrap_enc_key_id,bootstrap_enc_key_version,bootstrap_sign_key_id,bootstrap_sign_key_version,bootstrap_envelope,manifest,manifest_revision) VALUES($1::uuid,$2::uuid,'invite',decode(repeat('00',32),'hex'),$2::uuid,to_timestamp($3::bigint),$4::uuid,1,$5::uuid,1,decode(repeat('00',16),'hex'),decode($6,'hex'),1)`, invite, user, []byte(strconv.FormatInt(i.ExpiresAt, 10)), []byte(account.State.Encryption.ID.String()), []byte(account.State.Signing.ID.String()), hex.AppendEncode(nil, manifest))
	code := bytes.Repeat([]byte{31}, 16)
	bootstrapRaw, err := EncodeInvitationBootstrapEnvelope(i, bootstrapEnvelope, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE wormhole_data.invites SET bootstrap_envelope=decode($2,'hex') WHERE id=$1::uuid`, invite, hex.AppendEncode(nil, bootstrapRaw))
	role, verifier, err := i.EnrollmentVerifier(code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(verifier)
	exec(`SELECT wormhole_data.provision_invitation_login($1::uuid,$2)`, invite, verifier)
	testNativeInvitationCertification(t, ctx, admin, i, code, certificate, trust)
	preparationSession := NewSession()
	if err := preparationSession.OpenInitialInvitation(ctx, i, code, vault.Standard, vault.Default, true); err == nil || preparationSession.started {
		t.Fatal("initial invitation ignored the OS TLS floor")
	}
	if err := preparationSession.OpenInitialInvitation(ctx, i, code, vault.Default, vault.Default, false); !errors.Is(err, vault.ErrPolicy) || preparationSession.started {
		t.Fatal("initial invitation omitted the TLS-Off acknowledgement")
	}
	if err := preparationSession.OpenInitialInvitation(ctx, i, code, vault.Default, vault.Default, true); err != nil {
		t.Fatal(err)
	}
	initial, err := preparationSession.PrepareInitialEnrollment(ctx, i, code, []byte("native enrollment password"), bytes.Repeat([]byte{45}, 32), "prepared native device", vault.Default, vault.Standard)
	if err != nil {
		t.Fatal("native preparation", err)
	}
	if err := initial.Borrow(func(master *AccountMaster, root *DeviceTrustRoot, commit *PreparedInvitationCommit) error {
		pending, err := commit.PendingEnrollment(root.Binding())
		if err != nil {
			return err
		}
		if len(pending.Certificate.Manifest.Copies) != 1 || pending.Trust.Account.Sequence != 1 {
			t.Error("incomplete native preparation")
		}
		return commit.ValidateAccountMaster(master)
	}); err != nil {
		t.Fatal(err)
	}
	if err := initial.BorrowDeviceStorage(func(key []byte, slots vault.SlotFile, envelope []byte) error {
		metadata, err := OpenDeviceEnrollment(key, slots, slots.VaultID, slots.FileID, 1, envelope)
		if err != nil {
			return err
		}
		if metadata.Binding().WorkspaceID != i.WorkspaceID || metadata.Binding().UserID != i.Enrollment.Context.UserID {
			t.Error("stored native enrollment identity changed")
		}
		if len(slots.Slots) != 1 || !slots.Slots[0].ASKRequired {
			t.Error("native storage lost ASK")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	transferred, err := initial.TakeDeviceAccount(ctx)
	if err != nil {
		t.Fatal("transfer prepared native account", err)
	}
	defer func() {
		if err := transferred.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transferred.Borrow(func(master *AccountMaster, root *DeviceTrustRoot) error {
		if master.WorkspaceID() != i.WorkspaceID || master.LoginName() != i.LoginName || root.Binding().UserID != i.Enrollment.Context.UserID {
			t.Fatal("native transfer changed authenticated account")
		}
		return transferred.BorrowDeviceStorage(func([]byte, []byte) error { return nil })
	}); err != nil {
		t.Fatal("transferred native owner lost keys", err)
	}
	if err := transferred.Close(); err != nil {
		t.Fatal(err)
	}
	if err := preparationSession.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Preparation must leave the invite available to the actual commit below.
	loginSettings, loginSecret, err := i.EnrollmentLogin(code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(loginSecret)
	enroll, err := Connect(ctx, loginSettings, loginSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer enroll.Close(context.Background())
	device := uuid.New()
	deviceRole := "wh_testscope_d_" + device.String()
	material, err := vault.DeriveKey(master, nil, vault.PurposeLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(material)
	deviceVerifier, err := NewSCRAMVerifier(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(deviceVerifier)
	digest := sha256.Sum256(manifest)
	args := [][]byte{invite, []byte("1"), hex.AppendEncode(nil, digest[:]), []byte(device.String()), []byte("test device"), deviceVerifier, []byte("kdf-v1"), []byte("true"), rows[0][9], rows[0][10], hex.AppendEncode(nil, certRaw), copyJSON}
	const query = `SELECT device_id::text,role_name,wrap_revision::text,auth_epoch::text FROM wormhole_api_v1.commit_invitation($1::uuid,$2::bigint,decode($3,'hex'),$4::uuid,$5,$6,$7,$8::boolean,decode($9,'hex'),decode($10,'hex'),decode($11,'hex'),$12::jsonb)`
	reject := func(expected string, a [][]byte) {
		t.Helper()
		r := enroll.ExecParams(ctx, query, a, nil, nil, nil).Read()
		var pe *pgconn.PgError
		if !errors.As(r.Err, &pe) || pe.Code != expected {
			t.Fatal("expected "+expected, r.Err)
		}
	}
	checkPending := func() {
		t.Helper()
		r := admin.ExecParams(ctx, `SELECT (NOT EXISTS(SELECT 1 FROM wormhole_data.account_auth) AND NOT EXISTS(SELECT 1 FROM wormhole_data.devices) AND NOT EXISTS(SELECT 1 FROM wormhole_data.user_key_wraps) AND NOT EXISTS(SELECT 1 FROM wormhole_data.user_enrollments) AND (SELECT count(*) FROM wormhole_data.key_copies)=1 AND (SELECT used_at IS NULL FROM wormhole_data.invites) AND (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1))::text`, [][]byte{[]byte(role)}, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("partial commit", r.Err)
		}
	}
	for _, col := range []int{1, 2, 3, 4, 6, 8, 9, 10, 11} {
		bad := append([][]byte(nil), args...)
		switch col {
		case 1:
			bad[col] = []byte("2")
		case 2:
			bad[col] = []byte("00")
		case 3:
			bad[col] = []byte(uuid.Nil.String())
		case 4:
			bad[col] = nil
		case 6:
			bad[col] = []byte("bad")
		case 8, 9:
			bad[col] = []byte("00")
		case 10:
			bad[col] = hex.AppendEncode(nil, []byte("{}"))
		case 11:
			bad[col] = []byte("[]")
		}
		reject("WH012", bad)
		checkPending()
	}
	// Signed requirements may change after the native prerequisite download.
	// Commit must not activate a device against a revoked/replaced bootstrap.
	org := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer vault.Wipe(org)
	for _, mode := range []string{"revoked", "anchor", "certificate-floor"} {
		changed := *account.State
		changed.Sequence++
		switch mode {
		case "revoked":
			changed.Active = false
		case "anchor":
			changed.Encryption.ID = uuid.New()
		case "certificate-floor":
			changed.MinimumEncryptionCertificate++
		}
		changed, err = vault.SignUserKeyState(changed, org)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := vault.EncodeUserKeyState(changed)
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE wormhole_data.user_key_states SET signed_state=decode($1,'hex'),state_sequence=$2::bigint`, hex.AppendEncode(nil, raw), []byte(strconv.FormatUint(changed.Sequence, 10)))
		reject("WH010", args)
		checkPending()
	}
	exec(`UPDATE wormhole_data.user_key_states SET signed_state=decode($1,'hex'),state_sequence=1`, rows[0][12])
	for _, col := range []int{6, 7} {
		bad := append([][]byte(nil), args...)
		if col == 6 {
			bad[col] = []byte("kdf-low")
		} else {
			bad[col] = []byte("false")
		}
		reject("WH010", bad)
		checkPending()
	}
	profile := certificationProfile(t, i.WorkspaceID, trust.Signer)
	stronger, err := vault.DecodeSignedPolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	stronger.Policy.Sequence++
	stronger.Policy.KDF = vault.KDFV2
	stronger, err = vault.SignPolicy(stronger.Policy, trust.Signer.ID.String(), trust.Signer.Version, org)
	if err != nil {
		t.Fatal(err)
	}
	strongRaw, err := vault.EncodeSignedPolicy(stronger)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')`, hex.AppendEncode(nil, strongRaw))
	reject("WH010", args)
	checkPending()
	exec(`UPDATE wormhole_data.workspace_meta SET signed_profile=decode($1,'hex')`, hex.AppendEncode(nil, profile))
	var copyItems []map[string]any
	if err := json.Unmarshal(copyJSON, &copyItems); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"duplicate", "oversize", "wrong-key", "invalid-enc"} {
		item := make(map[string]any)
		for k, v := range copyItems[0] {
			item[k] = v
		}
		items := []map[string]any{item}
		switch mode {
		case "duplicate":
			items = append(items, item)
		case "oversize":
			items = make([]map[string]any, 1025)
			for n := range items {
				items[n] = item
			}
		case "wrong-key":
			item["keyId"] = uuid.NewString()
		case "invalid-enc":
			item["enc"] = "zz"
		}
		bad := append([][]byte(nil), args...)
		bad[11], err = json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		reject("WH012", bad)
		checkPending()
	}
	script("BEGIN; SELECT 1 FROM wormhole_data.invites FOR SHARE")
	reject("55P03", args)
	script("ROLLBACK")
	checkPending()
	script("BEGIN; SELECT 1 FROM wormhole_data.key_copies FOR UPDATE")
	reject("55P03", args)
	script("ROLLBACK")
	checkPending()
	script(`CREATE ROLE "` + deviceRole + `" NOLOGIN`)
	reject("42710", args)
	checkPending()
	script(`DROP ROLE "` + deviceRole + `"`)
	script(`CREATE FUNCTION wormhole_data.fail_join_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$; CREATE TRIGGER fail_join_audit BEFORE INSERT ON wormhole_data.audit_log FOR EACH ROW EXECUTE FUNCTION wormhole_data.fail_join_audit()`)
	reject("WH005", args)
	checkPending()
	script(`DROP TRIGGER fail_join_audit ON wormhole_data.audit_log; DROP FUNCTION wormhole_data.fail_join_audit()`)
	owner := &AccountMaster{memory: &masterMemoryProbe{data: bytes.Clone(master)}, preset: vault.KDFV1, askUsed: true, workspaceID: i.WorkspaceID, loginName: i.LoginName}
	defer owner.Close()
	certification := &UnverifiedInvitationCertification{State: *account.State, Encryption: certificate.BootstrapEncryption, Signing: certificate.BootstrapSigning, SignedProfile: profile}
	plan := &vault.InviteRewrapPlan{Keys: keys, Proof: certificate.Rekey, Copies: []vault.RewrappedKeyCopy{{Binding: finalBinding, Copy: replacement}}, SourceManifestRevision: certificate.Manifest.Revision, SourceManifestDigest: digest[:]}
	prepared, err := PrepareInvitationCommit(i, certification, trust.Organisation, certificate.Manifest, plan, owner, device, "test device", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Wipe()
	localBinding := TrustBinding{WorkspaceID: i.WorkspaceID, UserID: trust.UserID, DeviceID: device, KeyID: uuid.New(), KeyVersion: 1}
	pending, err := prepared.PendingEnrollment(localBinding)
	if err != nil {
		t.Fatal(err)
	}
	joining := NewSession()
	defer joining.Close(context.Background())
	if err := joining.OpenInvitation(ctx, i, code); err != nil {
		t.Fatal(err)
	}
	if _, err := joining.Query(ctx, "BEGIN", nil); err != nil {
		t.Fatal(err)
	}
	if err := joining.CommitInvitation(ctx, prepared); err != ErrConfiguration {
		t.Fatal("caller transaction", err)
	}
	if _, err := joining.Query(ctx, "ROLLBACK", nil); err != nil {
		t.Fatal(err)
	}
	script("BEGIN; SELECT 1 FROM wormhole_data.invites FOR UPDATE")
	if err := joining.CommitInvitation(ctx, prepared); err != ErrChangeInProgress {
		t.Fatal("native contention", err)
	}
	script("ROLLBACK")
	checkPending()
	if err := joining.CommitInvitation(ctx, prepared); err != nil {
		t.Fatal("native join", err)
	}
	select {
	case <-joining.Done():
	default:
		t.Fatal("committed invite session retained")
	}
	reject("WH012", args)
	retired := admin.ExecParams(ctx, `SELECT ((SELECT used_at IS NOT NULL AND bootstrap_envelope IS NULL FROM wormhole_data.invites)
AND (SELECT count(*) FROM wormhole_data.keys WHERE status='retired')=2
AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='join_workspace')=1
AND NOT EXISTS(SELECT 1 FROM wormhole_data.key_copies WHERE holder_key_id=$1::uuid)
AND NOT (SELECT rolcanlogin FROM pg_roles WHERE rolname=$2))::text`, [][]byte{[]byte(account.State.Encryption.ID.String()), []byte(role)}, nil, nil, nil).Read()
	if retired.Err != nil || len(retired.Rows) != 1 || string(retired.Rows[0][0]) != "true" {
		t.Fatal("bootstrap not atomically retired", retired.Err)
	}
	settings := s
	settings.DeviceRole = deviceRole
	deviceLogin, err := EncodeLoginSecret(material)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(deviceLogin)
	native := NewSession()
	defer native.Close(context.Background())
	if err := native.Open(ctx, settings, deviceLogin, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal("device login", err)
	}
	if _, err := native.VerifyPendingEnrollment(ctx, localBinding, pending, owner, nil); err != ErrAuthentication {
		t.Fatal("SCRAM alone established enrollment", err)
	}
	request := admissionRequest()
	request.DeviceID = device
	if _, err := native.AuthenticateSession(ctx, request, material); err != nil {
		t.Fatal("new device proof", err)
	}
	committed, err := native.AccountEnrollmentMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := native.VerifyPendingEnrollment(ctx, localBinding, pending, owner, committed)
	if err != nil {
		t.Fatal("committed device reconciliation", err)
	}
	activation, err := verified.Activation(localBinding, pending)
	if err != nil || activation.Enrollment == nil || activation.Enrollment.Encryption != account.Binding.Encryption {
		t.Fatal("wrong reconciled selection", err)
	}
	certificateDigest := sha256.Sum256(certRaw)
	if !bytes.Equal(verified.CertificateDigest(), certificateDigest[:]) {
		t.Fatal("wrong confirmation certificate")
	}
	opened, err := vault.OpenEnrolledUserKeys(master, committed.Binding, committed.Envelope, *committed.EnrollmentCertificate, *committed.State, trust, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	stored := admin.ExecParams(ctx, `SELECT encode(enc,'hex'),encode(ciphertext,'hex'),encode(signature,'hex') FROM wormhole_data.key_copies WHERE holder_key_id=$1::uuid`, [][]byte{[]byte(account.Binding.Encryption.ID.String())}, nil, nil, nil).Read()
	if stored.Err != nil || len(stored.Rows) != 1 {
		t.Fatal(stored.Err)
	}
	replacement.Envelope.Enc, _ = hex.DecodeString(string(stored.Rows[0][0]))
	replacement.Envelope.Ciphertext, _ = hex.DecodeString(string(stored.Rows[0][1]))
	replacement.Signature, _ = hex.DecodeString(string(stored.Rows[0][2]))
	actual, err := vault.OpenKeyCopy(opened.EncryptionPrivate, finalBinding, replacement, certificate.Rekey.Public.Signing)
	if err != nil || !bytes.Equal(actual, dek) {
		t.Fatal("rewrap changed secret", err)
	}
	vault.Wipe(actual)
	if connection, err := Connect(ctx, loginSettings, loginSecret); err == nil {
		connection.Close(context.Background())
		t.Fatal("consumed invite login remained active")
	}
	testEnrollmentConfirmation(t, ctx, admin, native, settings, deviceLogin, material, device, certRaw, localBinding, pending, verified)
}
