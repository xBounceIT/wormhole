package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func publishWorkspaceBootstrap(ctx context.Context, p *workspaceBootstrap, role string, password, code []byte) (string, error) {
	wire, err := p.wire()
	if err != nil {
		return "", err
	}
	return publishWorkspaceBootstrapWire(ctx, p.invitation, p.organisation.Signing, p.recovery.Signing, p.envelope, wire, role, password, code)
}

func checkWorkspaceBootstrap(t *testing.T, ctx context.Context, dba Settings, secret []byte) {
	t.Helper()
	ca, _ := pem.Decode(dba.CAPEM)
	workspace := uuid.MustParse(testHintID)
	wrongTrust := dba
	wrongTrust.CAPEM = testCA(t)
	if p, s, err := prepareWorkspaceBootstrapFromDeployment(ctx, wrongTrust, secret, workspace, "delegated", "first-admin", vault.Standard, true, nil); p != nil || s != nil || err == nil {
		t.Fatal("bootstrap prepared against an unverified server")
	}
	off := dba
	off.TLS, off.CAPEM = TLSOff, nil
	if _, _, err := prepareWorkspaceBootstrapFromDeployment(ctx, off, secret, workspace, "delegated", "first-admin", vault.Default, false, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("bootstrap accepted an unencrypted setup", err)
	}
	withBundle := dba
	withBundle.CAPEM = append(bytes.Clone(dba.CAPEM), testCA(t)...)
	if _, _, err := prepareWorkspaceBootstrapFromDeployment(ctx, withBundle, secret, uuid.New(), "delegated", "first-admin", vault.Standard, true, nil); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("bootstrap accepted a different workspace identity", err)
	}
	prepare := func() (*workspaceBootstrap, *workspaceBootstrapSecrets) {
		t.Helper()
		p, s, err := prepareWorkspaceBootstrapFromDeployment(ctx, withBundle, secret, workspace, "delegated", "first-admin", vault.Standard, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.wipe)
		pin, err := p.invitation.AuthenticatedTLSBundle(p.organisation.Signing, p.recovery.Signing)
		if err != nil || len(pin.bundle.CAs) != 1 || !bytes.Equal(pin.bundle.CAs[0], ca.Bytes) {
			t.Fatal("the signed bundle included unused provider roots", err)
		}
		return p, s
	}
	draft, factors := prepare()
	conn, err := Connect(ctx, dba, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	wire, err := draft.wire()
	if err != nil {
		t.Fatal(err)
	}
	if result := conn.ExecParams(ctx, workspaceBootstrapSQL, [][]byte{wire, []byte("invalid synthetic verifier")}, nil, nil, nil).Read(); result.Err == nil {
		t.Fatal("invalid enrollment login left a partially initialized workspace")
	}
	if _, err := publishWorkspaceBootstrap(ctx, draft, dba.DeviceRole, secret, make([]byte, vault.InviteCodeBytes)); !errors.Is(err, ErrInvitation) {
		t.Fatal("unrelated code reached the deployment transaction", err)
	}
	if _, err := publishWorkspaceBootstrap(ctx, draft, dba.DeviceRole, []byte("wrong"), factors.invitationCode[:]); !errors.Is(err, ErrAuthentication) {
		t.Fatal("wrong DBA password was accepted", err)
	}
	publish := func(p *workspaceBootstrap, s *workspaceBootstrapSecrets, want string) {
		t.Helper()
		state, err := publishWorkspaceBootstrap(ctx, p, dba.DeviceRole, secret, s.invitationCode[:])
		if err != nil || state != want {
			t.Fatal("workspace bootstrap receipt mismatch", state, err)
		}
	}
	publish(draft, factors, "provisioning")
	publish(draft, factors, "provisioning")
	const recoverySQL = `SELECT pg_catalog.encode(recovery_capsule,'hex') FROM wormhole_data.workspace_bootstrap WHERE singleton`
	if receipt := conn.ExecParams(ctx, recoverySQL, nil, nil, nil, nil).Read(); !hasSQLState(receipt.Err, "42501", 0) {
		t.Fatal("the scoped DBA could read protected bootstrap records")
	}
	ownerSettings := dba
	ownerSettings.DeviceRole = "wormhole_test_admin"
	owner, err := Connect(ctx, ownerSettings, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(owner)
	receipt := owner.ExecParams(ctx, recoverySQL, nil, nil, nil, nil).Read()
	if receipt.Err != nil || len(receipt.Rows) != 1 || len(receipt.Rows[0]) != 1 {
		t.Fatal("missing stored recovery capsule")
	}
	raw, err := hex.AppendDecode(nil, receipt.Rows[0][0])
	var recovery vault.Envelope
	if err != nil || json.Unmarshal(raw, &recovery) != nil || !bytes.Equal(recovery.Ciphertext, draft.recoveryKeys.Ciphertext) {
		t.Fatal("stored recovery material differs from the encrypted capsule")
	}
	org, err := vault.OpenOrganisationRecovery(factors.recoveryKey[:], draft.recovery, recovery, draft.organisation)
	if err != nil {
		t.Fatal("could not recover both organisation keys from the stored ciphertext", err)
	}
	org.Wipe()
	other, wrong := prepare()
	if _, err := publishWorkspaceBootstrap(ctx, other, dba.DeviceRole, secret, wrong.invitationCode[:]); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("a second draft replaced the first administrator", err)
	}
	if state, err := CheckSchemaDeployment(ctx, dba, secret, "delegated", testHintID); err != nil || !state.Provisioning {
		t.Fatal("an unused invitation activated ordinary sessions", err)
	}
	ask := bytes.Repeat([]byte{42}, 32)
	defer vault.Wipe(ask)
	if _, err := owner.Exec(ctx, `INSERT INTO wormhole_data.nodes(id,parent_id,kind,name) VALUES
('10000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000020',1,'Archive test connection'),
('10000000-0000-4000-8000-000000000020',NULL,0,'Archive test folder')`).ReadAll(); err != nil {
		t.Fatal("insert recovery catalog fixture", err)
	}
	joinTestAdministrator(t, ctx, draft.invitation, factors.invitationCode[:], draft.organisation.Signing, draft.recovery.Signing, ask,
		func(plaintext []byte) {
			checkWorkspaceRecoveryRestore(t, ctx, owner, plaintext, draft, factors, ask, 2)
		})
	publish(draft, factors, "ready")
	if state, err := CheckSchemaDeployment(ctx, dba, secret, "delegated", testHintID); err != nil || state.Provisioning {
		t.Fatal("certified first administration did not activate the workspace", err)
	}
	if _, _, err := prepareWorkspaceBootstrapFromDeployment(ctx, dba, secret, workspace, "delegated", "first-admin", vault.Standard, true, nil); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatal("an active workspace accepted a new setup", err)
	}
	checkWorkspaceAdminRecovery(t, ctx, dba, owner, conn, secret, draft, factors, ask)
}

type joinedAdministratorCheck func(*Session, TrustState, *VerifiedTLSBundle, *vault.UserKeys)

func joinTestAdministrator(t *testing.T, ctx context.Context, i Invitation, code []byte, organisation []byte, signer vault.KeyRef, ask []byte, restore func([]byte), checks ...joinedAdministratorCheck) {
	t.Helper()
	joinConfirmedTestAccount(t, ctx, i, code, organisation, signer, ask, true,
		func(native *Session, master *AccountMaster, material *UnverifiedAccountKeys, state TrustState, tls *VerifiedTLSBundle) error {
			return checkWorkspaceRecoverySnapshot(t, ctx, native, master, material, state, tls, restore, checks)
		})
}

func joinConfirmedTestAccount(t *testing.T, ctx context.Context, i Invitation, code, organisation []byte, signer vault.KeyRef, ask []byte, administrator bool,
	check func(*Session, *AccountMaster, *UnverifiedAccountKeys, TrustState, *VerifiedTLSBundle) error) {
	t.Helper()
	join := NewSession()
	defer join.Close(context.Background())
	if err := join.OpenInitialInvitation(ctx, i, code, vault.Default, vault.Default, false); err != nil {
		t.Fatal(err)
	}
	if _, err := join.Query(ctx, `SELECT wormhole_api_v1.bootstrap_workspace('{}',NULL)`, nil); err == nil {
		t.Fatal("enrollment role was allowed to provision")
	}
	if _, err := join.Query(ctx, recoveryMaterialSQL, nil); err == nil {
		t.Fatal("enrollment role was allowed to inspect recovery material")
	}
	if _, err := join.Query(ctx, `SELECT wormhole_api_v1.export_workspace(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, nil); err == nil {
		t.Fatal("enrollment role could export custodian data")
	}
	prepared, err := join.PrepareInitialEnrollment(ctx, i, code, []byte("synthetic-administrator-account"), ask, "Administrator device", vault.Default, vault.Default)
	if prepared != nil {
		defer prepared.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Borrow(func(master *AccountMaster, root *DeviceTrustRoot, commit *PreparedInvitationCommit) error {
		binding := root.Binding()
		pending, err := commit.PendingEnrollment(binding)
		if err != nil {
			return err
		}
		if err := join.CommitInvitation(ctx, commit); err != nil {
			return err
		}
		var material []byte
		if err := master.Use(func(key []byte, _ vault.KDFPreset, _ bool) error {
			var err error
			material, err = vault.DeriveKey(key, nil, vault.PurposeLogin)
			return err
		}); err != nil {
			return err
		}
		defer vault.Wipe(material)
		login, err := EncodeLoginSecret(material)
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		tls, err := i.AuthenticatedTLSBundle(organisation, signer)
		if err != nil {
			return err
		}
		settings := Settings{Endpoints: i.Endpoints, Database: i.Database, DeviceRole: commit.role, TLS: TLSVerified, TLSBundle: tls, Profile: vault.Standard}
		native := NewSession()
		defer native.Close(context.Background())
		if err := native.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
			return err
		}
		request := AdmissionRequest{WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, DeviceID: binding.DeviceID, API: 1, AppVersion: "2.4.3", Source: "ui"}
		admission, err := native.AuthenticateSession(ctx, request, material)
		if err != nil {
			return err
		}
		if admission.IsAdmin != administrator {
			t.Fatal("confirmed account has the wrong administrative role")
		}
		keys, err := native.AccountEnrollmentMaterial(ctx)
		if err != nil {
			return err
		}
		verified, err := native.VerifyPendingEnrollment(ctx, binding, pending, master, keys)
		if err != nil {
			return err
		}
		confirmed, err := native.ConfirmVerifiedEnrollment(ctx, binding, pending, verified)
		if err != nil {
			return err
		}
		state, err := confirmed.ConfirmedActivation(binding, pending)
		if err != nil {
			return err
		}
		state, err = state.AdvanceTLS(tls)
		if err != nil {
			return err
		}
		return check(native, master, keys, state, tls)
	}); err != nil {
		t.Fatal("account could not join and confirm its device", err)
	}
}

func TestWorkspaceBootstrapPreparesCertifiedFirstJoinAndRecovery(t *testing.T) {
	now := time.Now()
	ca, _ := pem.Decode(testCA(t))
	endpoint := Endpoint{Host: "DB.EXAMPLE.ORG", Port: 5432}
	id := uuid.New()
	p, secrets, err := prepareWorkspaceBootstrap(id, "testscope", Settings{Database: "work", Endpoints: []Endpoint{endpoint}, Profile: vault.Standard, Changes: ChangePolicy{ConcurrentDevices: 300}}, [][]byte{ca.Bytes, ca.Bytes}, "first-admin", true, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer secrets.wipe()
	i := p.invitation
	if i.Endpoints[0].Host != "db.example.org" || i.ExpiresAt != now.Add(72*time.Hour).Unix() || i.WorkspaceID != id || len(p.manifest.Copies) != 4 || len(p.copies) != 6 {
		t.Fatal("incorrect creation scope")
	}
	if bundle, err := i.AuthenticatedTLSBundle(p.organisation.Signing, p.recovery.Signing); err != nil || bundle.Pin().MinimumSequence != 1 || len(bundle.bundle.CAs) != 1 {
		t.Fatal("incorrect initial signed transport pin", err)
	}
	var envelope vault.Envelope
	if err := json.Unmarshal(p.envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	public := UnverifiedInvitationBootstrap{Envelope: envelope, Manifest: p.manifest}
	if _, err := public.Authenticate(i, make([]byte, vault.InviteCodeBytes), 1, now); !errors.Is(err, ErrInvitation) {
		t.Fatal("an unrelated code opened first-admin material", err)
	}
	opened, err := public.Authenticate(i, secrets.invitationCode[:], 1, now)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Wipe()
	policy, _, err := p.certification.Verify(i, opened.OrganisationPublic, public.Manifest, 1, 1, 1, now)
	if err != nil || !policy.ASKRequired || policy.Profile != vault.Standard || policy.KDF != vault.KDFV1 {
		t.Fatal("the ordinary invitation verifier rejected initial certification", err)
	}
	if policy.DirectConnectionDevices == nil || *policy.DirectConnectionDevices != 300 {
		t.Fatal("certified profile lost the deployment's direct connection budget")
	}
	org, err := vault.OpenOrganisationRecovery(secrets.recoveryKey[:], p.recovery, p.recoveryKeys, p.organisation)
	if err != nil {
		t.Fatal(err)
	}
	defer org.Wipe()
	b := p.boundary
	trust := vault.BoundaryTrust{WorkspaceID: id, BoundaryID: b.BoundaryID, Signer: p.recovery.Signing, Organisation: p.organisation.Signing, MinimumRevision: 1}
	if err := vault.VerifyBoundaryManifest(b, trust); err != nil {
		t.Fatal(err)
	}
	var inviteCopies []vault.SignedKeyCopy
	for _, c := range p.copies {
		if c.binding.Holder == p.certification.Encryption.Key {
			inviteCopies = append(inviteCopies, c.copy)
			continue
		}
		purpose := vault.BoundaryView
		if c.binding.Key == b.Secret.Key {
			purpose = vault.BoundarySecret
		}
		root, err := vault.OpenBoundaryKeyCopy(org.EncryptionPrivate, c.binding, c.copy, vault.KeyCopyTrust{Issuer: trust.Signer, Public: trust.Organisation}, b, trust, purpose)
		if err != nil || len(root) != 32 {
			t.Fatal("offline recovery did not unlock the boundary escrow", err)
		}
		vault.Wipe(root)
	}
	plan, err := vault.PrepareCertifiedInviteRewrap(context.Background(), i.Enrollment.Context, opened, public.Manifest, inviteCopies, 1, i.ExpiresAt, now)
	if err != nil {
		t.Fatal("ordinary invitation rekey did not accept first-admin copies", err)
	}
	defer plan.Wipe()
	for n, item := range p.copies[:2] {
		raw, err := vault.OpenKeyCopy(opened.EncryptionPrivate, item.binding, item.copy, p.organisation.Signing)
		if err != nil || !bytes.Equal(raw, [][]byte{org.EncryptionPrivate, org.SigningSeed}[n]) {
			t.Fatal("custodian copy and offline recovery disagree", err)
		}
		vault.Wipe(raw)
	}
	secrets.wipe()
	if *secrets != (workspaceBootstrapSecrets{}) {
		t.Fatal("setup factors survived cleanup")
	}
}

func TestWorkspaceBootstrapRejectsInvalidPreparation(t *testing.T) {
	now := time.Now()
	id := uuid.New()
	ca, _ := pem.Decode(testCA(t))
	for _, tc := range []struct {
		name, host, login string
		profile           vault.Profile
		ca                [][]byte
		want              error
	}{
		{"host", "bad host", "alice", vault.Default, [][]byte{ca.Bytes}, ErrServerCertificate},
		{"login", "::1", " Alice", vault.Default, [][]byte{ca.Bytes}, ErrConfiguration},
		{"profile", "::1", "alice", vault.Hardened, [][]byte{ca.Bytes}, vault.ErrPolicy},
		{"empty CA", "::1", "alice", vault.Default, nil, vault.ErrFormat},
		{"invalid CA", "::1", "alice", vault.Default, [][]byte{[]byte("bad certificate")}, vault.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s, err := prepareWorkspaceBootstrap(id, "testscope", Settings{Database: "work", Endpoints: []Endpoint{{Host: tc.host, Port: 5432}}, Profile: tc.profile}, tc.ca, tc.login, false, now, nil)
			if p != nil || s != nil || !errors.Is(err, tc.want) {
				t.Fatal("invalid setup was accepted", err)
			}
		})
	}
	p, s, err := prepareWorkspaceBootstrap(id, "testscope", Settings{Database: "work", Endpoints: []Endpoint{{Host: "0:0:0:0:0:0:0:1", Port: 5432}}, Profile: vault.Default}, [][]byte{ca.Bytes}, "alice", false, now, nil)
	if err != nil || p.invitation.Endpoints[0].Host != "::1" {
		t.Fatal("valid IPv6 deployment target was refused", err)
	}
	s.wipe()
}

func TestWorkspaceBootstrapPublicationChecksLocalStateBeforeConnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	publish := func(ctx context.Context, role string) error {
		_, err := publishWorkspaceBootstrapWire(ctx, Invitation{}, nil, vault.KeyRef{}, nil, nil, role, nil, nil)
		return err
	}
	if err := publish(ctx, "valid_role"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled setup was not retired", err)
	}
	if err := publish(context.Background(), "invalid role"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid temporary role was accepted", err)
	}
	if err := publish(context.Background(), "valid_role"); !errors.Is(err, ErrInvitation) {
		t.Fatal("missing local proof was accepted", err)
	}
}
