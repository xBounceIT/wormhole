package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestBoundaryRecoveryRejectsAmbiguousScope(t *testing.T) {
	first := workspaceAdminRecoveryBoundary{BoundaryID: uuid.MustParse("00000000-0000-0000-0000-000000000001")}
	second := workspaceAdminRecoveryBoundary{BoundaryID: uuid.MustParse("00000000-0000-0000-0000-000000000002")}
	for _, material := range []workspaceAdminRecoveryMaterial{
		{Boundaries: []workspaceAdminRecoveryBoundary{}},
		{Boundaries: []workspaceAdminRecoveryBoundary{{}}},
		{Boundaries: []workspaceAdminRecoveryBoundary{second, first}},
		{Boundaries: []workspaceAdminRecoveryBoundary{first, first}},
		{Boundaries: []workspaceAdminRecoveryBoundary{first}, workspaceAdminRecoveryBoundary: second},
		{Boundaries: make([]workspaceAdminRecoveryBoundary, maxAdminRecoveryBoundaries+1)},
	} {
		if boundaries, _, err := recoveryBoundarySelection(material); boundaries != nil || err != ErrAdmissionResponse {
			t.Fatal("ambiguous recovery boundaries were accepted", err)
		}
	}
	if result, version, err := recoveryBoundarySelection(workspaceAdminRecoveryMaterial{Boundaries: []workspaceAdminRecoveryBoundary{first, second}}); err != nil || version != 2 || len(result) != 2 {
		t.Fatal("exact list of shared boundaries was rejected", err)
	}
}

func checkWorkspaceAdminRecovery(t *testing.T, ctx context.Context, dba Settings, owner, delegated *pgconn.PgConn, secret []byte, original *workspaceBootstrap, factors *workspaceBootstrapSecrets, ask []byte) {
	t.Helper()
	target := WorkspaceRecoveryTarget{WorkspaceID: original.invitation.WorkspaceID, Endpoint: original.invitation.Endpoints[0],
		Database: original.invitation.Database, DeployerRole: "wh_delegated_deployer"}
	kit, err := encodeWorkspaceRecoveryKit(workspaceRecoveryKit{Version: 1, Workspace: target.WorkspaceID,
		Encryption: original.recovery.Encryption, Signing: original.recovery.Signing, Public: original.organisation, Capsule: original.recoveryKeys})
	if err != nil {
		t.Fatal(err)
	}
	code, err := vault.FormatRecoveryKey(factors.recoveryKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	tls := original.invitation.TLSIdentity.Bundle
	otherKey := vault.NewRecoveryKey()
	defer vault.Wipe(otherKey)
	wrong, err := vault.FormatRecoveryKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(wrong)
	if draft, err := PrepareWorkspaceRecovery(ctx, target, kit, wrong, tls, secret, "replacement-admin"); draft != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("incorrect recovery code authenticated a deployer", err)
	}
	bundle, err := DecodeTLSTrustBundle(tls)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature[0] ^= 1
	forged, err := EncodeTLSTrustBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if draft, err := PrepareWorkspaceRecovery(ctx, target, kit, code, forged, secret, "replacement-admin"); draft != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("unsigned TLS identity authorized a recovery connection", err)
	}
	if response := delegated.ExecParams(ctx, recoveryMaterialSQL, nil, nil, nil, nil).Read(); !hasSQLState(response.Err, "42501", 0) {
		t.Fatal("schema installer could inspect break-glass material", response.Err)
	}
	if response := delegated.ExecParams(ctx, recoveryBoundariesSQL, nil, nil, nil, nil).Read(); !hasSQLState(response.Err, "42501", 0) {
		t.Fatal("schema installer could inspect shared boundary recovery material", response.Err)
	}
	if _, err := owner.Exec(ctx, "ALTER ROLE wh_delegated_deployer PASSWORD '"+postgresTestVerifier(secret)+"'").ReadAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE wormhole_data.users SET disabled=true WHERE login_name='first-admin'`).ReadAll(); err != nil {
		t.Fatal(err)
	}
	prepare := func(login string) *PreparedWorkspaceRecovery {
		t.Helper()
		draft, err := PrepareWorkspaceRecovery(ctx, target, kit, code, tls, secret, login)
		if err != nil {
			t.Fatal("authenticated recovery could not prepare an invitation", err)
		}
		t.Cleanup(draft.Close)
		return draft
	}
	draft := prepare("replacement-admin")
	if err := draft.BorrowJoin(func(Invitation, []byte) error { t.Fatal("unpublished invitation lent its code"); return nil }); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("unpublished invitation became usable", err)
	}
	if err := draft.Publish(ctx, []byte("incorrect-deployer-factor")); !errors.Is(err, ErrAuthentication) {
		t.Fatal("incorrect deployer credentials authorized publication", err)
	}

	// Authenticate every projection component again on the native side using
	// data read from the live function. These edits never go to PostgreSQL.
	deployer := dba
	deployer.DeviceRole = target.DeployerRole
	conn, err := Connect(ctx, deployer, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	raw, err := readDeploymentResponse(ctx, conn, recoveryMaterialSQL, nil, maxAdminRecoveryMaterial)
	if err != nil {
		t.Fatal(err)
	}
	record, keys, _, err := openWorkspaceRecoveryTrust(target.WorkspaceID, kit, code, tls)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	for name, change := range map[string]func(*workspaceAdminRecoveryMaterial){
		"other-database":  func(m *workspaceAdminRecoveryMaterial) { m.Database = "elsewhere" },
		"stale-TLS":       func(m *workspaceAdminRecoveryMaterial) { m.TLSDigest = hex.EncodeToString(make([]byte, 32)) },
		"unknown-signer":  func(m *workspaceAdminRecoveryMaterial) { m.OrganisationSigning.Version++ },
		"altered-capsule": func(m *workspaceAdminRecoveryMaterial) { m.Capsule[0] = ' ' },
		"unsigned-policy": func(m *workspaceAdminRecoveryMaterial) { m.Policy = []byte("{}") },
		"wrong-boundary":  func(m *workspaceAdminRecoveryMaterial) { m.BoundaryVersion++ },
		"damaged-copy":    func(m *workspaceAdminRecoveryMaterial) { m.Copies[0].Signature[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var material workspaceAdminRecoveryMaterial
			if err := json.Unmarshal(raw, &material); err != nil {
				t.Fatal(err)
			}
			change(&material)
			bad, err := json.Marshal(material)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := prepareWorkspaceRecoveryDraft(draft.settings, "delegated", "replacement-admin", record, keys, bad, time.Now()); got != nil || err == nil {
				t.Fatal("altered recovery material prepared an issuance")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`{"unexpected":true}`), append(bytes.Clone(raw), []byte("{}")...)} {
		if newDraft, err := prepareWorkspaceRecoveryDraft(draft.settings, "delegated", "replacement-admin", record, keys, raw, time.Now()); newDraft != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("malformed recovery projection accepted", err)
		}
	}
	policy, err := vault.DecodeSignedPolicy(original.certification.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy.Policy.Sequence++
	signer := ed25519.NewKeyFromSeed(keys.SigningSeed)
	defer vault.Wipe(signer)
	signed, err := vault.SignPolicy(policy.Policy, record.Signing.ID.String(), record.Signing.Version, signer)
	if err != nil {
		t.Fatal(err)
	}
	signedRaw, err := vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	result := owner.ExecParams(ctx, `UPDATE wormhole_data.workspace_meta SET signed_profile=pg_catalog.decode($1,'hex') WHERE singleton`,
		[][]byte{hex.AppendEncode(nil, signedRaw)}, nil, nil, nil).Read()
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if err := draft.Publish(ctx, secret); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("draft prepared against the superseded signed policy was published", err)
	}
	draft = prepare("replacement-admin")
	path := filepath.Join(t.TempDir(), "recovery.checkpoint")
	checkpoint := draft.Checkpoint()
	if len(checkpoint) == 0 || bytes.Contains(checkpoint, draft.wire) || bytes.Contains(checkpoint, code) {
		t.Fatal("checkpoint did not encrypt the issuance")
	}
	if err := os.WriteFile(path, checkpoint, 0600); err != nil {
		t.Fatal(err)
	}
	if err := draft.Publish(ctx, secret); err != nil {
		t.Fatal("recovery publication was rejected", err)
	}
	inviteID := draft.invitation.Enrollment.Context.InviteID
	// The database owner can inspect these escrowed copies, but the trigger's
	// recovery exception belongs only to the deployer and the enrolling login.
	scope := owner.ExecParams(ctx, `SELECT (count(*) > 0 AND bool_and(NOT wormhole_data.recovery_invitation_root_copy(c)))::text
        FROM wormhole_data.invites i JOIN wormhole_data.key_copies c
          ON (c.holder_key_id,c.holder_key_version)=(i.bootstrap_enc_key_id,i.bootstrap_enc_key_version)
        WHERE i.id=$1::uuid AND wormhole_data.account_rotation_pending(c.key_id,c.key_version)`,
		[][]byte{[]byte(inviteID.String())}, nil, nil, nil).Read()
	if scope.Err != nil || len(scope.Rows) != 1 || string(scope.Rows[0][0]) != "true" {
		t.Fatal("pending recovery copies were not restricted to the issuing session", scope.Err)
	}
	draft.Close()
	if raw := draft.Checkpoint(); raw != nil {
		t.Fatal("closed recovery owner kept its state accessible")
	}
	checkpoint, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	alternate := target
	alternate.Database = "other_database"
	if restored, err := OpenWorkspaceRecoveryCheckpoint(alternate, kit, code, tls, checkpoint); restored != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("recovery checkpoint moved between database targets", err)
	}
	if restored, err := OpenWorkspaceRecoveryCheckpoint(target, kit, wrong, tls, checkpoint); restored != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("checkpoint reopened with a different recovery code", err)
	}
	var envelope vault.Envelope
	if err := json.Unmarshal(checkpoint, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	changed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := OpenWorkspaceRecoveryCheckpoint(target, kit, code, tls, changed); restored != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("altered recovery checkpoint opened", err)
	}
	if restored, err := OpenWorkspaceRecoveryCheckpoint(target, kit, code, tls, []byte("{}")); restored != nil || !errors.Is(err, vault.ErrFormat) {
		t.Fatal("invalid recovery checkpoint opened", err)
	}
	draft, err = OpenWorkspaceRecoveryCheckpoint(target, kit, code, tls, checkpoint)
	if err != nil {
		t.Fatal("could not resume the recovery after discarding its native owner", err)
	}
	defer draft.Close()
	if draft.invitation.Enrollment.Context.InviteID != inviteID {
		t.Fatal("resuming generated a different administrator invitation")
	}
	if err := draft.Publish(ctx, secret); err != nil {
		t.Fatal("the resumed issuance could not reconcile its receipt", err)
	}
	if err := prepare("first-admin").Publish(ctx, secret); !errors.Is(err, ErrDeploymentRejected) {
		t.Fatal("recovery replaced an existing identity", err)
	}
	if err := draft.BorrowJoin(func(i Invitation, code []byte) error {
		joinTestAdministrator(t, ctx, i, code, original.organisation.Signing, original.recovery.Signing, ask, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	check := owner.ExecParams(ctx, `SELECT
    (SELECT count(*) FROM wormhole_data.audit_log WHERE action='break_glass_recovery' AND outcome='invitation_published'),
    (SELECT count(*) FROM wormhole_data.users WHERE is_admin AND NOT disabled),
    (SELECT count(*) FROM wormhole_data.users WHERE login_name='first-admin' AND disabled),
    (SELECT count(*) FROM wormhole_data.workspace_admin_recovery r JOIN wormhole_data.invites i ON i.id=r.invite_id WHERE used_at IS NOT NULL)`,
		nil, nil, nil, nil).Read()
	if check.Err != nil || len(check.Rows) != 1 || len(check.Rows[0]) != 4 {
		t.Fatal("recovery audit and enrollment not available", check.Err)
	}
	for _, value := range check.Rows[0] {
		if string(value) != "1" {
			t.Fatal("recovery duplicated issuance or changed an existing identity", check.Rows)
		}
	}
	legacy, err := readDeploymentResponse(ctx, conn, recoveryMaterialSQL, nil, maxAdminRecoveryMaterial)
	if err != nil {
		t.Fatal(err)
	}
	old, err := prepareWorkspaceRecoveryDraft(draft.settings, "delegated", "legacy-restored-admin", record, keys, legacy, time.Now())
	if err != nil || old.version != 1 {
		t.Fatal("previous recovery protocol could not prepare its original scope", err)
	}
	defer old.Close()
	sealed, err := sealAdminRecoveryCheckpoint(target, draft.settings.TLSBundle, record.Encryption, code, old.wire, old.code)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := OpenWorkspaceRecoveryCheckpoint(target, kit, code, tls, sealed)
	if err != nil || resumed.version != 1 {
		t.Fatal("the earlier encrypted checkpoint could not be opened", err)
	}
	defer resumed.Close()
	if err := resumed.Publish(ctx, secret); err != nil {
		t.Fatal("schema 67 rejected a legacy continuation", err)
	}
	if err := resumed.BorrowJoin(func(i Invitation, code []byte) error {
		joinTestAdministrator(t, ctx, i, code, original.organisation.Signing, original.recovery.Signing, ask, nil)
		return nil
	}); err != nil {
		t.Fatal("earlier recovery invitation could not enroll its administrator", err)
	}
}
