package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestAccountRecoveryRequiresPinnedRecipient(t *testing.T) {
	user := vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{31}, 32), SigningSeed: bytes.Repeat([]byte{24}, 32)}
	org := vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{59}, 32), SigningSeed: bytes.Repeat([]byte{87}, 32)}
	defer user.Wipe()
	defer org.Wipe()
	userPublic, err := user.Public()
	if err != nil {
		t.Fatal(err)
	}
	orgPublic, err := org.Public()
	if err != nil {
		t.Fatal(err)
	}
	workspace := uuid.New()
	recipient := vault.OrganisationRecoveryRecipient{WorkspaceID: workspace, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1},
		Signer: vault.KeyRef{ID: uuid.New(), Version: 1}, PublicKey: orgPublic.Encryption}
	trust := TrustState{WorkspaceID: workspace, Enrollment: &EnrollmentPin{
		Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1},
	}}
	account := vault.UserKeyTrust{WorkspaceID: workspace, Signer: recipient.Signer, Organisation: orgPublic.Signing}
	wrap := func(binding vault.KeyCopyBinding, key, to []byte) workspaceAdminRecoveryCopy {
		t.Helper()
		copy, err := vault.SealKeyCopy(key, binding, to, user.SigningSeed)
		if err != nil {
			t.Fatal(err)
		}
		return workspaceAdminRecoveryCopy{KeyRef: binding.Key, Enc: copy.Envelope.Enc,
			Ciphertext: copy.Envelope.Ciphertext, Signature: copy.Signature}
	}
	orgCopy := func(key vault.KeyRef, value []byte) workspaceAdminRecoveryCopy {
		return wrap(accountRecoveryBinding(trust, key, trust.Enrollment.Encryption), value, userPublic.Encryption)
	}
	m := accountRecoveryMaterial{Recipient: recipient.Encryption, Signer: recipient.Signer, PublicKey: recipient.PublicKey}
	if proof, err := m.authenticateRecipient(recipient, trust, account, &user); proof != nil || err != nil {
		t.Fatal("a non-custodian tried to sign an unproven recipient", err)
	}
	m.OrganisationCopies = []workspaceAdminRecoveryCopy{
		orgCopy(recipient.Signer, org.SigningSeed), orgCopy(recipient.Encryption, org.EncryptionPrivate),
	}
	proof, err := m.authenticateRecipient(recipient, trust, account, &user)
	if err != nil || len(proof) != 64 {
		t.Fatal("custodian could not authenticate the recipient", err)
	}
	for _, scenario := range []string{"changed-signer", "changed-public", "unknown-copy", "duplicate-copy", "bad-copy", "wrong-private"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := recipient
			material := m
			material.OrganisationCopies = append([]workspaceAdminRecoveryCopy(nil), m.OrganisationCopies...)
			switch scenario {
			case "changed-signer":
				candidate.Signer.ID = uuid.New()
			case "changed-public":
				candidate.PublicKey = userPublic.Encryption
			case "unknown-copy":
				material.OrganisationCopies[0].KeyRef.ID = uuid.New()
			case "duplicate-copy":
				material.OrganisationCopies[0] = material.OrganisationCopies[1]
			case "bad-copy":
				material.OrganisationCopies[0].Signature = make([]byte, 64)
			case "wrong-private":
				material.OrganisationCopies[1] = orgCopy(recipient.Encryption, user.EncryptionPrivate)
			}
			if proof, err := material.authenticateRecipient(candidate, trust, account, &user); proof != nil || err == nil {
				t.Fatal("substituted custody material was accepted")
			}
		})
	}
	m.OrganisationCopies = nil
	m.Certificate = proof
	if _, err := m.authenticateRecipient(recipient, trust, account, &user); err != nil {
		t.Fatal("non-custodian could not verify the signed recipient", err)
	}
	m.Certificate = make([]byte, 64)
	if proof, err := m.authenticateRecipient(recipient, trust, account, &user); proof != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("invalid proof authorized a new account copy", err)
	}
	binding := accountRecoveryBinding(trust, trust.Enrollment.Encryption, recipient.Encryption)
	copy := wrap(binding, user.EncryptionPrivate, orgPublic.Encryption)
	if validAccountRecoveryCopy(nil, binding, userPublic.Signing) ||
		validAccountRecoveryCopy([]workspaceAdminRecoveryCopy{copy}, binding, orgPublic.Signing) ||
		!validAccountRecoveryCopy([]workspaceAdminRecoveryCopy{copy}, binding, userPublic.Signing) {
		t.Fatal("an existing copy did not bind the current account signer")
	}
	plain, err := vault.OpenKeyCopy(org.EncryptionPrivate, binding, accountRecoverySignedCopy(copy), userPublic.Signing)
	defer vault.Wipe(plain)
	if err != nil || !bytes.Equal(plain, user.EncryptionPrivate) {
		t.Fatal("custodian could not read the original key", err)
	}
}

func TestAccountRecoveryResponseBounds(t *testing.T) {
	for _, rows := range [][][][]byte{
		nil, {nil}, {{[]byte("null"), nil}}, {{[]byte("{")}}, {{bytes.Repeat([]byte{' '}, 4097)}},
	} {
		if got, err := parseAccountRecoveryMaterial(rows); got != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("malformed result was accepted", err)
		}
	}
	if got, err := parseAccountRecoveryMaterial([][][]byte{{[]byte("null")}}); got != nil || err != nil {
		t.Fatal("ineligible account recovery was treated as corruption", err)
	}
	for _, result := range []accountRecoveryMaterial{
		{},
		{PublicKey: make([]byte, 32), Certificate: []byte{1}},
		{PublicKey: make([]byte, 32), OrganisationCopies: make([]workspaceAdminRecoveryCopy, 1)},
		{PublicKey: make([]byte, 32), Certificate: make([]byte, 64), OrganisationCopies: make([]workspaceAdminRecoveryCopy, 2)},
		{PublicKey: make([]byte, 32), AccountCopies: make([]workspaceAdminRecoveryCopy, 3)},
	} {
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := parseAccountRecoveryMaterial([][][]byte{{raw}}); got != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("malformed custody material was accepted", err)
		}
	}
	if err := checkAccountRecoveryReceipt([][][]byte{{[]byte("pending")}}); !errors.Is(err, ErrAdmissionResponse) {
		t.Fatal("expected commit confirmation", err)
	}
}

func TestAccountRecoveryRequiresAuthenticatedEnrollment(t *testing.T) {
	s := NewSession()
	defer s.Close(context.Background())
	_, _, trust, _, _, _, _ := accountTrustFixture(t)
	keys := &vault.UserKeys{}
	if ok, err := s.EnsureAccountRecovery(nil, trust, keys); ok || !errors.Is(err, ErrConfiguration) {
		t.Fatal("absent context reached the recovery API", err)
	}
	if ok, err := s.EnsureAccountRecovery(context.Background(), trust, keys); ok || err != nil {
		t.Fatal("legacy account should remain usable without recovery custody", err)
	}
	trust.SignedProfile = nil
	if ok, err := s.EnsureAccountRecovery(context.Background(), trust, keys); ok || err == nil {
		t.Fatal("unsigned workspace policy authorized recovery custody")
	}
}

func TestAccountRecoveryCustodyUpgradesSchema50(t *testing.T) {
	settings, password := postgresTestClusterTLS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := Connect(ctx, settings, password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDeploymentConnection(conn)
	const tag = "recovertest"
	script, err := deploy.SchemaScript(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _, ok := strings.Cut(script, "-- Version 51:")
	if !ok {
		t.Fatal("failed to locate the schema-50 fixture cutoff")
	}
	if _, err := conn.Exec(ctx, legacy+"COMMIT;").ReadAll(); err != nil {
		t.Fatal("could not deploy the schema-50 fixture", err)
	}
	session := NewSession()
	defer session.Close(context.Background())
	if err := session.Open(ctx, settings, password, ChangePolicy{TransactionPooler: true}); err != nil {
		t.Fatal(err)
	}
	if supported, err := session.accountRecoverySupported(ctx); supported || err != nil {
		t.Fatal("schema 50 advertised account escrow", err)
	}
	migration, err := deploy.AccountRecoveryCustodyMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema-50 workspace could not install the escrow API", err)
	}
	if supported, err := session.accountRecoverySupported(ctx); !supported || err != nil {
		t.Fatal("the upgraded workspace did not advertise account escrow", err)
	}
	row, err := readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=51 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.restore_workspace(text,text)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.restore_workspace(text,text)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll',
        'wormhole_api_v1.account_recovery_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("upgrade changed restore permissions or exposed escrow to the enrollment role", err)
	}
	migration, err = deploy.AccountResetIssuanceMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema-51 workspace could not install the reset API", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=52 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reset_capsule(uuid,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reset_publication_ready()','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reset_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("upgrade granted publication privileges to the enrollment role", err)
	}
	migration, err = deploy.AccountResetRedemptionMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema-52 workspace could not install the redemption transaction", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=53 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.redeem_account_reset(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reset_receipt(bytea,uuid,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_data.require_account_reset(uuid,bytea,boolean)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("upgrade granted unrestricted reconciliation or reset context", err)
	}
	if supported, err := session.AccountResetTargetsSupported(ctx); err != nil || supported {
		t.Fatal("schema 53 falsely advertised the reset queue", err)
	}
	migration, err = deploy.AccountResetHandoverMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 53 could not install the reset queue", err)
	}
	if supported, err := session.AccountResetTargetsSupported(ctx); err != nil || !supported {
		t.Fatal("the schema 54 migration did not advertise the reset queue", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=54 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.account_reset_targets(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,integer)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.account_reset_offers','SELECT')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.account_reset_offers','UPDATE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.mark_account_reset_handover(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("schema 54 exposed reset queue or acknowledgement without custodian permissions", err)
	}
	if supported, err := session.ConnectionPathsSupported(ctx); err != nil || supported {
		t.Fatal("schema 54 incorrectly advertised protocol-bound tickets", err)
	}
	migration, err = deploy.WorkspaceImportMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 54 could not install workspace import and authenticated metadata reads", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=55 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.imported_node_data(bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.imported_node_data(bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.imported_node_data(bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.node_import_data','SELECT')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_admin','wormhole_data.node_import_data','SELECT')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("schema 55 interrupted migration history or exposed imported metadata outside admitted devices", err)
	}
	if supported, err := session.ConnectionPathsSupported(ctx); err != nil || !supported {
		t.Fatal("the open session could not detect protocol-bound tickets after upgrade", err)
	}
	if supported, err := session.NoteViewSupported(ctx); err != nil || supported {
		t.Fatal("schema 55 incorrectly advertised note tickets", err)
	}
	migration, err = deploy.ImportedNoteViewMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 55 could not upgrade to protected note View", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=56 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.begin_note_view(bytea,uuid,bigint)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.fetch_note(bytea,uuid,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.fetch_note(bytea,uuid,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.node_note_graph(uuid,uuid,bigint,bigint)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("note tickets or private graph escaped the admitted-device API", err)
	}
	if supported, err := session.NoteViewSupported(ctx); err != nil || !supported {
		t.Fatal("the admitted session could not detect note support after upgrade", err)
	}
	if supported, err := session.WorkspaceImportDestinationsSupported(ctx); err != nil || supported {
		t.Fatal("schema 56 advertised personal destination provisioning", err)
	}
	migration, err = deploy.PersonalImportBoundaryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 56 could not upgrade to personal import destinations", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=57 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.workspace_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,boolean)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.personal_import_signer(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.provision_personal_import_boundary(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,jsonb)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.select_import_boundary(uuid,uuid,boolean)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.boundary_manifests','UPDATE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("personal boundary API escaped its dedicated device and custody gates", err)
	}
	if supported, err := session.WorkspaceImportDestinationsSupported(ctx); err != nil || !supported {
		t.Fatal("the admitted device could not detect the new import APIs", err)
	}
	if supported, err := session.SetupImportSupported(ctx); err != nil || supported {
		t.Fatal("schema 57 advertised signed setup import receipts", err)
	}
	migration, err = deploy.SetupImportReceiptMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 57 could not upgrade to signed setup receipts", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=58 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.setup_import_receipt(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.setup_import_receipt(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.commit_setup_import_graph(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,bytea,uuid)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.workspace_import_receipts','UPDATE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("setup import receipts escaped the device API", err)
	}
	if supported, err := session.SetupImportSupported(ctx); err != nil || !supported {
		t.Fatal("the admitted device could not detect signed setup receipts", err)
	}
	if supported, err := session.AdminInventorySupported(ctx, "accounts"); err != nil || supported {
		t.Fatal("schema 58 advertised administrative inventory", err)
	}
	migration, err = deploy.AdminInventoryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 58 could not upgrade to administrative inventory", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=59 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamptz)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamptz)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamptz)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.audit_log','SELECT')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.sessions','SELECT')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("administrative inventory escaped the device API", err)
	}
	if supported, err := session.AdminGroupsSupported(ctx); err != nil || supported {
		t.Fatal("schema 59 advertised group management", err)
	}
	migration, err = deploy.AdminGroupsMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 59 could not add group management", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=60 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.groups','INSERT,UPDATE,DELETE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.group_members','INSERT,UPDATE,DELETE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("group management escaped the device API", err)
	}
	if supported, err := session.AdminNodeGrantsSupported(ctx); err != nil || supported {
		t.Fatal("schema 60 advertised node grant administration", err)
	}
	migration, err = deploy.NodeGrantAdministrationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 60 could not add node grant administration", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=61 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.grants','INSERT,UPDATE,DELETE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("grant administration escaped the device API", err)
	}
	if available, err := session.GroupKeySupported(ctx); err != nil || available {
		t.Fatal("schema 61 advertised certified group issuance", err)
	}
	migration, err = deploy.GroupKeyProvisioningMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 61 could not add certified group issuance", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=62 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.group_key_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.group_key_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint,bytea)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.group_key_roster(uuid)','EXECUTE')
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.key_copies','INSERT,UPDATE,DELETE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("group key provisioning escaped the custody API", err)
	}
	migration, err = deploy.GroupBoundaryReleaseMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 62 could not add group boundary release", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=63 FROM wormhole_data.workspace_meta WHERE singleton)
    AND NOT EXISTS (SELECT FROM unnest(ARRAY['wh_recovertest_user','wh_recovertest_admin','wh_recovertest_enroll','wh_recovertest_deployer']) u(role)
        WHERE pg_catalog.has_function_privilege(u.role,'wormhole_data.boundary_release_root(uuid,uuid,uuid,integer,uuid,integer,bigint,bigint,integer)','EXECUTE'))
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("group root projection escaped the audited device APIs", err)
	}
	if available, err := session.GroupBoundaryGrantsSupported(ctx); err != nil || available {
		t.Fatal("schema 63 advertised administrative group boundary grants", err)
	}
	migration, err = deploy.GroupBoundaryGrantsMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 63 could not add administrative group boundary grants", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=64 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','`+groupBoundaryGrantSignature+`','EXECUTE')
    AND NOT EXISTS (SELECT FROM unnest(ARRAY['wh_recovertest_enroll','wh_recovertest_deployer']) u(role)
        WHERE pg_catalog.has_function_privilege(u.role,'`+groupBoundaryGrantSignature+`','EXECUTE'))
    AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.boundary_grants','INSERT,UPDATE,DELETE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("group boundary grant publication escaped the custodian API", err)
	}
	if available, err := session.GroupBoundaryRotationSupported(ctx); err != nil || available {
		t.Fatal("schema 64 advertised administrative rotation", err)
	}
	migration, err = deploy.BoundaryRotationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 64 could not add boundary rotation", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
    (SELECT schema_version=65 FROM wormhole_data.workspace_meta WHERE singleton)
    AND pg_catalog.has_function_privilege('wh_recovertest_user','`+boundaryRotationSignature+`','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+boundaryRotationSignature+`','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+boundaryRotationSignature+`','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.publish_boundary_rotation(uuid,jsonb,jsonb,jsonb)','EXECUTE')
    AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.boundary_rotation_graph(uuid,uuid,integer,jsonb,uuid,integer,bigint,bigint)','EXECUTE')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("boundary rotation material or publication escaped the custodian API", err)
	}
	if available, err := session.GroupMemberRotationSupported(ctx); err != nil || available {
		t.Fatal("schema 65 advertised group member rotation", err)
	}
	migration, err = deploy.GroupMemberRotationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 65 could not add durable group member rotation", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=66 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+memberRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+memberRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.group_member_rotation_scope(uuid,uuid,integer)','EXECUTE')
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.group_boundary_rotation_queue','SELECT,INSERT,UPDATE,DELETE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("membership rotation escaped its custodian API", err)
	}
	migration, err = deploy.WorkspaceBoundaryRecoveryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 66 could not add shared boundary recovery", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=67 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.workspace_admin_recovery_boundaries()','EXECUTE')
        AND pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_api_v1.recover_workspace_boundaries(jsonb,text)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.workspace_admin_recovery_boundaries()','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_admin','wormhole_api_v1.recover_workspace_boundaries(jsonb,text)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.recover_workspace_boundaries(jsonb,text)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_data.admin_recovery_boundaries()','EXECUTE')
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_deployer','wormhole_data.workspace_admin_recovery','INSERT')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("boundary recovery material or publication escaped the deployer API", err)
	}
	if available, err := session.GroupMemberAdditionSupported(ctx); err != nil || available {
		t.Fatal("schema 67 announced keyed group addition", err)
	}
	migration, err = deploy.GroupMemberAdditionMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 67 could not add certified group members", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=68 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+memberAdditionSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+memberAdditionSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+memberAdditionSignature+`','EXECUTE')
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.group_member_additions','SELECT,INSERT')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("keyed addition escaped its authenticated API", err)
	}
	if available, err := session.GroupMemberReconciliationSupported(ctx); err != nil || available {
		t.Fatal("schema 68 announced reconciliation support", err)
	}
	migration, err = deploy.GroupRotationReconciliationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 68 could not add rotation reconciliation", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=69 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+memberReconciliationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+memberReconciliationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+memberReconciliationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.rotation_job_roster(wormhole_data.group_member_rotation_jobs)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("reconciliation escaped its authenticated API", err)
	}
	if available, err := session.WorkspaceAccessSupported(ctx); err != nil || available {
		t.Fatal("schema 69 announced access changes", err)
	}
	migration, err = deploy.WorkspaceAccessMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 69 could not add workspace access changes", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=70 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+workspaceAccessSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+workspaceAccessSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+workspaceAccessSignature+`','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("workspace access changes escaped their authenticated API", err)
	}
	if available, err := session.AccountSuspensionSupported(ctx); err != nil || available {
		t.Fatal("schema 70 announced suspension inventory", err)
	}
	migration, err = deploy.AccountSuspensionInventoryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 70 could not add suspension inventory", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=71 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+accountSuspensionInventorySignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+accountSuspensionInventorySignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+accountSuspensionInventorySignature+`','EXECUTE')
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.account_suspension_roots','SELECT')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("suspension inventory escaped its authenticated API", err)
	}
	if available, err := session.AccountBoundaryRotationSupported(ctx); err != nil || available {
		t.Fatal("schema 71 announced account boundary rotation", err)
	}
	migration, err = deploy.AccountBoundaryRotationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 71 could not add account boundary rotation", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=72 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+accountBoundaryRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+accountBoundaryRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+accountBoundaryRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.account_rotation_pending(uuid,integer)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("account rotation escaped its scoped API", err)
	}
	migration, err = deploy.PersonalBoundaryRotationMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 72 could not add personal boundary rotation", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=73 FROM wormhole_data.workspace_meta WHERE singleton)
        AND NOT EXISTS(SELECT FROM unnest(ARRAY['user','admin','enroll','deployer']) AS role(suffix)
            CROSS JOIN unnest(ARRAY['wormhole_data.personal_account_rotation_available(uuid,uuid,uuid)',
                'wormhole_data.personal_account_recovery_required(uuid)']) AS helper(signature)
            WHERE pg_catalog.has_function_privilege('wh_recovertest_'||role.suffix,helper.signature,'EXECUTE'))
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+accountBoundaryRotationSignature+`','EXECUTE')
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+accountSuspensionInventorySignature+`','EXECUTE')
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+workspaceAccessSignature+`','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("personal rotation escaped its existing scoped APIs", err)
	}
	if reply, err := session.AccountSuspensionInventory(ctx, TrustState{}, AccountSuspensionRequest{AccountID: testHintID, Kind: "groups"}); err != nil || reply.Status != "unsupported" {
		t.Fatal("schema 73 did not report an unavailable group inventory capability", reply.Status, err)
	}
	migration, err = deploy.AccountSuspensionGroupsMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 73 could not add the suspension group inventory", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=74 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+accountSuspensionGroupsSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+accountSuspensionGroupsSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+accountSuspensionGroupsSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.suspension_group_page(uuid,uuid,bigint)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("group inventory escaped its scoped API", err)
	}
	if available, err := session.serverCapability(ctx, scopedMemberRotationSupportedSQL); err != nil || available {
		t.Fatal("schema 74 announced suspension-scoped group removal", err)
	}
	migration, err = deploy.ScopedGroupRemovalMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 74 could not add suspension-scoped group removal", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=75 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+memberRotationSignature+`','EXECUTE')
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+scopedMemberRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+scopedMemberRotationSignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+scopedMemberRotationSignature+`','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("scoped group removal changed the authorization of member rotation", err)
	}
	migration, err = deploy.EnrollmentHistoryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 75 could not add enrollment history", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=76 FROM wormhole_data.workspace_meta WHERE singleton)
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_user','wormhole_data.user_enrollment_history','SELECT')
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_admin','wormhole_data.user_enrollment_history','INSERT')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.enrolled_author_certificate(uuid,uuid,integer)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','wormhole_data.enrollment_history_recoverable()','EXECUTE')
        AND wormhole_data.enrollment_history_recoverable()
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("the history migration did not preserve the private enrollment boundary", err)
	}
	migration, err = deploy.SuspensionEnrollmentMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 76 could not scope suspension enrollment", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=77 FROM wormhole_data.workspace_meta WHERE singleton)
        AND NOT pg_catalog.has_table_privilege('wh_recovertest_admin','wormhole_data.account_suspension_enrollments','UPDATE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_data.capture_suspension_enrollment(uuid)','EXECUTE')
        AND wormhole_data.suspension_enrollments_recoverable()
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("suspension enrollment escaped its internal API", err)
	}
	migration, err = deploy.PersonalRootRecoveryMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 77 could not add personal root recovery", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=78 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_user','`+personalRootRecoverySignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','`+personalRootRecoverySignature+`','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_deployer','`+personalRootRecoverySignature+`','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("personal root recovery was exposed to an enrollment or deploy role", err)
	}
	migration, err = deploy.AccountReenrollmentMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 78 could not add replacement offers", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=79 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reenrollment_capsule(uuid,bytea)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.account_reenrollment_capsule(uuid,bytea)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_data.require_account_reenrollment(uuid,bytea,boolean)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reenrollment_material(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,bigint)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("temporary replacement login had privileges outside of download", err)
	}
	migration, err = deploy.AccountReenrollmentRedemptionMigration(tag, testHintID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, migration).ReadAll(); err != nil {
		t.Fatal("schema 79 could not add atomic replacement registration", err)
	}
	row, err = readDeploymentRow(ctx, conn, `SELECT (
        (SELECT schema_version=80 FROM wormhole_data.workspace_meta WHERE singleton)
        AND pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.redeem_account_reenrollment(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea,bytea)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.redeem_account_reenrollment(uuid,bytea,bytea,uuid,text,text,text,bytea,bytea,bytea)','EXECUTE')
        AND pg_catalog.has_function_privilege('wh_recovertest_user','wormhole_api_v1.account_reenrollment_receipt(uuid,bytea,uuid,bytea,bytea)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_api_v1.account_reenrollment_receipt(uuid,bytea,uuid,bytea,bytea)','EXECUTE')
        AND NOT pg_catalog.has_function_privilege('wh_recovertest_enroll','wormhole_data.install_replacement_enrollment(wormhole_data.account_reset_offers,bytea)','EXECUTE')
    )::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("replacement registration or receipt escaped its designated role", err)
	}
}
