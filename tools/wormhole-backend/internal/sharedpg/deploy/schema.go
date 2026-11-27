package deploy

import (
	_ "embed"
	"errors"
	"strconv"
	"strings"
)

//go:embed migrations/0093_admin_credential_slots.sql
var adminCredentialSlotsTemplate string

var adminCredentialSlotsMigration = strings.Replace(adminCredentialSlotsTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("93"), 1)

//go:embed migrations/0094_account_group_roles.sql
var accountGroupRolesTemplate string

var accountGroupRolesMigration = strings.Replace(accountGroupRolesTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("94"), 1)

//go:embed migrations/0095_create_credential_slot.sql
var createCredentialSlotTemplate string

var createCredentialSlotMigration = strings.Replace(createCredentialSlotTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("95"), 1)

//go:embed migrations/0096_public_api_limits.sql
var publicAPILimitsTemplate string

var publicAPILimitsMigration = strings.Replace(publicAPILimitsTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("96"), 1)

// This order matches the individual DBA upgrade scripts. A fresh deployment
// uses the same migrations in a single transaction.
var schemaMigrations = [...]string{
	identityMigration, sessionMigration, keyGraphMigration, sessionProofMigration,
	passwordChangeMigration, accountKeysMigration, accountCertificatesMigration,
	accountStateMigration, tlsTrustMigration, invitationLoginMigration,
	invitationCopiesMigration, accountEnrollmentMigration, invitationCommitMigration,
	deviceConfirmationMigration, invitationCertificationMigration, nodePermissionsMigration,
	treeSnapshotMigration, nodeAuthorMigration, catalogChangesMigration, useIntentsMigration,
	useConsumptionMigration, resolverMigration, resolutionChainMigration, credentialSlotsMigration,
	credentialCatalogMigration, credentialProjectionMigration, selectionProjectionMigration,
	connectionResolutionMigration, boundaryPermissionsMigration, boundaryManifestsMigration,
	connectionSnapshotMigration, credentialValuesMigration, keyCopyProjectionMigration,
	credentialReleaseGraphMigration, fetchSecretMigration, releasePolicyMigration,
	connectionPlanMigration, runtimeStateMigration, nodeSecretManifestsMigration,
	tunnelProfilesMigration, fortinetIPsecMigration, enrolledCatalogAuthorsMigration, tunnelFallbackMigration, workspaceBootstrapMigration,
	serverCertificateRenewalMigration, workspaceCARotationMigration, workspaceRecoveryKitRefreshMigration, workspaceAdminRecoveryMigration,
	workspaceRecoveryExportMigration, workspaceRecoveryRestoreMigration, accountRecoveryCustodyMigration,
	accountResetIssuanceMigration, accountResetRedemptionMigration, accountResetHandoverMigration,
	workspaceImportMigration, importedNoteViewMigration, personalImportBoundaryMigration, setupImportReceiptMigration,
	adminInventoryMigration, adminGroupsMigration, nodeGrantAdministrationMigration,
	groupKeyProvisioningMigration, groupBoundaryReleaseMigration, groupBoundaryGrantsMigration, boundaryRotationMigration,
	groupMemberRotationMigration, workspaceBoundaryRecoveryMigration, groupMemberAdditionMigration, groupRotationReconciliationMigration,
	workspaceAccessMigration, accountSuspensionInventoryMigration, accountBoundaryRotationMigration, personalBoundaryRotationMigration, accountSuspensionGroupsMigration,
	scopedGroupRemovalMigration, enrollmentHistoryMigration, suspensionEnrollmentMigration, personalRootRecoveryMigration, accountReenrollmentMigration,
	accountReenrollmentRedemptionMigration, webSessionViewsMigration, webConnectionPlanMigration, webTunnelReleaseMigration, webSuspensionInventoryMigration,
	auditMaintenanceMigration, unencryptedClientsMigration, sshHostPinMigration, updateNodeMigration, moveNodeMigration, suspensionRotationReceiptsMigration,
	rowSecurityMigration, deviceConnectionLimitMigration, adminCredentialSlotsMigration, accountGroupRolesMigration, createCredentialSlotMigration, publicAPILimitsMigration,
}

const SchemaVersion = len(schemaMigrations)

var errMigrationBoundary = errors.New("invalid shared workspace migration transaction boundary")

// NextMigrationScript renders the same standalone transaction used for this
// version in a fresh installation. Its SQL guard verifies the live identity and
// installed version when the DBA applies it.
func NextMigrationScript(roleTag, workspaceID string, installedVersion int) (string, error) {
	if installedVersion < 1 || installedVersion >= SchemaVersion {
		return "", errors.New("no workspace migration from this version")
	}
	return renderMigration(schemaMigrations[installedVersion], roleTag, workspaceID)
}

// SchemaScript builds a secret-free script for a fresh, dedicated database.
// Run it on a fresh DBA connection. The schema stays in provisioning until
// authenticated organisation data and the first account have been installed.
func SchemaScript(roleTag, workspaceID string) (string, error) {
	if err := ValidateIdentity(roleTag, workspaceID); err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("-- Wormhole fresh workspace schema. Run on a fresh connection.\nBEGIN;\n")
	// A delegated DBA needs temporary use of roles that it creates in this
	// transaction. PostgreSQL records the temporary grants under that DBA.
	script.WriteString("SET LOCAL createrole_self_grant = 'set,inherit';\n")
	for _, migration := range schemaMigrations {
		body, err := migrationBody(migration)
		if err != nil {
			return "", err
		}
		script.WriteString(body)
		// Each standalone migration ends with transaction-local role/settings
		// reset. Restore the role here before the next migration's guard.
		script.WriteString("\nSET LOCAL ROLE NONE;\n")
	}
	script.WriteString(`SET LOCAL ROLE wh_{{TAG}}_owner;
DO $verify$
BEGIN
    IF NOT EXISTS (
        SELECT FROM wormhole_data.workspace_meta
        WHERE singleton AND workspace_id = '{{WORKSPACE_ID}}'::uuid AND role_tag = '{{TAG}}'
          AND state = 'provisioning' AND require_tls AND schema_version = ` + strconv.Itoa(SchemaVersion) + `
    ) THEN
        RAISE EXCEPTION 'Workspace schema preparation was not confirmed' USING ERRCODE='55000';
    END IF;
END
$verify$;
-- Give the temporary DBA schema reconciliation and the one-time bootstrap.
-- It cannot read signed policy, credentials or any other data relation.
DO $inspection$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = session_user AND rolsuper) THEN
        EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA wormhole_data TO %I', session_user);
        EXECUTE pg_catalog.format('GRANT SELECT (singleton, workspace_id, role_tag, schema_version, state, require_tls) ON wormhole_data.workspace_meta TO %I', session_user);
        EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA wormhole_api_v1 TO %I', session_user);
        EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION wormhole_api_v1.bootstrap_workspace(jsonb,text) TO %I', session_user);
    END IF;
END
$inspection$;
SET LOCAL ROLE NONE;
DO $cleanup$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = current_user AND rolsuper) THEN
        REVOKE wh_{{TAG}}_owner, wh_{{TAG}}_observer, wh_{{TAG}}_user, wh_{{TAG}}_admin,
               wh_{{TAG}}_deployer, wh_{{TAG}}_enroll FROM CURRENT_USER GRANTED BY CURRENT_USER;
    END IF;
END
$cleanup$;
COMMIT;
`)
	return substituteIdentity(script.String(), roleTag, workspaceID), nil
}

func migrationBody(migration string) (string, error) {
	migration = strings.TrimSpace(strings.ReplaceAll(migration, "\r\n", "\n"))
	header, body, ok := strings.Cut("\n"+migration, "\nBEGIN;\n")
	if !ok || !strings.HasSuffix(body, "\nCOMMIT;") {
		return "", errMigrationBoundary
	}
	for _, line := range strings.Split(strings.TrimSpace(header), "\n") {
		if line != "" && !strings.HasPrefix(line, "--") {
			return "", errMigrationBoundary
		}
	}
	return strings.TrimSpace(header) + "\n" + strings.TrimSuffix(body, "\nCOMMIT;"), nil
}
