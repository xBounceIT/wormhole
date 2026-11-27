// Package deploy produces versioned, reviewable PostgreSQL deployment scripts.
// It never applies DDL through a runtime workspace connection.
package deploy

import (
	_ "embed"
	"errors"
	"strings"

	"github.com/google/uuid"
)

//go:embed migrations/0001_identity.sql
var identityMigration string

//go:embed migrations/0002_sessions.sql
var sessionMigration string

//go:embed migrations/0003_key_graph.sql
var keyGraphMigration string

//go:embed migrations/0004_session_proofs.sql
var sessionProofMigration string

//go:embed migrations/0005_password_change.sql
var passwordChangeMigration string

//go:embed migrations/0006_account_keys.sql
var accountKeysMigration string

//go:embed migrations/0007_account_certificates.sql
var accountCertificatesMigration string

//go:embed migrations/0008_account_state.sql
var accountStateMigration string

//go:embed migrations/0009_tls_trust.sql
var tlsTrustMigration string

//go:embed migrations/0010_invitation_login.sql
var invitationLoginMigration string

//go:embed migrations/0011_invitation_copies.sql
var invitationCopiesMigration string

//go:embed migrations/0012_account_enrollment.sql
var accountEnrollmentMigration string

//go:embed migrations/0013_invitation_commit.sql
var invitationCommitMigration string

//go:embed migrations/0014_device_confirmation.sql
var deviceConfirmationMigration string

//go:embed migrations/0015_invitation_certification.sql
var invitationCertificationMigration string

//go:embed migrations/0016_node_permissions.sql
var nodePermissionsMigration string

//go:embed migrations/0017_tree_snapshot.sql
var treeSnapshotMigration string

//go:embed migrations/0018_node_author.sql
var nodeAuthorMigration string

//go:embed migrations/0019_catalog_changes.sql
var catalogChangesMigration string

//go:embed migrations/0020_use_intents.sql
var useIntentsMigration string

//go:embed migrations/0021_use_consumption.sql
var useConsumptionMigration string

//go:embed migrations/0022_resolver.sql
var resolverTemplate string

//go:embed fragments/resolver_node_valid.sql
var resolverNodeValidDefinition string

var resolverMigration = strings.ReplaceAll(resolverTemplate, "{{RESOLVER_NODE_VALID_DEFINITION}}",
	strings.ReplaceAll(resolverNodeValidDefinition, "{{IMPORT_RESOLVER_NODE_VALIDATION}}", ""))

//go:embed migrations/0023_resolution_chain.sql
var resolutionChainTemplate string

//go:embed fragments/node_metadata.sql
var nodeMetadataDefinition string

var resolutionChainMigration = strings.ReplaceAll(resolutionChainTemplate, "{{NODE_METADATA_DEFINITION}}",
	strings.ReplaceAll(nodeMetadataDefinition, "{{IMPORT_NODE_METADATA}}", ""))

//go:embed migrations/0024_credential_slots.sql
var credentialSlotsMigration string

//go:embed migrations/0025_credential_catalog.sql
var credentialCatalogMigration string

//go:embed migrations/0026_credential_projection.sql
var credentialProjectionMigration string

//go:embed migrations/0027_selection_projection.sql
var selectionProjectionMigration string

//go:embed migrations/0028_connection_resolution.sql
var connectionResolutionTemplate string

//go:embed fragments/resolve_connection.sql
var resolveConnectionDefinition string

var connectionResolutionMigration = strings.ReplaceAll(connectionResolutionTemplate, "{{RESOLVE_CONNECTION_DEFINITION}}",
	legacyConnectionDefinition.Replace(resolveConnectionDefinition))

//go:embed migrations/0029_boundary_permissions.sql
var boundaryPermissionsMigration string

//go:embed migrations/0030_boundary_manifests.sql
var boundaryManifestsMigration string

//go:embed migrations/0031_connection_snapshot.sql
var connectionSnapshotMigration string

//go:embed migrations/0032_credential_values.sql
var credentialValuesMigration string

//go:embed migrations/0033_key_copy_projection.sql
var keyCopyProjectionMigration string

//go:embed migrations/0034_credential_release_graph.sql
var credentialReleaseGraphMigration string

//go:embed migrations/0035_fetch_secret.sql
var fetchSecretMigration string

//go:embed migrations/0036_release_policy.sql
var releasePolicyMigration string

//go:embed migrations/0037_connection_plan.sql
var connectionPlanTemplate string

//go:embed fragments/connection_plan.sql
var connectionPlanDefinition string

var connectionPlanMigration = strings.ReplaceAll(connectionPlanTemplate, "{{CONNECTION_PLAN_DEFINITION}}",
	legacyConnectionDefinition.Replace(connectionPlanDefinition))

//go:embed migrations/0038_runtime_state.sql
var runtimeStateMigration string

//go:embed migrations/0039_node_secret_manifests.sql
var nodeSecretManifestsMigration string

//go:embed migrations/0040_tunnel_profiles.sql
var tunnelProfilesTemplate string

//go:embed fragments/connection_account_permissions.sql
var connectionAccountPermissionsDefinition string

var tunnelProfilesMigration = strings.ReplaceAll(tunnelProfilesTemplate, "{{ACCOUNT_PERMISSIONS_DEFINITION}}",
	legacyConnectionDefinition.Replace(connectionAccountPermissionsDefinition))

//go:embed migrations/0041_fortinet_ipsec.sql
var fortinetIPsecMigration string

//go:embed migrations/0042_enrolled_catalog_authors.sql
var enrolledCatalogAuthorsTemplate string

//go:embed fragments/connection_snapshot.sql
var connectionSnapshotDefinition string

//go:embed fragments/credential_release_graph.sql
var credentialReleaseTemplate string

var credentialReleaseDefinition = strings.ReplaceAll(credentialReleaseTemplate, "{{CREDENTIAL_BOUNDARY_ROOT}}", `                SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq);
                roots:=roots||jsonb_build_object(label,wormhole_data.key_copy_wire(to_jsonb(item)));`)

var enrolledCatalogAuthorsMigration = strings.NewReplacer(
	"{{CONNECTION_SNAPSHOT_DEFINITION}}", legacyConnectionDefinition.Replace(connectionSnapshotDefinition),
	"{{CREDENTIAL_RELEASE_DEFINITION}}", legacyConnectionDefinition.Replace(credentialReleaseDefinition),
).Replace(enrolledCatalogAuthorsTemplate)

//go:embed migrations/0043_tunnel_fallback.sql
var tunnelFallbackTemplate string

//go:embed fragments/begin_use_intent.sql
var beginUseDefinition string

//go:embed fragments/claim_use_intent.sql
var claimUseDefinition string

//go:embed fragments/fetch_secret.sql
var fetchSecretDefinition string

//go:embed fragments/fallback_permissions.sql
var fallbackPermissionsDefinition string

//go:embed fragments/fallback_release_graph.sql
var fallbackReleaseTemplate string

var fallbackReleaseDefinition = strings.ReplaceAll(fallbackReleaseTemplate, "{{FALLBACK_BOUNDARY_ROOT}}", `            SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq);
            roots:=roots||jsonb_build_object(label,wormhole_data.key_copy_wire(to_jsonb(item)));`)

var tunnelFallbackMigration = strings.NewReplacer(
	"{{BEGIN_USE_DEFINITION}}", legacyConnectionDefinition.Replace(beginUseDefinition),
	"{{CLAIM_USE_DEFINITION}}", legacyConnectionDefinition.Replace(claimUseDefinition),
	"{{FETCH_SECRET_DEFINITION}}", legacyConnectionDefinition.Replace(fetchSecretDefinition),
	"{{FALLBACK_PERMISSIONS_DEFINITION}}", legacyConnectionDefinition.Replace(fallbackPermissionsDefinition),
	"{{FALLBACK_GRAPH_DEFINITION}}", legacyConnectionDefinition.Replace(fallbackReleaseDefinition),
).Replace(tunnelFallbackTemplate)

//go:embed migrations/0044_workspace_bootstrap.sql
var workspaceBootstrapMigration string

//go:embed migrations/0045_server_certificate_renewal.sql
var serverCertificateRenewalMigration string

//go:embed migrations/0046_workspace_ca_rotation.sql
var workspaceCARotationMigration string

//go:embed migrations/0047_workspace_recovery_kit_refresh.sql
var workspaceRecoveryKitRefreshMigration string

//go:embed migrations/0048_workspace_admin_recovery.sql
var workspaceAdminRecoveryMigration string

//go:embed migrations/0049_workspace_recovery_export.sql
var workspaceRecoveryExportTemplate string

//go:embed fragments/export_workspace.sql
var exportWorkspaceDefinition string

//go:embed fragments/admin_recovery_material.sql
var adminRecoveryMaterialDefinition string

var workspaceRecoveryExportMigration = strings.NewReplacer(
	"{{EXPORT_WORKSPACE_DEFINITION}}", strings.NewReplacer("{{IMPORT_EXPORT_ROWS}}", "", "{{PERSONAL_IMPORT_EXPORT_GUARD}}", "").Replace(exportWorkspaceDefinition),
	"{{ADMIN_RECOVERY_MATERIAL_DEFINITION}}", strings.NewReplacer(
		"{{ADDITIONAL_BOUNDARY_GUARD}}", "",
		"{{LEGACY_BOUNDARY_GUARD}}", `    IF EXISTS(SELECT FROM wormhole_data.boundaries r WHERE NOT r.deleted AND r.id<>b.boundary_id) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
`,
	).Replace(adminRecoveryMaterialDefinition),
).Replace(workspaceRecoveryExportTemplate)

//go:embed fragments/restore_workspace.sql
var restoreWorkspaceTemplate string

var restoreWorkspaceDefinition = strings.NewReplacer("{{IMPORT_ARCHIVE_RELATION}}", "", "{{MAX_RECOVERY_SCHEMA}}", "54",
	"{{IMPORT_RESTORE_GUARD}}", "").Replace(restoreWorkspaceTemplate)

//go:embed migrations/0050_workspace_recovery_restore.sql
var workspaceRecoveryRestoreTemplate string

//go:embed migrations/0051_account_recovery_custody.sql
var accountRecoveryCustodyTemplate string

var workspaceRecoveryRestoreMigration = strings.ReplaceAll(workspaceRecoveryRestoreTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreWorkspaceDefinition)
var accountRecoveryCustodyMigration = strings.ReplaceAll(accountRecoveryCustodyTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreWorkspaceDefinition)

//go:embed migrations/0052_account_reset_issuance.sql
var accountResetIssuanceTemplate string

var accountResetIssuanceMigration = strings.ReplaceAll(accountResetIssuanceTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreWorkspaceDefinition)

// AccountResetIssuanceMigration adds account reset offers to schema 51.
func AccountResetIssuanceMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountResetIssuanceMigration, roleTag, workspaceID)
}

//go:embed migrations/0053_account_reset_redemption.sql
var accountResetRedemptionTemplate string

var accountResetRedemptionMigration = strings.ReplaceAll(accountResetRedemptionTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreWorkspaceDefinition)

// AccountResetRedemptionMigration adds atomic reset redemption to schema 52.
func AccountResetRedemptionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountResetRedemptionMigration, roleTag, workspaceID)
}

//go:embed migrations/0054_account_reset_handover.sql
var accountResetHandoverTemplate string

var accountResetHandoverMigration = strings.ReplaceAll(accountResetHandoverTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreWorkspaceDefinition)

// AccountResetHandoverMigration adds a custodian queue to schema 53.
func AccountResetHandoverMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountResetHandoverMigration, roleTag, workspaceID)
}

//go:embed migrations/0055_workspace_import.sql
var workspaceImportTemplate string

//go:embed fragments/workspace_import.sql
var commitWorkspaceImportDefinition string

//go:embed migrations/0056_imported_note_view.sql
var importedNoteViewTemplate string

var legacyConnectionDefinition = strings.NewReplacer(
	"{{PATH_PARAMETER}}", "", "{{PATH_ARG}}", "", "{{PLAN_FUNCTION}}", "connection_plan", "{{PLAN_PERMISSION}}", "2",
	"{{PIN_DECLARATION}}", "", "{{SELECT_PIN}}", "", "{{PATH_WIRE}}", "", "{{PATH_PERMISSIONS}}", "",
	"{{WEB_PLAN_RESOLUTION}}", "", "{{WEB_SNAPSHOT_ACCOUNTS_BEGIN}}", "", "{{WEB_SNAPSHOT_ACCOUNTS_END}}", "",
	"{{APPLY_PROFILE}}", "", "{{APPLY_PROFILE_END}}\n", "", "{{IMPORT_RESOLVER_GUARD}}", "",
	"{{BEGIN_PATH_AUTHORIZATION}}", "", "{{PATH_COLUMN}}", "", "{{BEGIN_PATH_ACTION}}", "", "{{TICKET_PATH_KIND}}", "",
	"{{PATH_RECEIPT_COLUMN}}", "",
	"{{NOT_NOTE_PATH}}", "", "{{CLAIM_NOTE_PERMISSION}}", "",
	"{{UPDATE_PATH_COLUMN}}", "", "{{MATCH_TICKET_PATH}}\n", "",
	"{{FETCH_FUNCTION}}", "fetch_secret", "{{FETCH_KIND}}", "connection", "{{FETCH_PATH_MATCH}}", "",
	"{{FETCH_GRAPH}}", `    PERFORM wormhole_data.connection_account_permissions(p_capability,p_node,ticket.epoch,ticket.change_seq,2);
    result:=wormhole_data.credential_release_graph(p_node,identity.user_id,ticket.epoch,ticket.change_seq);`,
	"{{SKIP_GATEWAY_ROUTE_VALUES}}", "",
	"{{CLAIM_CALL}}", "claim_use(p_capability,p_node,p_ticket)",
	"{{FALLBACK_REPLACE}}", "",
	"{{FALLBACK_PATH_PLAN}}", "    plan:=wormhole_data.connection_account_permissions(p_capability,p_node,p_epoch,p_change_seq,2);",
	"{{FALLBACK_PATH_GRAPH}}", "    source:=wormhole_data.credential_release_graph(p_node,p_user,p_epoch,p_change_seq);",
)

var connectionPathDefinition = strings.NewReplacer(
	"{{PATH_PARAMETER}}", ",p_path text", "{{PATH_ARG}}", ",p_path", "{{PLAN_FUNCTION}}", "connection_plan_path",
	"{{PLAN_PERMISSION}}", "CASE WHEN p_path='reveal' THEN 8 ELSE 2 END",
	"{{NOT_NOTE_PATH}}", "", "{{CLAIM_NOTE_PERMISSION}}", "",
	"{{PIN_DECLARATION}}", " pin jsonb;",
	"{{IMPORT_RESOLVER_GUARD}}", "",
	"{{SELECT_PIN}}", `    IF p_path='default' THEN
        p_path:=wormhole_data.default_use_path((plan->>'protocol')::integer);
    END IF;
    pin:=wormhole_data.retained_account(plan,p_path,wormhole_data.imported_node_body(p_node));
    IF pin IS NOT NULL THEN
        plan:=wormhole_data.apply_retained_account(plan,pin);
    ELSIF p_path='rdp-gateway' THEN
        plan:=wormhole_data.gateway_candidate(plan);
    END IF;
    IF p_path IN ('rdp','rdp-gateway') THEN
        plan:=plan||pg_catalog.jsonb_build_object('gatewayCredentialId','');
    END IF;
`,
	"{{APPLY_PROFILE}}", `        IF pin IS NULL THEN
    `,
	"{{APPLY_PROFILE_END}}", `        ELSIF p_path<>'reveal' AND profile#>>'{metadata,protocol}' IS DISTINCT FROM
                  (CASE plan->>'protocol' WHEN '0' THEN 'ssh' WHEN '7' THEN 'ssh' WHEN '1' THEN 'rdp' WHEN '6' THEN 'vnc' ELSE '' END) THEN
            RAISE EXCEPTION 'Credential metadata unavailable' USING ERRCODE='WH018';
        END IF;`,
	"{{PATH_WIRE}}", `    result:=result||jsonb_build_object('formatVersion',4,'path',
        CASE WHEN p_path='default' THEN wormhole_data.default_use_path((plan->>'protocol')::integer) ELSE p_path END,
        'importedData',encode(wormhole_data.imported_node_body(p_node),'hex'));
`,
	"{{PATH_PERMISSIONS}}", `    IF EXISTS(SELECT FROM wormhole_data.node_import_data d WHERE d.node_id=p_node) THEN
        IF (wormhole_data.effective_permissions(identity.user_id,p_node)&1)<>1 THEN
            RAISE EXCEPTION 'View permission required' USING ERRCODE='42501';
        END IF;
        SELECT n.boundary_id INTO STRICT target_boundary FROM wormhole_data.nodes n WHERE n.id=p_node;
        IF (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
            RAISE EXCEPTION 'Connection boundary permission required' USING ERRCODE='42501';
        END IF;
        target_boundary:=NULL;
        PERFORM wormhole_data.require_imported_pin_permissions(identity.user_id,wormhole_data.imported_node_body(p_node),p_permission);
    END IF;
`,
	"{{BEGIN_PATH_AUTHORIZATION}}", `    IF p_path='default' THEN
        p_path:=wormhole_data.node_default_use_path(p_node,meta.epoch,meta.change_seq);
    END IF;
    IF p_path IS NOT NULL THEN
        IF p_path NOT IN ('ssh','sftp','vnc','rdp') OR p_primary IS NOT NULL OR p_fallback IS NOT NULL THEN
            RAISE EXCEPTION 'Invalid credential path' USING ERRCODE='22023';
        END IF;
        PERFORM wormhole_data.path_release_permissions(p_capability,p_node,meta.epoch,meta.change_seq,p_path);
    END IF;
`,
	"{{PATH_COLUMN}}", ",protocol_path", "{{BEGIN_PATH_ACTION}}", "WHEN p_path IS NOT NULL THEN 'begin_use_path' ",
	"{{PATH_RECEIPT_COLUMN}}", ",protocol_path text",
	"{{TICKET_PATH_KIND}}", "WHEN p_path IS NOT NULL THEN 'connection_path' ",
	"{{UPDATE_PATH_COLUMN}}", ",protocol_path=EXCLUDED.protocol_path",
	"{{MATCH_TICKET_PATH}}", "       OR ticket.protocol_path IS DISTINCT FROM p_path",
	"{{FETCH_FUNCTION}}", "fetch_secret_path", "{{FETCH_KIND}}", "connection_path",
	"{{FETCH_PATH_MATCH}}", " OR ticket.protocol_path IS DISTINCT FROM p_path",
	"{{FETCH_GRAPH}}", `    PERFORM wormhole_data.path_release_permissions(p_capability,p_node,ticket.epoch,ticket.change_seq,p_path);
    IF p_path='rdp' THEN
        result:=wormhole_data.rdp_release_graph(p_node,identity.user_id,ticket.epoch,ticket.change_seq);
    ELSE
        result:=wormhole_data.credential_release_graph(p_node,identity.user_id,ticket.epoch,ticket.change_seq,p_path);
    END IF;`,
	"{{SKIP_GATEWAY_ROUTE_VALUES}}", `        IF p_path='rdp-gateway' AND role_name='tunnel' THEN CONTINUE; END IF;
`,
	"{{CLAIM_CALL}}", "claim_use_intent(p_capability,p_node,p_ticket,NULL,NULL,p_path)",
	"{{FALLBACK_REPLACE}}", " OR REPLACE",
	"{{FALLBACK_PATH_PLAN}}", `    IF EXISTS(SELECT FROM wormhole_data.nodes n WHERE n.id=p_node AND n.imported->'retainedPins'='true'::jsonb) THEN
        plan:=wormhole_data.path_release_permissions(p_capability,p_node,p_epoch,p_change_seq,'default');
    ELSE
        plan:=wormhole_data.connection_account_permissions(p_capability,p_node,p_epoch,p_change_seq,2);
    END IF;`,
	"{{FALLBACK_PATH_GRAPH}}", `    IF EXISTS(SELECT FROM wormhole_data.nodes n WHERE n.id=p_node AND n.imported->'retainedPins'='true'::jsonb) THEN
        IF wormhole_data.node_default_use_path(p_node,p_epoch,p_change_seq)='rdp' THEN
            source:=wormhole_data.rdp_release_graph(p_node,p_user,p_epoch,p_change_seq);
        ELSE
            source:=wormhole_data.credential_release_graph(p_node,p_user,p_epoch,p_change_seq,'default');
        END IF;
    ELSE
        source:=wormhole_data.credential_release_graph(p_node,p_user,p_epoch,p_change_seq);
    END IF;`,
)

var workspaceImportMigration = strings.NewReplacer(
	"{{RESOLVER_NODE_VALID_DEFINITION}}", strings.ReplaceAll(strings.Replace(resolverNodeValidDefinition, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
		"{{IMPORT_RESOLVER_NODE_VALIDATION}}", ` IF n ? 'imported' THEN
  IF NOT wormhole_data.valid_import_reference(n->'imported') THEN RETURN false; END IF;
  n:=n-'imported';
 END IF;
`),
	"{{NODE_METADATA_DEFINITION}}", strings.ReplaceAll(strings.Replace(nodeMetadataDefinition, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
		"{{IMPORT_NODE_METADATA}}", ` || CASE WHEN ($1).imported IS NULL THEN '{}'::jsonb ELSE pg_catalog.jsonb_build_object('imported',($1).imported) END`),
	"{{RESOLVE_CONNECTION_DEFINITION}}", legacyConnectionDefinition.Replace(strings.Replace(strings.Replace(
		resolveConnectionDefinition, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
		"{{IMPORT_RESOLVER_GUARD}}", `    IF EXISTS(SELECT FROM wormhole_data.nodes WHERE id=p_node AND imported->'retainedPins'='true'::jsonb) THEN
        RAISE EXCEPTION 'Imported resolver pins require a compatible client and server' USING ERRCODE='WH026';
    END IF;
`, 1)),
	"{{CONNECTION_PATH_DEFINITIONS}}", strings.NewReplacer(
		"{{WEB_PLAN_RESOLUTION}}", "", "{{WEB_SNAPSHOT_ACCOUNTS_BEGIN}}", "", "{{WEB_SNAPSHOT_ACCOUNTS_END}}", "",
	).Replace(connectionPathDefinition.Replace(resolveConnectionDefinition+
		connectionSnapshotDefinition+connectionAccountPermissionsDefinition+connectionPlanDefinition)),
	"{{PATH_RELEASE_DEFINITIONS}}", connectionPathDefinition.Replace(credentialReleaseDefinition+
		beginUseDefinition+claimUseDefinition+fetchSecretDefinition+fallbackPermissionsDefinition+fallbackReleaseDefinition),
	"{{COMMIT_WORKSPACE_IMPORT_DEFINITION}}", renderWorkspaceImportFunction(false),
	"{{EXPORT_WORKSPACE_DEFINITION}}", exportImportedWorkspaceDefinition(""),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("55", ""),
).Replace(workspaceImportTemplate)

func exportImportedWorkspaceDefinition(personalGuard string) string {
	return strings.NewReplacer("{{PERSONAL_IMPORT_EXPORT_GUARD}}", personalGuard, "{{IMPORT_EXPORT_ROWS}}", `
        UNION ALL
        SELECT 'node_import_data'::text,pg_catalog.to_jsonb(i) FROM wormhole_data.node_import_data i`,
	).Replace(strings.Replace(exportWorkspaceDefinition, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
}

func restoreImportedWorkspaceDefinition(maxSchema, personalGuard string) string {
	return strings.NewReplacer("{{IMPORT_ARCHIVE_RELATION}}", ",'node_import_data'", "{{MAX_RECOVERY_SCHEMA}}", maxSchema,
		"{{IMPORT_RESTORE_GUARD}}", `    IF (original.schema_version<55 AND grouped ? 'node_import_data') OR
       EXISTS(SELECT FROM wormhole_data.nodes n LEFT JOIN wormhole_data.node_import_data i ON i.node_id=n.id
        WHERE (n.imported IS NULL) IS DISTINCT FROM (i.body IS NULL)
           OR n.imported->>'digest' IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(i.body),'hex')) THEN
        RAISE EXCEPTION 'Workspace archive imported node data mismatch' USING ERRCODE='WH002';
    END IF;
`+personalGuard).Replace(restoreWorkspaceTemplate)
}

func renderWorkspaceImportFunction(viewNotes bool) string {
	if !viewNotes {
		return strings.NewReplacer(
			"{{IMPORT_REPLACE}}", "", "{{NOTE_DECLARATIONS}}", "", "{{NOTE_BOUNDARY}}\n", "",
			"{{NOTE_FORMAT_INVALID}}", "extra->'formatVersion' IS DISTINCT FROM '1'::jsonb",
			"{{NOTE_REFERENCE_CHECK}}", "",
			"{{NOTE_RESET}}", "", "{{NOTE_FORMAT_SELECT}}", "", "{{NOTE_FORMAT_INTO}}", "",
			"{{NOTE_USE_VIEW_HOLDER}}", "", "{{VALUE_HOLDER}}", "holders->boundary::text",
		).Replace(commitWorkspaceImportDefinition)
	}
	return strings.NewReplacer(
		"{{IMPORT_REPLACE}}", " OR REPLACE",
		"{{NOTE_DECLARATIONS}}", " note_format text; view_holders jsonb:='{}'; value_holder jsonb;",
		"{{NOTE_BOUNDARY}}", "        view_holders:=view_holders||pg_catalog.jsonb_build_object(boundary::text,manifest#>'{view,key}');",
		"{{NOTE_FORMAT_INVALID}}", `NOT COALESCE(extra->'formatVersion'='1'::jsonb OR
                    (extra->'formatVersion'='2'::jsonb AND extra->'noteVersion'='1'::jsonb),false)`,
		"{{NOTE_REFERENCE_CHECK}}", `
               OR (node_row.imported->'noteVersion') IS DISTINCT FROM
                    (CASE WHEN extra->'formatVersion'='2'::jsonb THEN extra->'noteVersion' END)`,
		"{{NOTE_RESET}}", " note_format:=NULL;",
		"{{NOTE_FORMAT_SELECT}}", ", (pg_catalog.convert_from(i.body,'UTF8')::jsonb)->>'formatVersion'",
		"{{NOTE_FORMAT_INTO}}", ",note_format",
		"{{NOTE_USE_VIEW_HOLDER}}", `        value_holder:=holders->boundary::text;
        IF value_row.owner_kind='node' AND value_row.field='notes' AND note_format='2' THEN
            value_holder:=view_holders->boundary::text;
            IF NOT EXISTS(SELECT FROM wormhole_data.keys k
                WHERE (k.key_id,k.key_version)=((value_holder->>'id')::uuid,(value_holder->>'version')::integer)
                  AND k.owner_id=boundary AND k.kind='boundary-view' AND k.status='active' AND k.suite=2) THEN
                RAISE EXCEPTION 'Workspace import view root is unavailable' USING ERRCODE='WH025';
            END IF;
        END IF;
`,
		"{{VALUE_HOLDER}}", "value_holder",
	).Replace(commitWorkspaceImportDefinition)
}

//go:embed fragments/node_note_graph.sql
var nodeNoteGraphTemplate string

var importedNoteViewMigration = strings.NewReplacer(
	"{{NODE_NOTE_GRAPH_DEFINITION}}", strings.ReplaceAll(nodeNoteGraphTemplate, "{{NOTE_BOUNDARY_ROOT}}", `        SELECT * INTO STRICT copy FROM wormhole_data.key_copy_record(root,root_version,enrolled.encryption_key_id,enrolled.encryption_key_version,p_epoch,p_change_seq);
        root_wire:=wormhole_data.key_copy_wire(pg_catalog.to_jsonb(copy));`),
	"{{NOTE_TICKET_DEFINITIONS}}", renderNoteTicketDefinitions(),
	"{{FETCH_NOTE_DEFINITION}}", connectionPathDefinition.Replace(strings.NewReplacer(
		"{{FETCH_FUNCTION}}", "fetch_note", "{{PATH_PARAMETER}}", "",
		"{{FETCH_PATH_MATCH}}", " OR ticket.protocol_path IS DISTINCT FROM 'notes'",
		"{{FETCH_GRAPH}}", "    result:=wormhole_data.node_note_graph(p_node,identity.user_id,ticket.epoch,ticket.change_seq);",
		"{{CLAIM_CALL}}", "claim_use_intent(p_capability,p_node,p_ticket,NULL,NULL,'notes')",
	).Replace(fetchSecretDefinition)),
	"{{COMMIT_WORKSPACE_IMPORT_DEFINITION}}", renderWorkspaceImportFunction(true),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("56", ""),
).Replace(importedNoteViewTemplate)

func renderNoteTicketDefinitions() string {
	return connectionPathDefinition.Replace(strings.NewReplacer(
		"CREATE FUNCTION", "CREATE OR REPLACE FUNCTION",
		"{{NOT_NOTE_PATH}}", "p_path IS DISTINCT FROM 'notes' AND ",
		"{{CLAIM_NOTE_PERMISSION}}", `    IF p_path='notes' THEN
        PERFORM wormhole_data.note_view_target(identity.user_id,p_node);
    END IF;
`,
		"{{BEGIN_PATH_AUTHORIZATION}}", `    IF p_path='default' THEN
        p_path:=wormhole_data.node_default_use_path(p_node,meta.epoch,meta.change_seq);
    END IF;
    IF p_path='notes' AND p_primary IS NULL AND p_fallback IS NULL AND p_source='ui' THEN
        PERFORM wormhole_data.note_view_target(identity.user_id,p_node);
    ELSIF p_path IS NOT NULL THEN
        IF p_path NOT IN ('ssh','sftp','vnc','rdp') OR p_primary IS NOT NULL OR p_fallback IS NOT NULL THEN
            RAISE EXCEPTION 'Invalid credential path' USING ERRCODE='22023';
        END IF;
        PERFORM wormhole_data.path_release_permissions(p_capability,p_node,meta.epoch,meta.change_seq,p_path);
    END IF;
`,
		"{{BEGIN_PATH_ACTION}}", "WHEN p_path='notes' THEN 'begin_note_view' WHEN p_path IS NOT NULL THEN 'begin_use_path' ",
	).Replace(beginUseDefinition + claimUseDefinition))
}

// ImportedNoteViewMigration upgrades a schema-55 workspace for protected notes.
func ImportedNoteViewMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(importedNoteViewMigration, roleTag, workspaceID)
}

//go:embed migrations/0057_personal_import_boundary.sql
var personalImportBoundaryTemplate string

var personalImportBoundaryMigration = strings.NewReplacer(
	"{{ADMIN_RECOVERY_MATERIAL_DEFINITION}}", strings.NewReplacer(
		"{{LEGACY_BOUNDARY_GUARD}}", "",
		"{{ADDITIONAL_BOUNDARY_GUARD}}", `    IF NOT wormhole_data.personal_import_boundaries_recoverable(meta.workspace_id)
        OR EXISTS(SELECT FROM wormhole_data.boundaries r WHERE NOT r.deleted AND r.id<>b.boundary_id AND r.owner_user_id IS NULL) THEN
        RAISE EXCEPTION 'Workspace recovery graph is unsupported' USING ERRCODE='WH020';
    END IF;
`,
	).Replace(adminRecoveryMaterialDefinition),
	"{{EXPORT_WORKSPACE_DEFINITION}}", exportImportedWorkspaceDefinition(`    IF NOT wormhole_data.personal_import_boundaries_recoverable('{{WORKSPACE_ID}}'::uuid) THEN
        RAISE EXCEPTION 'Personal import recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
`),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("57", restorePersonalImportGuard),
).Replace(personalImportBoundaryTemplate)

const restorePersonalImportGuard = `    IF original.schema_version>=57
        AND NOT wormhole_data.personal_import_boundaries_recoverable(original.workspace_id) THEN
        RAISE EXCEPTION 'Personal import recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
`

// PersonalImportBoundaryMigration upgrades schema 56 for personal imports.
func PersonalImportBoundaryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(personalImportBoundaryMigration, roleTag, workspaceID)
}

//go:embed migrations/0058_setup_import_receipt.sql
var setupImportReceiptTemplate string

var setupImportReceiptMigration = strings.NewReplacer(
	"{{SETUP_IMPORT_GRAPH_DEFINITION}}", strings.NewReplacer(
		"wormhole_api_v1.commit_workspace_import(", "wormhole_data.commit_setup_import_graph(",
		"p_document text,p_signature bytea) RETURNS text", "p_document text,p_signature bytea,p_request uuid) RETURNS text",
		"OR request IS NULL OR", "OR request IS DISTINCT FROM p_request OR request IS NULL OR",
	).Replace(renderWorkspaceImportFunction(true)),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("58", restorePersonalImportGuard),
).Replace(setupImportReceiptTemplate)

func SetupImportReceiptMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(setupImportReceiptMigration, roleTag, workspaceID)
}

//go:embed migrations/0059_admin_inventory.sql
var adminInventoryTemplate string

var adminInventoryMigration = strings.ReplaceAll(adminInventoryTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("59", restorePersonalImportGuard))

// AdminInventoryMigration upgrades schema 58 for read-only administration.
func AdminInventoryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(adminInventoryMigration, roleTag, workspaceID)
}

//go:embed migrations/0060_admin_groups.sql
var adminGroupsTemplate string

var adminGroupsMigration = strings.ReplaceAll(adminGroupsTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("60", restorePersonalImportGuard))

func AdminGroupsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(adminGroupsMigration, roleTag, workspaceID)
}

//go:embed migrations/0061_node_grant_administration.sql
var nodeGrantAdministrationTemplate string

var nodeGrantAdministrationMigration = strings.ReplaceAll(nodeGrantAdministrationTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("61", restorePersonalImportGuard))

func NodeGrantAdministrationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(nodeGrantAdministrationMigration, roleTag, workspaceID)
}

//go:embed migrations/0062_group_key_provisioning.sql
var groupKeyProvisioningTemplate string

//go:embed fragments/group_key_roster.sql
var groupRosterTemplate string

func renderGroupRoster(name, args, filter string) string {
	return strings.NewReplacer("{{GROUP_ROSTER_NAME}}", name, "{{GROUP_ROSTER_OMIT_ARG}}", args,
		"{{GROUP_ROSTER_OMIT_FILTER}}", filter).Replace(groupRosterTemplate)
}

const groupKeysExportGuard = `    IF NOT wormhole_data.personal_import_boundaries_recoverable('{{WORKSPACE_ID}}'::uuid)
        OR NOT wormhole_data.group_keys_recoverable('{{WORKSPACE_ID}}'::uuid) THEN
        RAISE EXCEPTION 'Workspace key recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
`

var groupKeyProvisioningMigration = strings.NewReplacer(
	"{{GROUP_KEY_ROSTER_DEFINITION}}", renderGroupRoster("group_key_roster", "", ""),
	"{{GROUP_KEYS_EXPORT_DEFINITION}}", exportImportedWorkspaceDefinition(groupKeysExportGuard),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("62", restorePersonalImportGuard+restoreGroupKeysGuard),
).Replace(groupKeyProvisioningTemplate)

func GroupKeyProvisioningMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupKeyProvisioningMigration, roleTag, workspaceID)
}

//go:embed migrations/0063_group_boundary_release.sql
var groupBoundaryReleaseTemplate string

const restoreGroupKeysGuard = `    IF original.schema_version>=62 AND NOT wormhole_data.group_keys_recoverable(original.workspace_id) THEN
        RAISE EXCEPTION 'Workspace group recovery copies are unavailable' USING ERRCODE='WH020';
    END IF;
`

var groupBoundaryReleaseMigration = strings.NewReplacer(
	"{{GROUP_BOUNDARY_RELEASE_DEFINITIONS}}", groupBoundaryReleaseDefinitions(),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("63", restorePersonalImportGuard+restoreGroupKeysGuard),
).Replace(groupBoundaryReleaseTemplate)

func groupBoundaryReleaseDefinitions() string {
	credential := strings.ReplaceAll(credentialReleaseTemplate, "{{CREDENTIAL_BOUNDARY_ROOT}}", `                roots:=roots||jsonb_build_object(label,wormhole_data.boundary_release_root(
                    (profile_row->>5)::uuid,p_user,root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq,2));`)
	note := strings.ReplaceAll(strings.Replace(nodeNoteGraphTemplate, "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
		"{{NOTE_BOUNDARY_ROOT}}", `        root_wire:=wormhole_data.boundary_release_root(item.boundary_id,p_user,root,root_version,
            enrolled.encryption_key_id,enrolled.encryption_key_version,p_epoch,p_change_seq,CASE WHEN root_label='view' THEN 1 ELSE 2 END);`)
	return legacyConnectionDefinition.Replace(credential) + connectionPathDefinition.Replace(credential+groupFallbackReleaseDefinition) + note
}

var groupFallbackReleaseDefinition = strings.ReplaceAll(fallbackReleaseTemplate, "{{FALLBACK_BOUNDARY_ROOT}}", `            roots:=roots||jsonb_build_object(label,wormhole_data.boundary_release_root(
                target.boundary_id,p_user,root_id,root_version,holder_id,holder_version,p_epoch,p_change_seq,2));`)

func GroupBoundaryReleaseMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupBoundaryReleaseMigration, roleTag, workspaceID)
}

//go:embed migrations/0064_group_boundary_grants.sql
var groupBoundaryGrantsTemplate string

var groupBoundaryGrantsMigration = strings.ReplaceAll(groupBoundaryGrantsTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("64", restorePersonalImportGuard+restoreGroupKeysGuard))

func GroupBoundaryGrantsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupBoundaryGrantsMigration, roleTag, workspaceID)
}

//go:embed migrations/0065_boundary_rotation.sql
var boundaryRotationTemplate string

//go:embed fragments/boundary_rotation_api.sql
var boundaryRotationAPI string

var boundaryRotationMigration = strings.NewReplacer(
	"{{BOUNDARY_ROTATION_API}}", strings.ReplaceAll(boundaryRotationAPI, "{{BOUNDARY_ROTATION_PENDING_GUARD}}", ""),
	"{{RESTORE_WORKSPACE_DEFINITION}}", restoreImportedWorkspaceDefinition("65", restorePersonalImportGuard+restoreGroupKeysGuard),
).Replace(boundaryRotationTemplate)

func BoundaryRotationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(boundaryRotationMigration, roleTag, workspaceID)
}

//go:embed migrations/0066_group_member_rotation.sql
var groupMemberRotationTemplate string

//go:embed fragments/group_member_rotation.sql
var groupMemberRotationAPI string

//go:embed fragments/group_member_boundary_worker.sql
var memberBoundaryWorkerAPI string

//go:embed fragments/group_member_boundary_single_job.sql
var memberBoundarySingleJobGraph string

var memberBoundaryLegacyWorker = strings.NewReplacer(
	"{{MEMBER_BOUNDARY_WORKER_CREATE}}", "CREATE FUNCTION",
	"{{MEMBER_BOUNDARY_EXTRA_LOCALS}}", `    retained record; group_mask integer; rotation_graph jsonb; root jsonb; purpose integer;
    replacement jsonb; roster_raw bytea;`,
	"{{MEMBER_BOUNDARY_GENERATION}}", "job.retired_version+1",
	"{{MEMBER_BOUNDARY_REVISION}}", "job.group_revision",
	"{{MEMBER_BOUNDARY_GRAPH}}", memberBoundarySingleJobGraph,
	"{{MEMBER_BOUNDARY_FINISH}}", `    DELETE FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job AND q.boundary_id=p_boundary;
    IF NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=p_job) THEN
        UPDATE wormhole_data.group_member_rotation_jobs j SET complete=true WHERE j.id=p_job;
    END IF;`,
).Replace(memberBoundaryWorkerAPI)

const rotationArchiveRelations = ",'group_member_rotation_jobs','group_boundary_rotation_queue'"

const rotationArchiveCheck = `    IF NOT wormhole_data.group_rotation_queue_recoverable() THEN
        RAISE EXCEPTION 'Workspace member rotation backlog is incomplete' USING ERRCODE='WH020';
    END IF;
`

func renderRotationExport() string {
	export := exportImportedWorkspaceDefinition(groupKeysExportGuard + rotationArchiveCheck)
	return strings.Replace(export,
		"SELECT 'node_import_data'::text,pg_catalog.to_jsonb(i) FROM wormhole_data.node_import_data i",
		`SELECT 'node_import_data'::text,pg_catalog.to_jsonb(i) FROM wormhole_data.node_import_data i
        UNION ALL
        SELECT 'group_member_rotation_jobs'::text,to_jsonb(j) FROM wormhole_data.group_member_rotation_jobs j
        UNION ALL
        SELECT 'group_boundary_rotation_queue'::text,to_jsonb(q) FROM wormhole_data.group_boundary_rotation_queue q`, 1)
}

func renderRotationRestore(maxSchema string) string {
	return strings.Replace(restoreImportedWorkspaceDefinition(maxSchema, restorePersonalImportGuard+restoreGroupKeysGuard+`
    IF original.schema_version<66 AND (grouped ? 'group_member_rotation_jobs' OR grouped ? 'group_boundary_rotation_queue') THEN
        RAISE EXCEPTION 'Workspace archive member rotation records are unsupported' USING ERRCODE='WH020';
    END IF;
`+rotationArchiveCheck), ",'node_import_data'", ",'node_import_data'"+rotationArchiveRelations, 1)
}

func renderPendingRotationGuard() string {
	const fn = "CREATE FUNCTION wormhole_api_v1.rotate_group_boundary("
	_, definition, _ := strings.Cut(boundaryRotationAPI, fn)
	definition, _, _ = strings.Cut(definition, "REVOKE ALL ON FUNCTION")
	return "CREATE OR REPLACE FUNCTION wormhole_api_v1.rotate_group_boundary(" +
		strings.Replace(definition, "{{BOUNDARY_ROTATION_PENDING_GUARD}}", `    IF EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=p_boundary) THEN
        status:='unavailable'; RETURN NEXT; RETURN;
    END IF;`, 1)
}

var groupMemberRotationMigration = strings.NewReplacer(
	"{{POST_REMOVAL_ROSTER_DEFINITION}}", renderGroupRoster("group_key_roster_after_removal", ",p_member uuid", " AND m.user_id IS DISTINCT FROM p_member"),
	"{{GROUP_MEMBER_ROTATION_API}}", groupMemberRotationAPI,
	"{{MEMBER_BOUNDARY_WORKER}}", memberBoundaryLegacyWorker,
	"{{ROTATION_EXPORT_DEFINITION}}", renderRotationExport(),
	"{{RESTORE_WORKSPACE_DEFINITION}}", renderRotationRestore("66"),
	"{{PENDING_ROTATION_GUARDS}}", renderPendingRotationGuard(),
).Replace(groupMemberRotationTemplate)

func GroupMemberRotationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupMemberRotationMigration, roleTag, workspaceID)
}

//go:embed migrations/0067_workspace_boundary_recovery.sql
var workspaceBoundaryRecoveryTemplate string

var workspaceBoundaryRecoveryMigration = strings.ReplaceAll(workspaceBoundaryRecoveryTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", renderRotationRestore("67"))

// WorkspaceBoundaryRecoveryMigration upgrades schema 66 for shared boundary recovery.
func WorkspaceBoundaryRecoveryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceBoundaryRecoveryMigration, roleTag, workspaceID)
}

//go:embed migrations/0068_group_member_addition.sql
var groupMemberAdditionTemplate string

var groupMemberAdditionMigration = strings.ReplaceAll(groupMemberAdditionTemplate,
	"{{RESTORE_WORKSPACE_DEFINITION}}", renderRotationRestore("68"))

func GroupMemberAdditionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupMemberAdditionMigration, roleTag, workspaceID)
}

//go:embed migrations/0069_group_rotation_reconciliation.sql
var groupRotationReconciliationTemplate string

var groupRotationReconciliationMigration = strings.NewReplacer(
	"{{MEMBER_BOUNDARY_WORKER}}", strings.NewReplacer(
		"CREATE FUNCTION wormhole_api_v1.group_member_rotation_status(", "CREATE OR REPLACE FUNCTION wormhole_api_v1.group_member_rotation_status(",
		"{{MEMBER_BOUNDARY_WORKER_CREATE}}", "CREATE OR REPLACE FUNCTION",
		"{{MEMBER_BOUNDARY_EXTRA_LOCALS}}", "",
		"{{MEMBER_BOUNDARY_GENERATION}}", "COALESCE(job.replacement_version,job.retired_version+1)",
		"{{MEMBER_BOUNDARY_REVISION}}", "COALESCE(job.replacement_revision,job.group_revision)",
		"{{MEMBER_BOUNDARY_GRAPH}}", `    next_graph:=wormhole_data.member_rotation_joint_graph(p_boundary,job.group_id,mask,old,
        recipient.key_id,recipient.key_version,meta.epoch,meta.change_seq);
    IF next_graph IS NULL THEN status:='roster-changed'; RETURN NEXT; RETURN; END IF;`,
		"{{MEMBER_BOUNDARY_FINISH}}", `    WITH finished AS (
        DELETE FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=p_boundary AND (q.purpose&mask)<>0 RETURNING q.job_id
    )
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        admin_boundary_id,admin_group_id,admin_subject_id)
    SELECT actor.actor,actor.session_id,session_user,'ui','member_boundary_rotation','success',inet_client_addr(),actor.app_version,
        p_boundary,j.group_id,j.removed_user_id FROM (SELECT DISTINCT job_id FROM finished WHERE job_id<>p_job) f
        JOIN wormhole_data.group_member_rotation_jobs j ON j.id=f.job_id;
    UPDATE wormhole_data.group_member_rotation_jobs j SET complete=true WHERE NOT j.complete
        AND NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=j.id);`,
	).Replace(memberBoundaryWorkerAPI),
	"{{RESTORE_WORKSPACE_DEFINITION}}", renderRotationRestore("69"),
).Replace(groupRotationReconciliationTemplate)

func GroupRotationReconciliationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(groupRotationReconciliationMigration, roleTag, workspaceID)
}

//go:embed migrations/0070_workspace_access.sql
var workspaceAccessTemplate string

var workspaceAccessMigration = strings.NewReplacer(
	"{{CHANGE_PASSWORD_DEFINITION}}", changePasswordWithoutRevokedDevices(),
	"{{ADMIN_INVENTORY_DEFINITION}}", inventoryWithOwnDevices(),
	"{{RESTORE_WORKSPACE_DEFINITION}}", renderRotationRestore("70"),
).Replace(workspaceAccessTemplate)

func inventoryWithOwnDevices() string {
	const declaration = "CREATE FUNCTION wormhole_api_v1.admin_inventory("
	_, definition, _ := strings.Cut(adminInventoryTemplate, declaration)
	definition, _, _ = strings.Cut(definition, "{{RESTORE_WORKSPACE_DEFINITION}}")
	return "CREATE OR REPLACE FUNCTION wormhole_api_v1.admin_inventory(" + strings.NewReplacer(
		"'accounts','devices','sessions','audit'", "'accounts','devices','my-devices','sessions','audit'",
		"('accounts','devices')", "('accounts','devices','my-devices')",
		"IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)",
		"IF (p_kind<>'my-devices' AND NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled))",
		"WHEN 'devices' THEN", "WHEN 'devices','my-devices' THEN",
		"WHERE p_after IS NULL OR d.id>p_after ORDER BY d.id LIMIT 26",
		"WHERE (p_after IS NULL OR d.id>p_after) AND (p_kind<>'my-devices' OR d.user_id=actor.user_id) ORDER BY d.id LIMIT 26",
	).Replace(definition)
}

func changePasswordWithoutRevokedDevices() string {
	const declaration = "CREATE FUNCTION wormhole_api_v1.change_password("
	_, definition, _ := strings.Cut(passwordChangeMigration, declaration)
	definition, _, _ = strings.Cut(definition, "REVOKE ALL ON FUNCTION")
	definition = strings.Replace(definition, "d.user_id=identity.user_id ORDER BY d.id LOOP",
		"d.user_id=identity.user_id AND d.status<>'revoked' ORDER BY d.id LOOP", 1)
	return "CREATE OR REPLACE FUNCTION wormhole_api_v1.change_password(" + definition
}

// WorkspaceAccessMigration adds audited account and device access changes.
func WorkspaceAccessMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceAccessMigration, roleTag, workspaceID)
}

//go:embed migrations/0071_account_suspension_inventory.sql
var accountSuspensionInventoryTemplate string

const suspensionArchiveRelations = ",'account_suspensions','account_suspension_roots','account_suspension_passwords'"
const suspensionArchiveCheck = `    IF NOT wormhole_data.account_suspensions_recoverable() THEN
        RAISE EXCEPTION 'Workspace account suspension records are inconsistent' USING ERRCODE='WH020';
    END IF;
`

func renderSuspensionExport() string {
	return strings.NewReplacer(
		rotationArchiveCheck, rotationArchiveCheck+suspensionArchiveCheck,
		"SELECT 'group_boundary_rotation_queue'::text,to_jsonb(q) FROM wormhole_data.group_boundary_rotation_queue q",
		`SELECT 'group_boundary_rotation_queue'::text,to_jsonb(q) FROM wormhole_data.group_boundary_rotation_queue q
        UNION ALL SELECT 'account_suspensions'::text,to_jsonb(s) FROM wormhole_data.account_suspensions s
        UNION ALL SELECT 'account_suspension_roots'::text,to_jsonb(r) FROM wormhole_data.account_suspension_roots r
        UNION ALL SELECT 'account_suspension_passwords'::text,to_jsonb(p) FROM wormhole_data.account_suspension_passwords p`,
	).Replace(renderRotationExport())
}

var accountSuspensionInventoryMigration = strings.NewReplacer(
	"{{SUSPENSION_EXPORT_DEFINITION}}", renderSuspensionExport(),
	"{{SUSPENSION_RESTORE_DEFINITION}}", renderSuspensionRestore("71"),
).Replace(accountSuspensionInventoryTemplate)

func renderSuspensionRestore(maxSchema string) string {
	return strings.NewReplacer(
		rotationArchiveRelations, rotationArchiveRelations+suspensionArchiveRelations,
		rotationArchiveCheck, rotationArchiveCheck+`    IF original.schema_version<71 AND
        (grouped ? 'account_suspensions' OR grouped ? 'account_suspension_roots' OR grouped ? 'account_suspension_passwords') THEN
        RAISE EXCEPTION 'Workspace archive suspension records are unsupported' USING ERRCODE='WH020';
    END IF;
`+suspensionArchiveCheck,
	).Replace(renderRotationRestore(maxSchema))
}

// AccountSuspensionInventoryMigration persists the scope reviewed after suspension.
func AccountSuspensionInventoryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountSuspensionInventoryMigration, roleTag, workspaceID)
}

//go:embed migrations/0072_account_boundary_rotation.sql
var accountBoundaryRotationTemplate string

var accountBoundaryRotationMigration = strings.NewReplacer(
	"{{SUSPENSION_RESTORE_DEFINITION}}", renderSuspensionRestore("72"),
	"{{ACCOUNT_GROUP_ROTATION_SCOPE}}", strings.NewReplacer(
		"CREATE FUNCTION wormhole_data.group_member_rotation_scope(p_actor uuid,p_key uuid,p_version integer)",
		"CREATE FUNCTION wormhole_data.group_member_rotation_scope(p_actor uuid,p_key uuid,p_version integer,p_member uuid)",
		"OR EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=item.owner_id) THEN",
		`OR (EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.boundary_id=item.owner_id)
                AND NOT EXISTS(SELECT FROM wormhole_data.account_suspension_roots r
                    JOIN wormhole_data.users u ON u.id=r.account_id
                    WHERE r.account_id=p_member AND u.disabled AND
                        (r.boundary_id,r.root_id,r.root_version)=(item.owner_id,item.key_id,item.key_version))) THEN`,
		"CREATE FUNCTION wormhole_api_v1.rotate_group_member(", "CREATE OR REPLACE FUNCTION wormhole_api_v1.rotate_group_member(",
		"group_member_rotation_scope(actor.actor,old.key_id,old.key_version)",
		"group_member_rotation_scope(actor.actor,old.key_id,old.key_version,p_member)",
		"group_member_rotation_scope(uuid,uuid,integer),", "group_member_rotation_scope(uuid,uuid,integer,uuid),",
	).Replace(groupMemberRotationAPI),
).Replace(accountBoundaryRotationTemplate)

// AccountBoundaryRotationMigration adds manual rotation for suspended accounts.
func AccountBoundaryRotationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountBoundaryRotationMigration, roleTag, workspaceID)
}

//go:embed migrations/0073_personal_boundary_rotation.sql
var personalBoundaryRotationTemplate string

func replaceMigrationFunction(source, signature, end string) string {
	_, body, _ := strings.Cut(source, "CREATE FUNCTION "+signature)
	body, _, _ = strings.Cut(body, end)
	return "CREATE OR REPLACE FUNCTION " + signature + body
}

var personalAccountInventoryDefinition = strings.Replace(
	replaceMigrationFunction(accountSuspensionInventoryTemplate, "wormhole_api_v1.account_suspension_inventory(", "{{SUSPENSION_EXPORT_DEFINITION}}"),
	"CASE WHEN (wormhole_data.effective_boundary_permissions(actor.user_id,q.boundary_id)&17)=17",
	`CASE WHEN (wormhole_data.effective_boundary_permissions(actor.user_id,q.boundary_id)&17)=17
                       OR wormhole_data.personal_account_rotation_available(actor.user_id,p_account,q.boundary_id)`, 1)

var personalBoundaryRotationMigration = strings.NewReplacer(
	"{{PERSONAL_ACCOUNT_ROTATION_PENDING}}", strings.Replace(
		replaceMigrationFunction(accountBoundaryRotationTemplate, "wormhole_data.account_rotation_pending(", "CREATE OR REPLACE FUNCTION"),
		"AND b.owner_user_id IS NULL AND NOT b.deleted", "AND (b.owner_user_id IS NULL OR b.owner_user_id=r.account_id) AND NOT b.deleted", 1),
	"{{PERSONAL_ACCOUNT_ROTATION_GRAPH}}", strings.Replace(
		replaceMigrationFunction(boundaryRotationTemplate, "wormhole_data.boundary_rotation_graph(", "{{BOUNDARY_ROTATION_API}}"),
		"recipient_set:=wormhole_data.boundary_rotation_recipients(p_boundary,p_group,1<<bit,root_id,root_version,p_org,p_org_version);",
		`IF EXISTS(SELECT FROM wormhole_data.boundaries b WHERE b.id=p_boundary AND b.owner_user_id IS NOT NULL) THEN
            recipient_set:=jsonb_build_array(jsonb_build_object('kind','org','key',jsonb_build_object('id',p_org,'version',p_org_version)));
        ELSE
            recipient_set:=wormhole_data.boundary_rotation_recipients(p_boundary,p_group,1<<bit,root_id,root_version,p_org,p_org_version);
        END IF;`, 1),
	"{{PERSONAL_ACCOUNT_ROTATION_API}}", strings.NewReplacer(
		"WHERE b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted FOR SHARE NOWAIT;",
		"WHERE b.id=p_boundary AND NOT b.deleted FOR SHARE NOWAIT;",
		"IF NOT FOUND OR (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&(17|purpose_mask))<>(17|purpose_mask) THEN",
		`IF NOT FOUND OR (CASE WHEN boundary.owner_user_id IS NULL
        THEN (wormhole_data.effective_boundary_permissions(actor.actor,p_boundary)&(17|purpose_mask))<>(17|purpose_mask)
        ELSE NOT wormhole_data.personal_account_rotation_available(actor.actor,p_account,p_boundary) END) THEN`,
		"IF old->>'active' IS DISTINCT FROM 'true'",
		`IF old->>'ownerUserId' IS DISTINCT FROM coalesce(boundary.owner_user_id,'00000000-0000-0000-0000-000000000000'::uuid)::text
        OR old->>'active' IS DISTINCT FROM 'true'`,
	).Replace(replaceMigrationFunction(accountBoundaryRotationTemplate, "wormhole_api_v1.rotate_account_boundary(", "-- An account's related groups")),
	"{{PERSONAL_ACCOUNT_ROOT_INVENTORY}}", personalAccountInventoryDefinition,
	"{{PERSONAL_ACCOUNT_ENABLE_GUARD}}", strings.Replace(
		replaceMigrationFunction(workspaceAccessTemplate, "wormhole_api_v1.workspace_access(", "{{CHANGE_PASSWORD_DEFINITION}}"),
		`    IF target_revision=9223372036854775807 THEN`,
		`    IF p_action='enable-account' AND wormhole_data.personal_account_recovery_required(target_user) THEN
        RETURN QUERY SELECT 'personal-recovery-required'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF target_revision=9223372036854775807 THEN`, 1),
	"{{SUSPENSION_RESTORE_DEFINITION}}", renderSuspensionRestore("73"),
).Replace(personalBoundaryRotationTemplate)

// PersonalBoundaryRotationMigration scopes personal boundary rotation to organisation custody.
func PersonalBoundaryRotationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(personalBoundaryRotationMigration, roleTag, workspaceID)
}

//go:embed migrations/0074_suspension_groups.sql
var accountSuspensionGroupsTemplate string

var accountGroupInventoryDefinition = strings.NewReplacer(
	"p_kind NOT IN ('roots','passwords')", "p_kind NOT IN ('roots','passwords','groups')",
	"IF p_kind='roots' THEN", `IF p_kind='groups' THEN
        entries:=wormhole_data.suspension_group_page(actor.user_id,p_account,p_after);
    ELSIF p_kind='roots' THEN`,
).Replace(personalAccountInventoryDefinition)

var accountSuspensionGroupsMigration = strings.NewReplacer(
	"{{ACCOUNT_GROUP_INVENTORY_DEFINITION}}", accountGroupInventoryDefinition,
	"{{SUSPENSION_RESTORE_DEFINITION}}", renderSuspensionRestore("74"),
).Replace(accountSuspensionGroupsTemplate)

// AccountSuspensionGroupsMigration adds a bounded group review for suspended accounts.
func AccountSuspensionGroupsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountSuspensionGroupsMigration, roleTag, workspaceID)
}

//go:embed migrations/0075_scoped_group_removal.sql
var scopedGroupRemovalTemplate string

var scopedGroupRemovalMigration = strings.NewReplacer(
	"{{SCOPED_GROUP_REMOVAL_DEFINITION}}", strings.NewReplacer(
		"p_review bytea,p_publication jsonb)", "p_review bytea,p_publication jsonb,p_suspension bigint)",
		"OR (p_review IS NOT NULL AND octet_length(p_review)<>32)", "OR p_suspension<1 OR (p_review IS NOT NULL AND octet_length(p_review)<>32)",
		"OR (p_review IS NOT NULL AND p_review<>job.review_digest)", `OR job.suspension_revision IS DISTINCT FROM p_suspension
            OR (p_suspension IS NOT NULL AND p_review IS NULL)
            OR (p_review IS NOT NULL AND p_review<>job.review_digest)`,
		"    IF team.row_version<>p_revision", `    IF p_suspension IS NOT NULL AND NOT EXISTS(
        SELECT FROM wormhole_data.users u JOIN wormhole_data.account_suspensions s ON s.account_id=u.id
        WHERE u.id=p_member AND u.disabled AND s.revision=p_suspension AND EXISTS(
            SELECT FROM wormhole_data.account_suspension_roots r JOIN wormhole_data.boundaries b ON b.id=r.boundary_id
            WHERE r.account_id=u.id AND p_group=ANY(r.groups) AND b.owner_user_id IS NULL AND NOT b.deleted
                AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&17)=17)
        FOR SHARE OF u,s NOWAIT) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    IF team.row_version<>p_revision`,
		"group_member_rotation_scope(actor.actor,old.key_id,old.key_version)", "group_member_rotation_scope(actor.actor,old.key_id,old.key_version,p_member)",
		"'roots',scope)::text,'UTF8');", `'roots',scope)
        ||CASE WHEN p_suspension IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('suspension',p_suspension::text) END)::text,'UTF8');`,
		"document:=convert_to(jsonb_build_object(", "document:=convert_to((jsonb_build_object(",
		"review_digest,key_id,retired_version,complete)", "review_digest,key_id,retired_version,complete,suspension_revision)",
		"p_review,old.key_id,old.key_version,jsonb_array_length(scope)=0);", "p_review,old.key_id,old.key_version,jsonb_array_length(scope)=0,p_suspension);",
	).Replace(replaceMigrationFunction(groupMemberRotationAPI, "wormhole_api_v1.rotate_group_member(", "REVOKE ALL ON FUNCTION")),
	"{{SUSPENSION_RESTORE_DEFINITION}}", renderSuspensionRestore("75"),
).Replace(scopedGroupRemovalTemplate)

// ScopedGroupRemovalMigration binds a group removal to the captured suspension.
func ScopedGroupRemovalMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(scopedGroupRemovalMigration, roleTag, workspaceID)
}

//go:embed migrations/0076_enrollment_history.sql
var enrollmentHistoryTemplate string

const enrollmentHistoryArchiveCheck = `    IF NOT wormhole_data.enrollment_history_recoverable() THEN
        RAISE EXCEPTION 'Workspace enrollment history is inconsistent' USING ERRCODE='WH020';
    END IF;
`

func renderEnrollmentHistoryExport() string {
	return strings.NewReplacer(
		suspensionArchiveCheck, suspensionArchiveCheck+enrollmentHistoryArchiveCheck,
		"SELECT 'user_enrollments'::text,pg_catalog.to_jsonb(ue) FROM wormhole_data.user_enrollments ue",
		`SELECT 'user_enrollments'::text,pg_catalog.to_jsonb(ue) FROM wormhole_data.user_enrollments ue
        UNION ALL
        SELECT 'user_enrollment_history'::text,to_jsonb(h) FROM wormhole_data.user_enrollment_history h`,
	).Replace(renderSuspensionExport())
}

func renderEnrollmentHistoryRestore(maxSchema string) string {
	return strings.NewReplacer(
		"'user_key_states','user_key_wraps','user_enrollments','nodes'",
		"'user_key_states','user_key_wraps','user_enrollments','user_enrollment_history','nodes'",
		suspensionArchiveCheck, suspensionArchiveCheck+`    IF original.schema_version<76 AND grouped ? 'user_enrollment_history' THEN
        RAISE EXCEPTION 'Workspace archive enrollment history is unsupported' USING ERRCODE='WH020';
    END IF;
`+enrollmentHistoryArchiveCheck,
	).Replace(renderSuspensionRestore(maxSchema))
}

var enrollmentHistoryMigration = strings.NewReplacer(
	"{{ENROLLMENT_HISTORY_EXPORT_DEFINITION}}", renderEnrollmentHistoryExport(),
	"{{ENROLLMENT_HISTORY_RESTORE_DEFINITION}}", renderEnrollmentHistoryRestore("76"),
).Replace(enrollmentHistoryTemplate)

// EnrollmentHistoryMigration retains previous public author proofs on re-enrollment.
func EnrollmentHistoryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(enrollmentHistoryMigration, roleTag, workspaceID)
}

//go:embed migrations/0077_suspension_enrollment.sql
var suspensionEnrollmentTemplate string

const suspensionEnrollmentArchiveCheck = `    IF NOT wormhole_data.suspension_enrollments_recoverable() THEN
        RAISE EXCEPTION 'Workspace suspension enrollment records are inconsistent' USING ERRCODE='WH020';
    END IF;
`

var suspensionEnrollmentMigration = strings.NewReplacer(
	"{{SUSPENSION_CAPTURE_DEFINITION}}", strings.Replace(
		replaceMigrationFunction(accountSuspensionInventoryTemplate, "wormhole_data.capture_account_suspension(", "-- A v70 suspension"),
		"VALUES(NEW.id,NEW.row_version);", "VALUES(NEW.id,NEW.row_version);\n    PERFORM wormhole_data.capture_suspension_enrollment(NEW.id);", 1),
	"{{SUSPENSION_ENROLLMENT_EXPORT_DEFINITION}}", renderSuspensionEnrollmentExport(),
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderSuspensionEnrollmentRestore("77"),
).Replace(suspensionEnrollmentTemplate)

func renderSuspensionEnrollmentExport() string {
	return strings.NewReplacer(
		enrollmentHistoryArchiveCheck, enrollmentHistoryArchiveCheck+suspensionEnrollmentArchiveCheck,
		"SELECT 'account_suspensions'::text,to_jsonb(s) FROM wormhole_data.account_suspensions s",
		`SELECT 'account_suspensions'::text,to_jsonb(s) FROM wormhole_data.account_suspensions s
        UNION ALL SELECT 'account_suspension_enrollments'::text,to_jsonb(e) FROM wormhole_data.account_suspension_enrollments e`,
	).Replace(renderEnrollmentHistoryExport())
}

func renderSuspensionEnrollmentRestore(maxSchema string) string {
	return strings.NewReplacer(
		suspensionArchiveRelations, suspensionArchiveRelations+",'account_suspension_enrollments'",
		enrollmentHistoryArchiveCheck, enrollmentHistoryArchiveCheck+`    IF original.schema_version<77 THEN
        IF grouped ? 'account_suspension_enrollments' THEN
            RAISE EXCEPTION 'Workspace archive suspension enrollment records are unsupported' USING ERRCODE='WH020';
        END IF;
        PERFORM wormhole_data.capture_suspension_enrollment(NULL);
    END IF;
`+suspensionEnrollmentArchiveCheck,
	).Replace(renderEnrollmentHistoryRestore(maxSchema))
}

// SuspensionEnrollmentMigration scopes rotated personal custody to a fresh enrollment.
func SuspensionEnrollmentMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(suspensionEnrollmentMigration, roleTag, workspaceID)
}

//go:embed migrations/0078_personal_root_recovery.sql
var personalRootRecoveryTemplate string

var personalRootRecoveryMigration = strings.ReplaceAll(personalRootRecoveryTemplate,
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderSuspensionEnrollmentRestore("78"))

// PersonalRootRecoveryMigration enables reviewed publication of rotated personal roots.
func PersonalRootRecoveryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(personalRootRecoveryMigration, roleTag, workspaceID)
}

//go:embed migrations/0079_account_reenrollment_offer.sql
var accountReenrollmentTemplate string

var accountReenrollmentMigration = strings.NewReplacer(
	"{{PUBLISH_ACCOUNT_REENROLLMENT}}", strings.NewReplacer(
		"CREATE OR REPLACE FUNCTION wormhole_api_v1.publish_account_reset(", "CREATE FUNCTION wormhole_api_v1.publish_account_reenrollment(",
		"p_capsule bytea,p_verifier text)", "p_capsule bytea,p_verifier text,p_bootstrap bytea)",
		"OR p_capsule IS NULL", "OR p_bootstrap IS NULL OR octet_length(p_bootstrap) NOT BETWEEN 1 AND 32768 OR p_capsule IS NULL",
		"subject:=wormhole_data.account_reset_target(p_subject->>'loginName');",
		`subject:=wormhole_data.account_reenrollment_target((p_subject->>'userId')::uuid,(p_subject->>'suspension')::bigint);
    IF NOT wormhole_data.personal_account_rotation_available(actor.actor,(subject->>'userId')::uuid,
        wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,(subject->>'userId')::uuid))
        OR NOT wormhole_data.reenrollment_bootstrap_matches(p_bootstrap,subject,p_offer,p_expires) THEN
        RAISE EXCEPTION 'Account replacement unavailable' USING ERRCODE='WH023';
    END IF;`,
		"previous.capsule=p_capsule", "previous.capsule=p_capsule AND previous.replacement=p_bootstrap",
		"offer_hash,commit_hash,policy_hash,tls_hash,capsule)", "offer_hash,commit_hash,policy_hash,tls_hash,capsule,replacement)",
		"p_policy_digest,p_tls_digest,p_capsule);", "p_policy_digest,p_tls_digest,p_capsule,p_bootstrap);",
		"'publish_account_reset','issued'", "'publish_account_reenrollment','issued'",
	).Replace(replaceMigrationFunction(accountResetIssuanceTemplate, "wormhole_api_v1.publish_account_reset(", "CREATE FUNCTION wormhole_api_v1.account_reset_capsule(")),
	"{{REQUIRE_ACCOUNT_REENROLLMENT}}", strings.NewReplacer(
		"CREATE OR REPLACE FUNCTION wormhole_data.require_account_reset(", "CREATE FUNCTION wormhole_data.require_account_reenrollment(",
		"request.retired_at IS NOT NULL", "request.retired_at IS NOT NULL OR request.replacement IS NULL",
		"OR request.subject IS DISTINCT FROM wormhole_data.account_reset_target(request.subject->>'loginName')",
		`OR NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=request.issuer_id AND u.is_admin AND NOT u.disabled)
       OR NOT wormhole_data.personal_account_rotation_available(request.issuer_id,request.user_id,
           wormhole_data.personal_import_boundary_id('{{WORKSPACE_ID}}'::uuid,request.user_id))
       OR request.subject IS DISTINCT FROM wormhole_data.account_reenrollment_target(request.user_id,(request.subject->>'suspension')::bigint)`,
	).Replace(replaceMigrationFunction(accountResetRedemptionTemplate, "wormhole_data.require_account_reset(", "CREATE OR REPLACE FUNCTION wormhole_api_v1.account_reset_capsule(")),
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderSuspensionEnrollmentRestore("79"),
).Replace(accountReenrollmentTemplate)

// AccountReenrollmentMigration adds scoped offers for a certified replacement.
func AccountReenrollmentMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountReenrollmentMigration, roleTag, workspaceID)
}

//go:embed migrations/0080_account_reenrollment_redemption.sql
var accountReenrollmentRedemptionTemplate string

var redeemAccountReenrollment = strings.NewReplacer(
	"wormhole_api_v1.redeem_account_reset(", "wormhole_api_v1.redeem_account_reenrollment(",
	"p_verifier text,p_kdf text,p_nonce bytea,p_ciphertext bytea)", "p_verifier text,p_kdf text,p_nonce bytea,p_ciphertext bytea,p_certificate bytea)",
	"DECLARE request wormhole_data.account_reset_offers;", "DECLARE enrollment record; request wormhole_data.account_reset_offers;",
	"wormhole_data.require_account_reset(", "wormhole_data.require_account_reenrollment(",
	"    UPDATE wormhole_data.user_key_wraps w SET wrap_revision", `    SELECT * INTO STRICT enrollment FROM wormhole_data.install_replacement_enrollment(request,p_certificate);
    INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
        SELECT p_device,r.oid,pg_catalog.sha256(p_certificate) FROM pg_catalog.pg_roles r WHERE r.rolname=target;
    UPDATE wormhole_data.user_key_wraps w SET encryption_key_id=enrollment.encryption_id,encryption_key_version=1,
        signing_key_id=enrollment.signing_id,signing_key_version=1,wrap_revision`,
	"target,p_verifier,pg_catalog.clock_timestamp()+interval '1 hour'", "target,p_verifier,'infinity'",
	"'reset-v1','redeem_account_reset'", "'reset-v2','redeem_account_reenrollment'",
).Replace(replaceMigrationFunction(accountResetRedemptionTemplate, "wormhole_api_v1.redeem_account_reset(", "CREATE FUNCTION wormhole_api_v1.account_reset_receipt("))

var accountReenrollmentRedemptionMigration = strings.NewReplacer(
	"{{REDEEM_ACCOUNT_REENROLLMENT}}", redeemAccountReenrollment,
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderSuspensionEnrollmentRestore("80"),
).Replace(accountReenrollmentRedemptionTemplate)

// AccountReenrollmentRedemptionMigration registers a certified replacement and
// grants its new device a receipt without lifting account suspension.
func AccountReenrollmentRedemptionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountReenrollmentRedemptionMigration, roleTag, workspaceID)
}

//go:embed migrations/0081_web_session_views.sql
var webSessionViewsTemplate string

var webSessionViewsMigration = strings.ReplaceAll(webSessionViewsTemplate,
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderWebSessionRestore("81"))

func renderWebSessionRestore(version string) string {
	return strings.ReplaceAll(renderSuspensionEnrollmentRestore(version),
		"'catalog_changes'] LOOP", "'catalog_changes','web_session_views'] LOOP")
}

// WebSessionViewsMigration remembers continuous View for local web archives.
func WebSessionViewsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(webSessionViewsMigration, roleTag, workspaceID)
}

func WorkspaceImportMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceImportMigration, roleTag, workspaceID)
}

// AccountRecoveryCustodyMigration adds certified escrow to a schema-50 deployment.
func AccountRecoveryCustodyMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountRecoveryCustodyMigration, roleTag, workspaceID)
}

// WorkspaceRecoveryRestoreMigration adds archive restore to a schema-49 deployment.
func WorkspaceRecoveryRestoreMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceRecoveryRestoreMigration, roleTag, workspaceID)
}

// WorkspaceRecoveryExportMigration installs recovery exports on schema 48.
func WorkspaceRecoveryExportMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceRecoveryExportMigration, roleTag, workspaceID)
}

// WorkspaceAdminRecoveryMigration installs recovery for an already deployed
// schema-47 workspace. The DBA enables the workspace's deployer login as needed.
func WorkspaceAdminRecoveryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceAdminRecoveryMigration, roleTag, workspaceID)
}

// WorkspaceRecoveryKitRefreshMigration installs the audited recovery kit
// projection on an existing schema-46 workspace.
func WorkspaceRecoveryKitRefreshMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceRecoveryKitRefreshMigration, roleTag, workspaceID)
}

// WorkspaceCARotationMigration installs the audited server CA update endpoints
// on an existing schema-45 workspace.
func WorkspaceCARotationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceCARotationMigration, roleTag, workspaceID)
}

// ServerCertificateRenewalMigration installs audited access to the encrypted
// workspace CA for an already deployed schema-44 workspace.
func ServerCertificateRenewalMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(serverCertificateRenewalMigration, roleTag, workspaceID)
}

// WorkspaceBootstrapMigration installs the one-time first administrator
// transaction for a workspace at schema version 43.
func WorkspaceBootstrapMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(workspaceBootstrapMigration, roleTag, workspaceID)
}

// TunnelFallbackMigration adds independently audited secondary tunnel release.
// SQL returns unverified ciphertext; Go must authenticate the encrypted reference.
func TunnelFallbackMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(tunnelFallbackMigration, roleTag, workspaceID)
}

// EnrolledCatalogAuthorsMigration publishes public enrollment proofs with the
// current signed bootstrap state and selects final encrypted release recipients.
func EnrolledCatalogAuthorsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(enrolledCatalogAuthorsMigration, roleTag, workspaceID)
}

// FortinetIPsecMigration extends signed tunnel metadata without changing grants.
func FortinetIPsecMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(fortinetIPsecMigration, roleTag, workspaceID)
}

// TunnelProfilesMigration authenticates selected tunnel metadata and settings,
// with independent boundary permission checks and no runtime table access.
func TunnelProfilesMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(tunnelProfilesMigration, roleTag, workspaceID)
}

// NodeSecretManifestsMigration adds revision-bound inline field manifests and
// extends audited release without granting runtime table or private helper access.
func NodeSecretManifestsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(nodeSecretManifestsMigration, roleTag, workspaceID)
}

// RuntimeStateMigration adds public policy/account state without secret release.
func RuntimeStateMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(runtimeStateMigration, roleTag, workspaceID)
}

// ConnectionPlanMigration adds authorized public metadata-only planning.
func ConnectionPlanMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(connectionPlanMigration, roleTag, workspaceID)
}

// ReleasePolicyMigration includes current signed policy in the release snapshot.
func ReleasePolicyMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(releasePolicyMigration, roleTag, workspaceID)
}

// FetchSecretMigration adds the audited connection-scoped encrypted release API.
func FetchSecretMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(fetchSecretMigration, roleTag, workspaceID)
}

// CredentialReleaseGraphMigration adds private bounded encrypted release preparation.
func CredentialReleaseGraphMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(credentialReleaseGraphMigration, roleTag, workspaceID)
}

// KeyCopyProjectionMigration adds private bound copy/current issuer projection.
func KeyCopyProjectionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(keyCopyProjectionMigration, roleTag, workspaceID)
}

// CredentialValuesMigration adds private field-manifest-bound ciphertext reads.
func CredentialValuesMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(credentialValuesMigration, roleTag, workspaceID)
}

// ConnectionSnapshotMigration adds the bounded signed metadata snapshot builder.
func ConnectionSnapshotMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(connectionSnapshotMigration, roleTag, workspaceID)
}

// BoundaryManifestsMigration adds private signed manifest storage and snapshot read.
func BoundaryManifestsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(boundaryManifestsMigration, roleTag, workspaceID)
}

// BoundaryPermissionsMigration adds independent account-boundary permissions.
func BoundaryPermissionsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(boundaryPermissionsMigration, roleTag, workspaceID)
}

// ConnectionResolutionMigration adds the private connection-scoped resolver.
func ConnectionResolutionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(connectionResolutionMigration, roleTag, workspaceID)
}

// SelectionProjectionMigration adds the private signed selection snapshot reader.
func SelectionProjectionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(selectionProjectionMigration, roleTag, workspaceID)
}

// CredentialProjectionMigration adds the private signed profile snapshot reader.
func CredentialProjectionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(credentialProjectionMigration, roleTag, workspaceID)
}

// CredentialCatalogMigration adds private signed account selection records.
func CredentialCatalogMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(credentialCatalogMigration, roleTag, workspaceID)
}

// CredentialSlotsMigration adds the private metadata-only slot resolver.
func CredentialSlotsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(credentialSlotsMigration, roleTag, workspaceID)
}

// ResolutionChainMigration adds private bounded signed-chain projection.
func ResolutionChainMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(resolutionChainMigration, roleTag, workspaceID)
}

// ResolverMigration adds private resolver-v1 metadata functions.
func ResolverMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(resolverMigration, roleTag, workspaceID)
}

// UseConsumptionMigration adds private rollback-resistant ticket consumption.
func UseConsumptionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(useConsumptionMigration, roleTag, workspaceID)
}

// UseIntentsMigration adds committed audit intent tickets for secret use.
func UseIntentsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(useIntentsMigration, roleTag, workspaceID)
}

// CatalogChangesMigration adds bounded incremental catalog invalidations.
func CatalogChangesMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(catalogChangesMigration, roleTag, workspaceID)
}

// NodeAuthorMigration exposes public author verification material for visible nodes.
func NodeAuthorMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(nodeAuthorMigration, roleTag, workspaceID)
}

// TreeSnapshotMigration adds node payloads and bounded View-filtered paging.
func TreeSnapshotMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(treeSnapshotMigration, roleTag, workspaceID)
}

// NodePermissionsMigration adds the private node hierarchy and inherited grants.
// It does not expose tree payloads, writes or secret release.
func NodePermissionsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(nodePermissionsMigration, roleTag, workspaceID)
}

var ErrIdentity = errors.New("invalid shared workspace deployment identity")

// InitialMigration bootstraps an empty dedicated database using a DBA account.
// The deployer login intentionally has no password until separately enrolled.
// This first schema version is provisioning-only, not a usable shared workspace.
func InitialMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(identityMigration, roleTag, workspaceID)
}

// SessionMigration upgrades exactly identity schema v1. It exposes audited login
// only; remaining workspace APIs and provisioning are still separate work.
func SessionMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(sessionMigration, roleTag, workspaceID)
}

// KeyGraphMigration upgrades schema v2 with private key-graph and invite storage.
// It grants no runtime table access and does not activate enrollment APIs.
func KeyGraphMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(keyGraphMigration, roleTag, workspaceID)
}

// SessionProofMigration requires current credential proofs before admission.
// Credentials must be provisioned separately; missing credentials fail closed.
func SessionProofMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(sessionProofMigration, roleTag, workspaceID)
}

// PasswordChangeMigration adds private user-key wrappers and atomic password changes.
func PasswordChangeMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(passwordChangeMigration, roleTag, workspaceID)
}

// AccountKeysMigration exposes only the authenticated user's encrypted capsule.
func AccountKeysMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountKeysMigration, roleTag, workspaceID)
}

// AccountCertificatesMigration adds explicit certificate revisions and atomic retrieval.
func AccountCertificatesMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountCertificatesMigration, roleTag, workspaceID)
}

// AccountStateMigration adds signed state storage and consistent unlock retrieval.
func AccountStateMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountStateMigration, roleTag, workspaceID)
}

// TLSTrustMigration adds private workspace TLS metadata and capability-gated read.
func TLSTrustMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(tlsTrustMigration, roleTag, workspaceID)
}

// InvitationLoginMigration adds temporary roles restricted to enrollment APIs.
func InvitationLoginMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(invitationLoginMigration, roleTag, workspaceID)
}

// InvitationCopiesMigration adds revision-bound enrollment key-copy download.
func InvitationCopiesMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(invitationCopiesMigration, roleTag, workspaceID)
}

// AccountEnrollmentMigration adds committed bootstrap-to-user certification retrieval.
func AccountEnrollmentMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(accountEnrollmentMigration, roleTag, workspaceID)
}

// InvitationCommitMigration adds atomic first-account invitation redemption.
func InvitationCommitMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(invitationCommitMigration, roleTag, workspaceID)
}

// DeviceConfirmationMigration adds audited confirmation after a new device login.
func DeviceConfirmationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(deviceConfirmationMigration, roleTag, workspaceID)
}

// InvitationCertificationMigration exposes signed bootstrap prerequisites.
func InvitationCertificationMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(invitationCertificationMigration, roleTag, workspaceID)
}

func renderMigration(script, roleTag, workspaceID string) (string, error) {
	if err := ValidateIdentity(roleTag, workspaceID); err != nil {
		return "", err
	}
	return substituteIdentity(script, roleTag, workspaceID), nil
}

// ValidateIdentity checks the values shared by deployment and reconciliation.
func ValidateIdentity(roleTag, workspaceID string) error {
	if len(roleTag) < 8 || len(roleTag) > 16 {
		return ErrIdentity
	}
	for _, c := range roleTag {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return ErrIdentity
		}
	}
	id, err := uuid.Parse(workspaceID)
	if err != nil || id == uuid.Nil || id.String() != workspaceID {
		return ErrIdentity
	}
	return nil
}

func substituteIdentity(script, roleTag, workspaceID string) string {
	return strings.NewReplacer("{{TAG}}", roleTag, "{{WORKSPACE_ID}}", workspaceID).Replace(script)
}
