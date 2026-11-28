package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0082_web_connection_plan.sql
var webConnectionPlanTemplate string

var webConnectionPlanMigration = strings.NewReplacer(
	"{{WEB_CONNECTION_DEFINITIONS}}", renderWebConnectionDefinitions(false),
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderWebSessionRestore("82"),
).Replace(webConnectionPlanTemplate)

func renderWebConnectionDefinitions(tunnelRelease bool) string {
	definitions := strings.NewReplacer(
		"CREATE FUNCTION wormhole_data.resolve_connection(", "CREATE OR REPLACE FUNCTION wormhole_data.resolve_connection(",
		"{{WEB_PLAN_RESOLUTION}}", `    IF p_path='web' THEN
        plan:=wormhole_data.resolve_chain(chain);
        IF (plan->>'protocol')::integer NOT IN (3,4) THEN
            RAISE EXCEPTION 'Invalid web connection' USING ERRCODE='WH017';
        END IF;
        RETURN plan;
    END IF;
`,
		"{{WEB_SNAPSHOT_ACCOUNTS_BEGIN}}", "    IF p_path IS DISTINCT FROM 'web' THEN\n",
		"{{WEB_SNAPSHOT_ACCOUNTS_END}}", "    END IF;\n",
		"'importedData',encode(wormhole_data.imported_node_body(p_node),'hex')",
		"'importedData',CASE WHEN p_path IS DISTINCT FROM 'web' THEN encode(wormhole_data.imported_node_body(p_node),'hex') END",
	).Replace(connectionPathDefinition.Replace(resolveConnectionDefinition + connectionSnapshotDefinition))
	if !tunnelRelease {
		return definitions
	}
	// Normalize only the web default. Account selection for other protocols
	// must still run at its original point, after resolving the base plan.
	const normalize = `    IF p_path='default' AND wormhole_data.node_default_plan_path(p_node,p_epoch,p_change_seq)='web' THEN
        p_path:='web';
    END IF;
`
	return strings.NewReplacer(
		"    IF p_path='web' THEN\n        plan:=", normalize+"    IF p_path='web' THEN\n        plan:=",
		"    -- Validates every argument", normalize+"    -- Validates every argument",
		"    IF EXISTS(SELECT FROM wormhole_data.node_import_data", normalize+"    IF EXISTS(SELECT FROM wormhole_data.node_import_data",
		"        PERFORM wormhole_data.require_imported_pin_permissions(identity.user_id,wormhole_data.imported_node_body(p_node),p_permission);",
		"        IF p_path IS DISTINCT FROM 'web' THEN\n            PERFORM wormhole_data.require_imported_pin_permissions(identity.user_id,wormhole_data.imported_node_body(p_node),p_permission);\n        END IF;",
	).Replace(definitions + connectionPathDefinition.Replace(connectionAccountPermissionsDefinition))
}

// WebConnectionPlanMigration adds signed routing metadata for HTTP(S) without
// treating a retained Reveal account as part of opening a browser.
func WebConnectionPlanMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(webConnectionPlanMigration, roleTag, workspaceID)
}
