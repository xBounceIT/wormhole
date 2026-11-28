package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0084_web_suspension_inventory.sql
var webSuspensionInventoryTemplate string

const webSuspensionArchiveCheck = `    IF NOT wormhole_data.web_suspension_inventory_recoverable() THEN
        RAISE EXCEPTION 'Workspace web suspension records are inconsistent' USING ERRCODE='WH020';
    END IF;
`

var webSuspensionInventoryMigration = strings.NewReplacer(
	"{{ACCOUNT_WEB_INVENTORY_DEFINITION}}", strings.NewReplacer(
		"p_kind NOT IN ('roots','passwords','groups')", "p_kind NOT IN ('roots','passwords','groups','web-sessions')",
		"IF p_kind='groups' THEN", `IF p_kind='web-sessions' THEN
        IF NOT EXISTS(SELECT FROM wormhole_data.account_suspension_web_reports r WHERE r.account_id=p_account) THEN
            RETURN QUERY SELECT 'not-recorded'::text,NULL::jsonb;
            RETURN;
        END IF;
        entries:=wormhole_data.suspension_web_page(actor.user_id,p_account,p_after);
    ELSIF p_kind='groups' THEN`,
	).Replace(accountGroupInventoryDefinition),
	"{{WEB_SUSPENSION_EXPORT_DEFINITION}}", strings.NewReplacer(
		suspensionEnrollmentArchiveCheck, suspensionEnrollmentArchiveCheck+webSuspensionArchiveCheck,
		"SELECT 'account_suspensions'::text,to_jsonb(s) FROM wormhole_data.account_suspensions s",
		`SELECT 'account_suspensions'::text,to_jsonb(s) FROM wormhole_data.account_suspensions s
        UNION ALL SELECT 'account_suspension_web_reports'::text,to_jsonb(w) FROM wormhole_data.account_suspension_web_reports w
        UNION ALL SELECT 'account_suspension_web_targets'::text,to_jsonb(t) FROM wormhole_data.account_suspension_web_targets t`,
	).Replace(renderSuspensionEnrollmentExport()),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("84"),
).Replace(webSuspensionInventoryTemplate)

func renderWebSuspensionRestore(maxSchema string) string {
	return strings.NewReplacer(
		suspensionArchiveRelations, suspensionArchiveRelations+",'account_suspension_web_reports','account_suspension_web_targets'",
		"'web_session_views'] LOOP", "'web_session_views','web_session_checkpoints'] LOOP",
		suspensionEnrollmentArchiveCheck, suspensionEnrollmentArchiveCheck+`    IF original.schema_version<84 AND
        (grouped ? 'account_suspension_web_reports' OR grouped ? 'account_suspension_web_targets') THEN
        RAISE EXCEPTION 'Workspace archive web suspension records are unsupported' USING ERRCODE='WH020';
    END IF;
`+webSuspensionArchiveCheck,
	).Replace(renderWebSessionRestore(maxSchema))
}

func WebSuspensionInventoryMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(webSuspensionInventoryMigration, roleTag, workspaceID)
}
