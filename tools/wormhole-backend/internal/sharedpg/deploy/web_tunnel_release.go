package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0083_web_tunnel_release.sql
var webTunnelReleaseTemplate string

var webTunnelReleaseMigration = strings.NewReplacer(
	"{{WEB_CONNECTION_DEFINITIONS}}", renderWebConnectionDefinitions(true),
	"{{WEB_TICKET_DEFINITIONS}}", strings.ReplaceAll(renderNoteTicketDefinitions(),
		"p_path NOT IN ('ssh','sftp','vnc','rdp')", "p_path NOT IN ('ssh','sftp','vnc','rdp','web')"),
	"{{WEB_FALLBACK_DEFINITION}}", strings.ReplaceAll(connectionPathDefinition.Replace(groupFallbackReleaseDefinition),
		"wormhole_data.node_default_use_path(p_node,p_epoch,p_change_seq)", "wormhole_data.node_default_plan_path(p_node,p_epoch,p_change_seq)"),
	"{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}", renderWebSessionRestore("83"),
).Replace(webTunnelReleaseTemplate)

func WebTunnelReleaseMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(webTunnelReleaseMigration, roleTag, workspaceID)
}
