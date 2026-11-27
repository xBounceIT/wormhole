package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0090_suspension_rotation_receipts.sql
var suspensionRotationReceiptsTemplate string

var suspensionRotationReceiptsMigration = strings.NewReplacer(
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("90"),
	"{{GROUP_ROSTER_AT_SUSPENSION}}", strings.ReplaceAll(renderGroupRoster("group_roster_at_suspension", ",p_subject uuid", ""),
		"AND NOT u.disabled", "AND (NOT u.disabled OR u.id=p_subject)"),
).Replace(suspensionRotationReceiptsTemplate)

func SuspensionRotationReceiptsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(suspensionRotationReceiptsMigration, roleTag, workspaceID)
}
