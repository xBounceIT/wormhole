package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0085_audit_maintenance.sql
var auditMaintenanceTemplate string

var auditMaintenanceMigration = strings.ReplaceAll(auditMaintenanceTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("85"))

func AuditMaintenanceMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(auditMaintenanceMigration, roleTag, workspaceID)
}
