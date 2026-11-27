package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0085_audit_maintenance.sql
var auditMaintenanceTemplate string

//go:embed fragments/maintain_audit_partitions.sql
var auditPartitionTemplate string

func renderAuditPartitionMaintenance(replace, newPartitionPolicy string) string {
	return strings.NewReplacer("{{REPLACE}}", replace, "{{NEW_PARTITION_POLICY}}", newPartitionPolicy).Replace(strings.TrimSpace(auditPartitionTemplate))
}

var auditMaintenanceMigration = strings.NewReplacer(
	"{{MAINTAIN_AUDIT_PARTITIONS}}", renderAuditPartitionMaintenance("", ""),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("85"),
).Replace(auditMaintenanceTemplate)

func AuditMaintenanceMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(auditMaintenanceMigration, roleTag, workspaceID)
}
