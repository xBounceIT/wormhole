package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0091_row_security.sql
var rowSecurityTemplate string

var rowSecurityMigration = strings.NewReplacer(
	"{{MAINTAIN_AUDIT_PARTITIONS}}", renderAuditPartitionMaintenance("OR REPLACE ", `            IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='wormhole_data.audit_log'::regclass) THEN
                PERFORM wormhole_data.configure_relation_rls(format('wormhole_data.%I',child_name)::regclass,true);
            END IF;
`),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("91"),
).Replace(rowSecurityTemplate)

func RowSecurityMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(rowSecurityMigration, roleTag, workspaceID)
}
