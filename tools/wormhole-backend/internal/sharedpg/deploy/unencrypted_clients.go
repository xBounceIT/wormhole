package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0086_unencrypted_clients.sql
var unencryptedClientsTemplate string

var unencryptedClientsMigration = strings.ReplaceAll(unencryptedClientsTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("86"))

func UnencryptedClientsMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(unencryptedClientsMigration, roleTag, workspaceID)
}
