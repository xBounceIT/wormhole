package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0087_ssh_host_pin.sql
var sshHostPinTemplate string

var sshHostPinMigration = strings.ReplaceAll(sshHostPinTemplate, "{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("87"))

func SSHHostPinMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(sshHostPinMigration, roleTag, workspaceID)
}
