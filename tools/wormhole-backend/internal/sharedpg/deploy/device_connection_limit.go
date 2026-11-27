package deploy

import (
	_ "embed"
	"strings"
)

//go:embed migrations/0092_device_connection_limit.sql
var deviceConnectionLimitTemplate string

// Enrollment roles keep their two-connection limit. Only the functions that
// actually create device logins receive the new limit.
var deviceConnectionLimitMigration = strings.NewReplacer(
	"{{COMMIT_INVITATION}}", withDeviceConnectionLimit(replaceMigrationFunction(invitationCommitMigration,
		"wormhole_api_v1.commit_invitation(", "REVOKE ALL ON FUNCTION")),
	"{{REDEEM_ACCOUNT_RESET}}", withDeviceConnectionLimit(replaceMigrationFunction(accountResetRedemptionTemplate,
		"wormhole_api_v1.redeem_account_reset(", "CREATE FUNCTION wormhole_api_v1.account_reset_receipt(")),
	"{{REDEEM_ACCOUNT_REENROLLMENT}}", withDeviceConnectionLimit(redeemAccountReenrollment),
	"{{CONFIRM_ENROLLMENT}}", strings.Replace(replaceMigrationFunction(deviceConfirmationMigration,
		"wormhole_api_v1.confirm_enrollment(", "REVOKE ALL ON wormhole_data.device_confirmations"),
		"ALTER ROLE %I VALID UNTIL", "ALTER ROLE %I CONNECTION LIMIT 3 VALID UNTIL", 1),
	"{{WEB_SUSPENSION_RESTORE_DEFINITION}}", renderWebSuspensionRestore("92"),
).Replace(deviceConnectionLimitTemplate)

func withDeviceConnectionLimit(definition string) string {
	return strings.Replace(definition, "CONNECTION LIMIT 2 PASSWORD", "CONNECTION LIMIT 3 PASSWORD", 1)
}

func DeviceConnectionLimitMigration(roleTag, workspaceID string) (string, error) {
	return renderMigration(deviceConnectionLimitMigration, roleTag, workspaceID)
}
