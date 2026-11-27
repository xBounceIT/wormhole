package sharedpg

import (
	"context"
	"errors"
	"time"
)

var ErrWorkspaceRestoreLogging = errors.New("workspace archive parameter logging is enabled")

type WorkspaceRestoreResult string

const (
	WorkspaceRestored        WorkspaceRestoreResult = "restored"
	WorkspaceAlreadyRestored WorkspaceRestoreResult = "already-restored"
)

// RestoreWorkspaceRecoverySnapshot verifies the authenticated archive's
// organisation trust, connects as the target's dedicated deployer and sends
// the persistent graph only on that connection. Retrying after an uncertain
// reply is safe: the restore transaction records the exact archive digest.
func RestoreWorkspaceRecoverySnapshot(ctx context.Context, target WorkspaceRecoveryTarget, plaintext, password []byte) (WorkspaceRestoreResult, error) {
	if ctx == nil || len(password) == 0 || len(password) > 1024 {
		return "", ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	tag, err := target.roleTag()
	if err != nil {
		return "", err
	}
	summary, tls, err := authenticateWorkspaceRecoverySnapshot(plaintext)
	if err != nil {
		return "", err
	}
	if summary.WorkspaceID != target.WorkspaceID || summary.RoleTag != tag {
		return "", ErrDeploymentMismatch
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := Connect(ctx, target.settings(tls), password)
	if err != nil {
		return "", err
	}
	defer closeDeploymentConnection(conn)
	// Restore sends the archive as a bind parameter. Check this connection's
	// settings before any archive bytes can reach statement or error logs.
	row, err := readDeploymentRow(ctx, conn, `SELECT (
 pg_catalog.current_setting('log_statement')='none'
 AND pg_catalog.current_setting('log_parameter_max_length')='0'
 AND pg_catalog.current_setting('log_parameter_max_length_on_error')='0'
 AND COALESCE(pg_catalog.current_setting('pgaudit.log_parameter',true),'off')='off'
)::text`, 1)
	if err != nil {
		return "", err
	}
	if string(row[0]) != "true" {
		return "", ErrWorkspaceRestoreLogging
	}
	raw, err := readDeploymentResponse(ctx, conn, "SELECT wormhole_api_v1.restore_workspace($1::text,$2::text)",
		[][]byte{plaintext, []byte(target.Database)}, 64)
	if err != nil {
		return "", err
	}
	switch result := WorkspaceRestoreResult(raw); result {
	case WorkspaceRestored, WorkspaceAlreadyRestored:
		return result, nil
	default:
		return "", ErrDeploymentUncertain
	}
}
