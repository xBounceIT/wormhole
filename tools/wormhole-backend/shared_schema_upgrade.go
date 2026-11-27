package main

import (
	"io"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg/deploy"
)

// This offline operation writes SQL to stdout and never opens a workspace.
func exportSharedSchemaUpgrade(input io.Reader, output, diagnostics io.Writer) int {
	const limit = 1024
	raw, err := io.ReadAll(io.LimitReader(input, limit+1))
	var roleTag, workspaceID string
	var version int
	if err != nil || len(raw) > limit || decodeVaultObject(raw, map[string]any{
		"roleTag": &roleTag, "workspaceId": &workspaceID, "installedVersion": &version,
	}, "roleTag", "workspaceId", "installedVersion") != nil {
		writeErrorTo(diagnostics, "Invalid workspace upgrade request.")
		return 1
	}
	script, err := deploy.NextMigrationScript(roleTag, workspaceID, version)
	if err != nil {
		writeErrorTo(diagnostics, err.Error())
		return 1
	}
	if written, err := io.WriteString(output, script); err != nil || written != len(script) {
		writeErrorTo(diagnostics, "Could not write the workspace upgrade script.")
		return 1
	}
	return 0
}
