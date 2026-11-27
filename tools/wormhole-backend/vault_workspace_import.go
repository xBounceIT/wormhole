package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/workspaceimport"
)

// stageVaultWorkspaceImport is called within the admitted destination's native
// owner. Keep provider validation common with the vault tunnel editor.
func stageVaultWorkspaceImport(ctx context.Context, source *localvault.Owner, plan *workspaceimport.Plan, authority workspaceimport.Authority, signingSeed []byte) (*workspaceimport.SealedImport, error) {
	return plan.Seal(ctx, source, authority, signingSeed, transformWorkspaceImportTunnel)
}

func workspaceImportFallback(configuration []byte) (string, error) {
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return "", err
	}
	defer clearTunnelSettingsMap(settings)
	return selectNativeIPsecFallbackSettings(settings)
}

func transformWorkspaceImportTunnel(kind int, configuration []byte, resolveFallback func(string) (string, error)) ([]byte, error) {
	if kind != 9 {
		if err := validateVaultTunnelConfiguration(configuration, kind); err != nil {
			return nil, err
		}
		return configuration, nil
	}
	settings, err := decodeVaultTunnelSettings(configuration)
	if err != nil {
		return nil, err
	}
	defer clearTunnelSettingsMap(settings)
	fallback, err := selectNativeIPsecFallbackSettings(settings)
	if err != nil {
		return nil, err
	}
	if fallback == "" {
		return configuration, nil
	}
	destination, err := resolveFallback(fallback)
	if err != nil {
		return nil, err
	}
	if destination == "" || normalizeTunnelID(destination) != destination || destination == "00000000-0000-0000-0000-000000000000" {
		return nil, vault.ErrFormat
	}
	vault.Wipe(settings["FallbackTunnelId"])
	settings["FallbackTunnelId"] = strconv.AppendQuote(nil, destination)
	return json.Marshal(settings)
}
