package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

func setBitwardenCliConfig(databasePath, path string, serverRegion int) (bitwardenCliState, bool, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return bitwardenCliState{}, false, err
	}
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		normalizedPath = "bw"
	}
	if serverRegion < bitwardenCliServerUnitedStates || serverRegion > bitwardenCliServerCurrent {
		return bitwardenCliState{}, false, errors.New("Bitwarden server region is invalid")
	}
	pathChanged := !bitwardenCliPathsEqual(settings.Path, normalizedPath)
	changed := pathChanged || settings.ServerRegion != serverRegion
	if pathChanged {
		settings.Version = ""
		settings.Sha256 = ""
		settings.AssetName = ""
		settings.DownloadURL = ""
		settings.InstallStatus = ""
		settings.InstallError = ""
	}
	settings.Path = normalizedPath
	settings.ServerRegion = serverRegion
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		return bitwardenCliState{}, false, err
	}
	return buildBitwardenCliState(databasePath, settings), changed, nil
}

func bitwardenCliPathsEqual(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func installBitwardenCliLatestWrapped(databasePath string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	// The explicit Install action also enables the vault in WinUI. Persist that choice before the
	// network operation so a failed download still leaves the user's toggle intent intact.
	settings.Enabled = true
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		return nil, err
	}
	_, err = installBitwardenCliLatest(databasePath, &settings)
	if err != nil {
		settings.InstallError = summarizeBitwardenCliError(err)
		settings.InstallStatus = "Bitwarden CLI install failed."
		_ = writeBitwardenCliSettings(databasePath, settings)
		return nil, err
	}
	return buildBitwardenCliState(databasePath, settings), nil
}

func ensureBitwardenCliInstalled(databasePath string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	if resolveBitwardenCliInstall(settings) != nil {
		return buildBitwardenCliState(databasePath, settings), nil
	}
	_, err = installBitwardenCliLatest(databasePath, &settings)
	if err != nil {
		settings.InstallError = summarizeBitwardenCliError(err)
		settings.InstallStatus = "Bitwarden CLI install failed."
		_ = writeBitwardenCliSettings(databasePath, settings)
		return nil, err
	}
	return buildBitwardenCliState(databasePath, settings), nil
}

func bitwardenCliStatusOperation(databasePath string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	return bitwardenCliStatusState(databasePath, settings)
}

func bitwardenCliLogoutOperation(databasePath, sessionKey string) error {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return err
	}
	return bitwardenCliLogout(databasePath, settings)
}

func bitwardenCliSyncOperation(databasePath, sessionKey string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	if err := bitwardenCliSync(databasePath, settings, sessionKey); err != nil {
		return nil, err
	}
	// List after the sync so the reported count and status reflect the freshly synchronized vault,
	// matching the WinUI 3 credential sync service ordering.
	items, err := bitwardenCliListItems(databasePath, settings, sessionKey, "")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	availableCount, err := replaceBitwardenCredentialCache(databasePath, items, now)
	if err != nil {
		return nil, err
	}
	settings.LastSyncUtc = &now
	settings.LastSyncStatus = fmt.Sprintf("Synced %d Bitwarden login items.", availableCount)
	settings.LastSyncError = ""
	count := availableCount
	settings.AvailableCount = &count
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		return nil, err
	}
	return map[string]any{
		"lastSyncUtc":    now.Format(time.RFC3339Nano),
		"lastSyncStatus": settings.LastSyncStatus,
		"availableCount": availableCount,
		"usedCache":      false,
	}, nil
}

func bitwardenCliListOperation(databasePath, sessionKey, query string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	items, err := bitwardenCliListItems(databasePath, settings, sessionKey, query)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items}, nil
}

func bitwardenCliSearchOperation(databasePath, sessionKey, query string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	items, err := bitwardenCliSearchItems(databasePath, settings, sessionKey, query)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items}, nil
}

func bitwardenCliGetOperation(databasePath, sessionKey, itemID string) (any, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return nil, err
	}
	item, err := bitwardenCliGetItem(databasePath, settings, sessionKey, itemID)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return map[string]any{"item": nil}, nil
	}
	return map[string]any{"item": item}, nil
}

func isBitwardenCliAuthError(err error) bool {
	var vaultErr *bitwardenCliVaultError
	return errors.As(err, &vaultErr) && vaultErr.IsAuth
}
