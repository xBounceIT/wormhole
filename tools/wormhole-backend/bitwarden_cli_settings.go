package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The optional Bitwarden Password Manager vault reached through the official bw CLI. All state
// lives in the shared settings.json document (see authPaths), owned by Go. The renderer only reads
// and writes it through the cli-* operations. Keys match the WinUI 3 AppSettings serialization
// exactly so the native and Electron apps share one settings file.
const (
	bitwardenCliDefaultReleasesURL = "repos/bitwarden/clients/releases?per_page=20"
	bitwardenCliMaxErrorLength     = 240

	bwCliKeyEnabled        = "EnableBitwardenVault"
	bwCliKeyPath           = "BitwardenCliPath"
	bwCliKeyServerRegion   = "BitwardenCliServerRegion"
	bwCliKeyReleasesURL    = "BitwardenCliReleasesUrl"
	bwCliKeyVersion        = "BitwardenCliVersion"
	bwCliKeySha256         = "BitwardenCliSha256"
	bwCliKeyAssetName      = "BitwardenCliAssetName"
	bwCliKeyDownloadURL    = "BitwardenCliDownloadUrl"
	bwCliKeyInstallStatus  = "BitwardenCliInstallStatus"
	bwCliKeyInstallError   = "BitwardenCliInstallError"
	bwCliKeyLastSyncUtc    = "BitwardenCredentialLastSyncUtc"
	bwCliKeyLastSyncStatus = "BitwardenCredentialLastSyncStatus"
	bwCliKeyLastSyncError  = "BitwardenCredentialLastSyncError"
	bwCliKeyAvailableCount = "BitwardenCredentialAvailableCount"
)

// BitwardenCliServerRegion enum values, matching WinUI 3 AppSettings.
const (
	bitwardenCliServerUnitedStates = 0
	bitwardenCliServerEurope       = 1
	bitwardenCliServerCurrent      = 2
)

type bitwardenCliSettings struct {
	Enabled        bool
	Path           string
	ServerRegion   int
	ReleasesURL    string
	Version        string
	Sha256         string
	AssetName      string
	DownloadURL    string
	InstallStatus  string
	InstallError   string
	LastSyncUtc    *time.Time
	LastSyncStatus string
	LastSyncError  string
	AvailableCount *int
}

type bitwardenCliInstalled struct {
	Version     string `json:"version"`
	Path        string `json:"path"`
	Sha256      string `json:"sha256,omitempty"`
	AssetName   string `json:"assetName,omitempty"`
	DownloadURL string `json:"downloadUrl,omitempty"`
}

type bitwardenCliState struct {
	Enabled        bool                   `json:"enabled"`
	Path           string                 `json:"path"`
	ServerRegion   string                 `json:"serverRegion"`
	ReleasesURL    string                 `json:"releasesUrl"`
	Version        *string                `json:"version"`
	Sha256         *string                `json:"sha256"`
	AssetName      *string                `json:"assetName"`
	DownloadURL    *string                `json:"downloadUrl"`
	InstallStatus  *string                `json:"installStatus"`
	InstallError   *string                `json:"installError"`
	LastSyncUtc    *string                `json:"lastSyncUtc"`
	LastSyncStatus *string                `json:"lastSyncStatus"`
	LastSyncError  *string                `json:"lastSyncError"`
	AvailableCount *int                   `json:"availableCount"`
	Installed      *bitwardenCliInstalled `json:"installed"`
}

func defaultBitwardenCliSettings() bitwardenCliSettings {
	return bitwardenCliSettings{
		Path:         "bw",
		ServerRegion: bitwardenCliServerUnitedStates,
		ReleasesURL:  bitwardenCliDefaultReleasesURL,
	}
}

func readBitwardenCliSettings(databasePath string) (bitwardenCliSettings, error) {
	settings := defaultBitwardenCliSettings()
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil || document == nil {
		return settings, nil
	}
	migrateLegacySettingsDocument(document)
	if value, ok := document[bwCliKeyEnabled]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.Enabled = enabled
		}
	}
	if value, ok := document[bwCliKeyPath]; ok {
		var path string
		if json.Unmarshal(value, &path) == nil && strings.TrimSpace(path) != "" {
			settings.Path = strings.TrimSpace(path)
		}
	}
	if value, ok := document[bwCliKeyServerRegion]; ok {
		var region int
		if json.Unmarshal(value, &region) == nil && region >= bitwardenCliServerUnitedStates && region <= bitwardenCliServerCurrent {
			settings.ServerRegion = region
		}
	}
	if value, ok := document[bwCliKeyReleasesURL]; ok {
		var releasesURL string
		if json.Unmarshal(value, &releasesURL) == nil && strings.TrimSpace(releasesURL) != "" {
			settings.ReleasesURL = strings.TrimSpace(releasesURL)
		}
	}
	settings.Version = readBitwardenSettingString(document, bwCliKeyVersion)
	settings.Sha256 = readBitwardenSettingString(document, bwCliKeySha256)
	settings.AssetName = readBitwardenSettingString(document, bwCliKeyAssetName)
	settings.DownloadURL = readBitwardenSettingString(document, bwCliKeyDownloadURL)
	settings.InstallStatus = readBitwardenSettingString(document, bwCliKeyInstallStatus)
	settings.InstallError = readBitwardenSettingString(document, bwCliKeyInstallError)
	settings.LastSyncStatus = readBitwardenSettingString(document, bwCliKeyLastSyncStatus)
	settings.LastSyncError = readBitwardenSettingString(document, bwCliKeyLastSyncError)
	if value, ok := document[bwCliKeyLastSyncUtc]; ok {
		var stamp string
		if json.Unmarshal(value, &stamp) == nil {
			if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(stamp)); err == nil {
				settings.LastSyncUtc = &parsed
			}
		}
	}
	if value, ok := document[bwCliKeyAvailableCount]; ok && string(value) != "null" {
		var count int
		if json.Unmarshal(value, &count) == nil {
			settings.AvailableCount = &count
		}
	}
	return settings, nil
}

func writeBitwardenCliSettings(databasePath string, settings bitwardenCliSettings) error {
	_, settingsPath := authPaths(databasePath)
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		enabled, _ := json.Marshal(settings.Enabled)
		path, _ := json.Marshal(settings.Path)
		region, _ := json.Marshal(settings.ServerRegion)
		releasesURL, _ := json.Marshal(settings.ReleasesURL)
		document[bwCliKeyEnabled] = enabled
		document[bwCliKeyPath] = path
		document[bwCliKeyServerRegion] = region
		document[bwCliKeyReleasesURL] = releasesURL
		document[bwCliKeyVersion] = marshalBitwardenNullableString(settings.Version)
		document[bwCliKeySha256] = marshalBitwardenNullableString(settings.Sha256)
		document[bwCliKeyAssetName] = marshalBitwardenNullableString(settings.AssetName)
		document[bwCliKeyDownloadURL] = marshalBitwardenNullableString(settings.DownloadURL)
		document[bwCliKeyInstallStatus] = marshalBitwardenNullableString(settings.InstallStatus)
		document[bwCliKeyInstallError] = marshalBitwardenNullableString(settings.InstallError)
		document[bwCliKeyLastSyncStatus] = marshalBitwardenNullableString(settings.LastSyncStatus)
		document[bwCliKeyLastSyncError] = marshalBitwardenNullableString(settings.LastSyncError)
		if settings.LastSyncUtc == nil {
			document[bwCliKeyLastSyncUtc] = json.RawMessage("null")
		} else {
			stamp, _ := json.Marshal(settings.LastSyncUtc.Format(time.RFC3339Nano))
			document[bwCliKeyLastSyncUtc] = stamp
		}
		if settings.AvailableCount == nil {
			document[bwCliKeyAvailableCount] = json.RawMessage("null")
		} else {
			count, _ := json.Marshal(*settings.AvailableCount)
			document[bwCliKeyAvailableCount] = count
		}
		return nil
	})
}

func bitwardenCliInstallRoot(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "tools", "bitwarden-cli")
}

func bitwardenCliDownloadRoot(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "cache", "bitwarden-cli")
}

func bitwardenCliServerRegionName(region int) string {
	switch region {
	case bitwardenCliServerEurope:
		return "Europe"
	case bitwardenCliServerCurrent:
		return "Current"
	default:
		return "UnitedStates"
	}
}

func buildBitwardenCliState(databasePath string, settings bitwardenCliSettings) bitwardenCliState {
	state := bitwardenCliState{
		Enabled:        settings.Enabled,
		Path:           settings.Path,
		ServerRegion:   bitwardenCliServerRegionName(settings.ServerRegion),
		ReleasesURL:    settings.ReleasesURL,
		Version:        nullableBitwardenString(settings.Version),
		Sha256:         nullableBitwardenString(settings.Sha256),
		AssetName:      nullableBitwardenString(settings.AssetName),
		DownloadURL:    nullableBitwardenString(settings.DownloadURL),
		InstallStatus:  nullableBitwardenString(settings.InstallStatus),
		InstallError:   nullableBitwardenString(settings.InstallError),
		LastSyncStatus: nullableBitwardenString(settings.LastSyncStatus),
		LastSyncError:  nullableBitwardenString(settings.LastSyncError),
		AvailableCount: settings.AvailableCount,
	}
	if settings.LastSyncUtc != nil {
		stamp := settings.LastSyncUtc.Format(time.RFC3339Nano)
		state.LastSyncUtc = &stamp
	}
	if install := resolveBitwardenCliInstall(settings); install != nil {
		state.Installed = install
	}
	return state
}

func readBitwardenCliState(databasePath string) (bitwardenCliState, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return bitwardenCliState{}, err
	}
	return buildBitwardenCliState(databasePath, settings), nil
}

func setBitwardenCliEnabled(databasePath string, enabled bool) (bitwardenCliState, error) {
	settings, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		return bitwardenCliState{}, err
	}
	settings.Enabled = enabled
	if err := writeBitwardenCliSettings(databasePath, settings); err != nil {
		return bitwardenCliState{}, err
	}
	return buildBitwardenCliState(databasePath, settings), nil
}

func summarizeBitwardenCliError(err error) string {
	message := err.Error()
	if message == "" {
		return "Bitwarden CLI operation failed."
	}
	runes := []rune(message)
	if len(runes) <= bitwardenCliMaxErrorLength {
		return message
	}
	return string(runes[:bitwardenCliMaxErrorLength])
}
