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

// The optional Bitwarden browser extension inside HTTPS browser sessions. All state lives in the
// shared settings.json document (see authPaths), owned by Go. The renderer only reads and writes it
// through the extension-* operations. Keys match the WinUI 3 AppSettings serialization exactly so
// the native and Electron apps share one settings file.
const (
	bitwardenExtensionDefaultReleasesURL = "repos/bitwarden/clients/releases?per_page=20"
	bitwardenExtensionReleasesBaseURL    = "https://api.github.com/"
	bitwardenExtensionUpdateInterval     = 24 * time.Hour
	bitwardenExtensionMaxErrorLength     = 240

	bwExtKeyEnabled            = "EnableBitwardenBrowserExtension"
	bwExtKeySource             = "BitwardenBrowserExtensionSource"
	bwExtKeyReleasesURL        = "BitwardenBrowserExtensionReleasesUrl"
	bwExtKeyVersion            = "BitwardenBrowserExtensionVersion"
	bwExtKeyPath               = "BitwardenBrowserExtensionPath"
	bwExtKeySha256             = "BitwardenBrowserExtensionSha256"
	bwExtKeyAssetName          = "BitwardenBrowserExtensionAssetName"
	bwExtKeyDownloadURL        = "BitwardenBrowserExtensionDownloadUrl"
	bwExtKeyLastUpdateCheckUtc = "BitwardenBrowserExtensionLastUpdateCheckUtc"
	bwExtKeyLastUpdateStatus   = "BitwardenBrowserExtensionLastUpdateStatus"
	bwExtKeyLastUpdateError    = "BitwardenBrowserExtensionLastUpdateError"
	bwExtKeyAvailableVersion   = "BitwardenBrowserExtensionAvailableVersion"
)

// BitwardenBrowserExtensionSource enum values, matching WinUI 3 AppSettings.
const (
	bitwardenSourceOfficialGitHub = 0
	bitwardenSourceManualZip      = 1
	bitwardenSourceManualFolder   = 2
)

type bitwardenExtensionSettings struct {
	Enabled            bool
	Source             int
	ReleasesURL        string
	Version            string
	Path               string
	Sha256             string
	AssetName          string
	DownloadURL        string
	LastUpdateCheckUtc *time.Time
	LastUpdateStatus   string
	LastUpdateError    string
	AvailableVersion   string
}

type bitwardenInstalledInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Path         string `json:"path"`
	DefaultPopup string `json:"defaultPopup,omitempty"`
}

type bitwardenExtensionState struct {
	Enabled            bool                    `json:"enabled"`
	Source             string                  `json:"source"`
	ReleasesURL        string                  `json:"releasesUrl"`
	Version            *string                 `json:"version"`
	Path               *string                 `json:"path"`
	Sha256             *string                 `json:"sha256"`
	AssetName          *string                 `json:"assetName"`
	DownloadURL        *string                 `json:"downloadUrl"`
	LastUpdateCheckUtc *string                 `json:"lastUpdateCheckUtc"`
	LastUpdateStatus   *string                 `json:"lastUpdateStatus"`
	LastUpdateError    *string                 `json:"lastUpdateError"`
	AvailableVersion   *string                 `json:"availableVersion"`
	Installed          *bitwardenInstalledInfo `json:"installed"`
}

func defaultBitwardenExtensionSettings() bitwardenExtensionSettings {
	return bitwardenExtensionSettings{
		Source:      bitwardenSourceOfficialGitHub,
		ReleasesURL: bitwardenExtensionDefaultReleasesURL,
	}
}

func readBitwardenExtensionSettings(databasePath string) (bitwardenExtensionSettings, error) {
	settings := defaultBitwardenExtensionSettings()
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
	if value, ok := document[bwExtKeyEnabled]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.Enabled = enabled
		}
	}
	if value, ok := document[bwExtKeySource]; ok {
		var source int
		if json.Unmarshal(value, &source) == nil && source >= 0 && source <= 2 {
			settings.Source = source
		}
	}
	if value, ok := document[bwExtKeyReleasesURL]; ok {
		var releasesURL string
		if json.Unmarshal(value, &releasesURL) == nil && strings.TrimSpace(releasesURL) != "" {
			settings.ReleasesURL = strings.TrimSpace(releasesURL)
		}
	}
	settings.Version = readBitwardenSettingString(document, bwExtKeyVersion)
	settings.Path = readBitwardenSettingString(document, bwExtKeyPath)
	settings.Sha256 = readBitwardenSettingString(document, bwExtKeySha256)
	settings.AssetName = readBitwardenSettingString(document, bwExtKeyAssetName)
	settings.DownloadURL = readBitwardenSettingString(document, bwExtKeyDownloadURL)
	settings.LastUpdateStatus = readBitwardenSettingString(document, bwExtKeyLastUpdateStatus)
	settings.LastUpdateError = readBitwardenSettingString(document, bwExtKeyLastUpdateError)
	settings.AvailableVersion = readBitwardenSettingString(document, bwExtKeyAvailableVersion)
	if value, ok := document[bwExtKeyLastUpdateCheckUtc]; ok {
		var stamp string
		if json.Unmarshal(value, &stamp) == nil {
			if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(stamp)); err == nil {
				settings.LastUpdateCheckUtc = &parsed
			}
		}
	}
	return settings, nil
}

func readBitwardenSettingString(document map[string]json.RawMessage, key string) string {
	value, ok := document[key]
	if !ok {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	return ""
}

func writeBitwardenExtensionSettings(databasePath string, settings bitwardenExtensionSettings) error {
	_, settingsPath := authPaths(databasePath)
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		enabled, _ := json.Marshal(settings.Enabled)
		source, _ := json.Marshal(settings.Source)
		releasesURL, _ := json.Marshal(settings.ReleasesURL)
		document[bwExtKeyEnabled] = enabled
		document[bwExtKeySource] = source
		document[bwExtKeyReleasesURL] = releasesURL
		document[bwExtKeyVersion] = marshalBitwardenNullableString(settings.Version)
		document[bwExtKeyPath] = marshalBitwardenNullableString(settings.Path)
		document[bwExtKeySha256] = marshalBitwardenNullableString(settings.Sha256)
		document[bwExtKeyAssetName] = marshalBitwardenNullableString(settings.AssetName)
		document[bwExtKeyDownloadURL] = marshalBitwardenNullableString(settings.DownloadURL)
		document[bwExtKeyLastUpdateStatus] = marshalBitwardenNullableString(settings.LastUpdateStatus)
		document[bwExtKeyLastUpdateError] = marshalBitwardenNullableString(settings.LastUpdateError)
		document[bwExtKeyAvailableVersion] = marshalBitwardenNullableString(settings.AvailableVersion)
		if settings.LastUpdateCheckUtc == nil {
			document[bwExtKeyLastUpdateCheckUtc] = json.RawMessage("null")
		} else {
			stamp, _ := json.Marshal(settings.LastUpdateCheckUtc.Format(time.RFC3339Nano))
			document[bwExtKeyLastUpdateCheckUtc] = stamp
		}
		return nil
	})
}

func marshalBitwardenNullableString(value string) json.RawMessage {
	if value == "" {
		return json.RawMessage("null")
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func bitwardenExtensionInstallRoot(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "extensions", "bitwarden")
}

func bitwardenExtensionDownloadRoot(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "cache", "bitwarden-browser-extension")
}

func bitwardenExtensionSourceName(source int) string {
	switch source {
	case bitwardenSourceManualZip:
		return "ManualZip"
	case bitwardenSourceManualFolder:
		return "ManualFolder"
	default:
		return "OfficialGitHub"
	}
}

func buildBitwardenExtensionState(databasePath string, settings bitwardenExtensionSettings) bitwardenExtensionState {
	state := bitwardenExtensionState{
		Enabled:          settings.Enabled,
		Source:           bitwardenExtensionSourceName(settings.Source),
		ReleasesURL:      settings.ReleasesURL,
		Version:          nullableBitwardenString(settings.Version),
		Path:             nullableBitwardenString(settings.Path),
		Sha256:           nullableBitwardenString(settings.Sha256),
		AssetName:        nullableBitwardenString(settings.AssetName),
		DownloadURL:      nullableBitwardenString(settings.DownloadURL),
		LastUpdateStatus: nullableBitwardenString(settings.LastUpdateStatus),
		LastUpdateError:  nullableBitwardenString(settings.LastUpdateError),
		AvailableVersion: nullableBitwardenString(settings.AvailableVersion),
	}
	if settings.LastUpdateCheckUtc != nil {
		stamp := settings.LastUpdateCheckUtc.Format(time.RFC3339Nano)
		state.LastUpdateCheckUtc = &stamp
	}
	if install := getBitwardenExtensionInstall(settings); install != nil {
		state.Installed = &bitwardenInstalledInfo{
			Name:         install.ManifestName,
			Version:      install.Version,
			Path:         install.Path,
			DefaultPopup: install.DefaultPopup,
		}
	}
	return state
}

func nullableBitwardenString(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

func readBitwardenExtensionState(databasePath string) (bitwardenExtensionState, error) {
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func setBitwardenExtensionEnabled(databasePath string, enabled bool) (bitwardenExtensionState, error) {
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	settings.Enabled = enabled
	if err := writeBitwardenExtensionSettings(databasePath, settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func installBitwardenExtensionLatest(databasePath string) (bitwardenExtensionState, error) {
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	if err := persistEnabledBitwardenExtension(databasePath, &settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	if _, err := installBitwardenLatestRelease(databasePath, &settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func ensureBitwardenExtensionInstalled(databasePath string) (bitwardenExtensionState, error) {
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	if getBitwardenExtensionInstall(settings) != nil {
		return buildBitwardenExtensionState(databasePath, settings), nil
	}
	return installBitwardenExtensionLatest(databasePath)
}

func importBitwardenExtensionZip(databasePath, zipPath string) (bitwardenExtensionState, error) {
	if strings.TrimSpace(zipPath) == "" {
		return bitwardenExtensionState{}, errors.New("Select a Bitwarden browser extension ZIP file.")
	}
	if _, err := os.Stat(zipPath); err != nil {
		return bitwardenExtensionState{}, errors.New("The selected ZIP file does not exist.")
	}
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	// A manual import enables the extension without triggering an official auto-install, matching
	// the WinUI 3 settings page.
	if err := persistEnabledBitwardenExtension(databasePath, &settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	sha256hex, err := computeBitwardenFileSha256(zipPath)
	if err != nil {
		return bitwardenExtensionState{}, errors.New("Could not read the selected ZIP file.")
	}
	if _, err := installBitwardenZipFile(
		databasePath,
		&settings,
		zipPath,
		"",
		sha256hex,
		filepath.Base(zipPath),
		"",
		bitwardenSourceManualZip,
	); err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func importBitwardenExtensionFolder(databasePath, folderPath string) (bitwardenExtensionState, error) {
	if strings.TrimSpace(folderPath) == "" {
		return bitwardenExtensionState{}, errors.New("Select an unpacked Bitwarden browser extension folder.")
	}
	if info, err := os.Stat(folderPath); err != nil || !info.IsDir() {
		return bitwardenExtensionState{}, errors.New("The selected extension folder does not exist.")
	}
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	if err := persistEnabledBitwardenExtension(databasePath, &settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	if _, err := installBitwardenFolder(databasePath, &settings, folderPath); err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func persistEnabledBitwardenExtension(databasePath string, settings *bitwardenExtensionSettings) error {
	if settings.Enabled {
		return nil
	}
	settings.Enabled = true
	return writeBitwardenExtensionSettings(databasePath, *settings)
}

func updateBitwardenExtensionIfStale(databasePath string) (bitwardenExtensionState, error) {
	settings, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		return bitwardenExtensionState{}, err
	}
	if !shouldCheckBitwardenUpdate(settings) {
		return buildBitwardenExtensionState(databasePath, settings), nil
	}

	now := time.Now().UTC()
	settings.LastUpdateCheckUtc = &now
	if check, install, wasUpdated, checkErr := updateBitwardenIfAvailable(databasePath, &settings); checkErr != nil {
		settings.LastUpdateStatus = "Auto-update check failed."
		settings.LastUpdateError = summarizeBitwardenError(checkErr)
	} else {
		settings.LastUpdateError = ""
		settings.AvailableVersion = ""
		if wasUpdated {
			settings.LastUpdateStatus = fmt.Sprintf("Auto-updated from official release to %s.", install.Version)
		} else {
			if check.IsUpdateAvailable {
				settings.AvailableVersion = check.LatestVersion
			}
			settings.LastUpdateStatus = fmt.Sprintf("Up to date with official release %s.", check.LatestVersion)
		}
	}
	if err := writeBitwardenExtensionSettings(databasePath, settings); err != nil {
		return bitwardenExtensionState{}, err
	}
	return buildBitwardenExtensionState(databasePath, settings), nil
}

func shouldCheckBitwardenUpdate(settings bitwardenExtensionSettings) bool {
	if !settings.Enabled || settings.Source != bitwardenSourceOfficialGitHub {
		return false
	}
	if settings.LastUpdateCheckUtc != nil && time.Since(*settings.LastUpdateCheckUtc) < bitwardenExtensionUpdateInterval {
		return false
	}
	return getBitwardenExtensionInstall(settings) != nil
}

func summarizeBitwardenError(err error) string {
	message := err.Error()
	if message == "" {
		return "Bitwarden browser extension update failed."
	}
	runes := []rune(message)
	if len(runes) <= bitwardenExtensionMaxErrorLength {
		return message
	}
	return string(runes[:bitwardenExtensionMaxErrorLength])
}
