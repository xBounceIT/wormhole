package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PromptBeforeTunnelConnect lives in the shared settings.json document next to app-auth.dpapi
// (see authPaths). It is owned by Go: the renderer only reads and writes it through the
// settings-read / settings-set-prompt-before-tunnel operations.
const promptBeforeTunnelConnectKey = "PromptBeforeTunnelConnect"

const autoCopyOnSelectKey = "AutoCopyOnSelect"

const themeKey = "Theme"

type applicationTheme string

const (
	applicationThemeSystem applicationTheme = "system"
	applicationThemeLight  applicationTheme = "light"
	applicationThemeDark   applicationTheme = "dark"
)

type themeMigrationResult struct {
	Handled  bool `json:"handled"`
	Migrated bool `json:"migrated"`
}

const (
	confirmOnTabCloseKey = "ConfirmOnTabClose"
	sidebarWidthKey      = "SidebarWidth"
	defaultSidebarWidth  = 320
	minSidebarWidth      = 180
	maxSidebarWidth      = 600
)

// Update preferences share the same settings.json document and use the same JSON keys as the
// WinUI 3 AppSettings model (AutoCheckForUpdates, LastUpdateCheck, SkippedUpdateVersion).
const (
	autoCheckForUpdatesKey  = "AutoCheckForUpdates"
	lastUpdateCheckKey      = "LastUpdateCheck"
	skippedUpdateVersionKey = "SkippedUpdateVersion"
)

const (
	bitwardenOnboardingNoticeSeenKey    = "BitwardenOnboardingNoticeSeenVersion"
	bitwardenOnboardingNoticePendingKey = "BitwardenOnboardingNoticePendingVersion"
	currentBitwardenOnboardingVersion   = 1
)

type bitwardenOnboardingNotice struct {
	Show    bool   `json:"show"`
	Title   string `json:"title,omitempty"`
	Message string `json:"message,omitempty"`
}

type settingsMigrationResult struct {
	Updated bool `json:"updated"`
}

const (
	settingsSchemaVersionKey     = "SettingsSchemaVersion"
	currentSettingsSchemaVersion = 8
)

// migrateLegacySettingsDocument mirrors AppSettingsService.Load so Electron and WinUI interpret
// the same pre-v8 settings file identically. Callers decide whether a missing file is legacy: a
// truly new settings document starts at the current schema and must not show an upgrade notice.
func migrateLegacySettingsDocument(document map[string]json.RawMessage) {
	schemaVersion := 0
	if raw, ok := document[settingsSchemaVersionKey]; ok {
		_ = json.Unmarshal(raw, &schemaVersion)
	}
	if schemaVersion >= currentSettingsSchemaVersion {
		return
	}
	set := func(key string, value any) {
		encoded, _ := json.Marshal(value)
		document[key] = encoded
	}
	settingString := func(key string) string {
		var value string
		_ = json.Unmarshal(document[key], &value)
		return strings.TrimSpace(value)
	}

	if schemaVersion < 1 {
		set(promptBeforeTunnelConnectKey, true)
	}
	if schemaVersion < 2 && settingString(bwCliKeyPath) == "" {
		set(bwCliKeyPath, "bw")
	}
	if schemaVersion < 3 && settingString(bwExtKeyReleasesURL) == "" {
		set(bwExtKeyReleasesURL, bitwardenExtensionDefaultReleasesURL)
	}
	if schemaVersion < 4 {
		source := bitwardenSourceOfficialGitHub
		if settingString(bwExtKeyPath) != "" && settingString(bwExtKeyDownloadURL) == "" {
			if settingString(bwExtKeyAssetName) == "" {
				source = bitwardenSourceManualFolder
			} else {
				source = bitwardenSourceManualZip
			}
		}
		set(bwExtKeySource, source)
	}
	if schemaVersion < 5 && settingString(bwCliKeyReleasesURL) == "" {
		set(bwCliKeyReleasesURL, bitwardenCliDefaultReleasesURL)
	}
	if schemaVersion < 6 {
		set(bitwardenOnboardingNoticePendingKey, currentBitwardenOnboardingVersion)
	}
	if schemaVersion < 8 {
		set(bwCliKeyServerRegion, bitwardenCliServerCurrent)
	}
	set(settingsSchemaVersionKey, currentSettingsSchemaVersion)
}

// persistLegacySettingsMigration matches AppSettingsService startup semantics: an existing valid
// legacy document is upgraded atomically, while a missing or malformed file remains untouched.
func persistLegacySettingsMigration(databasePath string) (settingsMigrationResult, error) {
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settingsMigrationResult{}, nil
	}
	if err != nil {
		return settingsMigrationResult{}, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil || document == nil {
		return settingsMigrationResult{}, nil
	}
	if readSettingsInteger(document, settingsSchemaVersionKey) >= currentSettingsSchemaVersion {
		return settingsMigrationResult{}, nil
	}
	if err := updateSettingsDocument(settingsPath, func(map[string]json.RawMessage) error { return nil }); err != nil {
		return settingsMigrationResult{}, err
	}
	return settingsMigrationResult{Updated: true}, nil
}

func readBitwardenOnboardingNotice(databasePath, appVersion string) (bitwardenOnboardingNotice, error) {
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return bitwardenOnboardingNotice{}, nil
	}
	if err != nil {
		return bitwardenOnboardingNotice{}, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}

	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil || document == nil {
		return bitwardenOnboardingNotice{}, nil
	}
	migrateLegacySettingsDocument(document)

	seen := readSettingsInteger(document, bitwardenOnboardingNoticeSeenKey)
	pending := readSettingsInteger(document, bitwardenOnboardingNoticePendingKey)
	major, minor, validVersion := bitwardenAppMajorMinor(appVersion)
	if seen >= currentBitwardenOnboardingVersion ||
		pending < currentBitwardenOnboardingVersion ||
		!validVersion || major != 0 || minor != 7 {
		return bitwardenOnboardingNotice{}, nil
	}

	return bitwardenOnboardingNotice{
		Show:  true,
		Title: "New Bitwarden integration",
		Message: "Wormhole now supports Bitwarden as an optional vault for credentials and as a " +
			"browser extension in HTTPS windows. Enable it from Settings > Extensions > Bitwarden.",
	}, nil
}

func dismissBitwardenOnboardingNotice(databasePath string) error {
	_, settingsPath := authPaths(databasePath)
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		seen, _ := json.Marshal(currentBitwardenOnboardingVersion)
		pending, _ := json.Marshal(0)
		document[bitwardenOnboardingNoticeSeenKey] = seen
		document[bitwardenOnboardingNoticePendingKey] = pending
		return nil
	})
}

func readSettingsInteger(document map[string]json.RawMessage, key string) int {
	var value int
	_ = json.Unmarshal(document[key], &value)
	return value
}

func parseApplicationTheme(value string) (applicationTheme, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(applicationThemeSystem):
		return applicationThemeSystem, true
	case string(applicationThemeLight):
		return applicationThemeLight, true
	case string(applicationThemeDark):
		return applicationThemeDark, true
	default:
		return applicationThemeSystem, false
	}
}

// readApplicationTheme accepts both the numeric representation written by System.Text.Json for
// the WinUI enum and string enum names found in hand-edited or older shared documents.
func readApplicationTheme(value json.RawMessage) (applicationTheme, bool) {
	var numeric int
	if json.Unmarshal(value, &numeric) == nil {
		switch numeric {
		case 0:
			return applicationThemeSystem, true
		case 1:
			return applicationThemeLight, true
		case 2:
			return applicationThemeDark, true
		default:
			return applicationThemeSystem, false
		}
	}
	var label string
	if json.Unmarshal(value, &label) != nil {
		return applicationThemeSystem, false
	}
	return parseApplicationTheme(label)
}

func persistedApplicationTheme(theme applicationTheme) (int, bool) {
	switch theme {
	case applicationThemeSystem:
		return 0, true
	case applicationThemeLight:
		return 1, true
	case applicationThemeDark:
		return 2, true
	default:
		return 0, false
	}
}

func writeApplicationTheme(databasePath string, theme applicationTheme) error {
	persisted, ok := persistedApplicationTheme(theme)
	if !ok {
		return errors.New("application theme is invalid")
	}
	return writeSettingsValues(databasePath, map[string]any{themeKey: persisted})
}

// migrateLegacyElectronTheme imports the former renderer-only preference exactly once. Any
// explicit shared Theme wins, and a malformed document is left untouched so app-auth and unknown
// keys cannot be destroyed by a best-effort migration.
func migrateLegacyElectronTheme(databasePath string, legacyTheme *string) (themeMigrationResult, error) {
	if legacyTheme == nil {
		return themeMigrationResult{}, nil
	}
	theme, ok := parseApplicationTheme(*legacyTheme)
	if !ok {
		return themeMigrationResult{}, errors.New("legacy application theme is invalid")
	}
	persisted, _ := persistedApplicationTheme(theme)
	_, settingsPath := authPaths(databasePath)
	result := themeMigrationResult{}
	err := updateSettingsDocumentWithOptions(
		settingsPath,
		settingsDocumentUpdateOptions{ReplaceMalformed: false},
		func(document map[string]json.RawMessage) (bool, error) {
			if _, present := document[themeKey]; present {
				result.Handled = true
				return false, nil
			}
			encoded, encodeErr := json.Marshal(persisted)
			if encodeErr != nil {
				return false, fmt.Errorf("cannot encode Wormhole theme: %w", encodeErr)
			}
			document[themeKey] = encoded
			result.Handled = true
			result.Migrated = true
			return true, nil
		},
	)
	if errors.Is(err, errMalformedSettingsDocument) {
		return themeMigrationResult{}, nil
	}
	return result, err
}

func bitwardenAppMajorMinor(version string) (int, int, bool) {
	parts := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(version, "v")), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

// readPromptBeforeTunnelConnect reports whether connecting to a saved connection should first
// ask whether to use its configured VPN tunnel. Absent, invalid, or unreadable settings fall
// back to true, matching the WinUI 3 default.
func readPromptBeforeTunnelConnect(databasePath string) (bool, error) {
	settings, err := readAppSettings(databasePath)
	return settings.PromptBeforeTunnelConnect, err
}

// writePromptBeforeTunnelConnect merges the setting into settings.json, preserving every other
// key (including the app-authentication settings) that already lives in the document.
func writePromptBeforeTunnelConnect(databasePath string, enabled bool) error {
	return writeSettingsValues(databasePath, map[string]any{promptBeforeTunnelConnectKey: enabled})
}

func writeAutoCopyOnSelect(databasePath string, enabled bool) error {
	return writeSettingsValues(databasePath, map[string]any{autoCopyOnSelectKey: enabled})
}

func writeConfirmOnTabClose(databasePath string, enabled bool) error {
	return writeSettingsValues(databasePath, map[string]any{confirmOnTabCloseKey: enabled})
}

func clampSidebarWidth(width int) int {
	if width < minSidebarWidth {
		return minSidebarWidth
	}
	if width > maxSidebarWidth {
		return maxSidebarWidth
	}
	return width
}

func writeSidebarWidth(databasePath string, width int) error {
	return writeSettingsValues(databasePath, map[string]any{sidebarWidthKey: clampSidebarWidth(width)})
}

type appSettingsValues struct {
	Theme                     applicationTheme
	PromptBeforeTunnelConnect bool
	AutoCopyOnSelect          bool
	ConfirmOnTabClose         bool
	SidebarWidth              int
	AutoCheckForUpdates       bool
	LastUpdateCheck           *string
	SkippedUpdateVersion      *string
}

// readAppSettings reads the shared settings.json document. Absent or invalid values use safe
// defaults, including confirmation for connected tabs and a bounded sidebar width.
func readAppSettings(databasePath string) (appSettingsValues, error) {
	settings := appSettingsValues{
		Theme:                     applicationThemeSystem,
		PromptBeforeTunnelConnect: true,
		AutoCopyOnSelect:          true,
		ConfirmOnTabClose:         true,
		SidebarWidth:              defaultSidebarWidth,
		AutoCheckForUpdates:       true,
	}
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil || document == nil {
		return settings, nil
	}
	migrateLegacySettingsDocument(document)
	if value, ok := document[themeKey]; ok {
		if theme, valid := readApplicationTheme(value); valid {
			settings.Theme = theme
		}
	}
	if value, ok := document[promptBeforeTunnelConnectKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.PromptBeforeTunnelConnect = enabled
		}
	}
	if value, ok := document[autoCopyOnSelectKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.AutoCopyOnSelect = enabled
		}
	}
	if value, ok := document[confirmOnTabCloseKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.ConfirmOnTabClose = enabled
		}
	}
	if value, ok := document[sidebarWidthKey]; ok {
		var width int
		if json.Unmarshal(value, &width) == nil {
			settings.SidebarWidth = clampSidebarWidth(width)
		}
	}
	if value, ok := document[autoCheckForUpdatesKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			settings.AutoCheckForUpdates = enabled
		}
	}
	if value, ok := document[lastUpdateCheckKey]; ok && string(value) != "null" {
		var stamp string
		if json.Unmarshal(value, &stamp) == nil && stamp != "" {
			settings.LastUpdateCheck = &stamp
		}
	}
	if value, ok := document[skippedUpdateVersionKey]; ok && string(value) != "null" {
		var skipped string
		if json.Unmarshal(value, &skipped) == nil && skipped != "" {
			settings.SkippedUpdateVersion = &skipped
		}
	}
	return settings, nil
}

// writeSettingsValues merges the given keys into settings.json, preserving every other key
// (including the app-authentication settings) that already lives in the document. A nil value
// writes JSON null, which clears the key on the next read.
func writeSettingsValues(databasePath string, values map[string]any) error {
	_, settingsPath := authPaths(databasePath)
	return updateSettingsDocument(settingsPath, func(document map[string]json.RawMessage) error {
		for key, value := range values {
			encoded, err := json.Marshal(value)
			if err != nil {
				return fmt.Errorf("cannot encode Wormhole settings: %w", err)
			}
			document[key] = encoded
		}
		return nil
	})
}
