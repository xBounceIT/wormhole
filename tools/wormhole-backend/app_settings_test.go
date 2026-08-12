package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateLegacySettingsMatchesBitwardenWinUIRules(t *testing.T) {
	document := map[string]json.RawMessage{}
	set := func(key string, value any) {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		document[key] = encoded
	}
	set(settingsSchemaVersionKey, 3)
	set(bwExtKeyPath, `C:\legacy\bitwarden`)
	set(bwExtKeyAssetName, "")
	set(bwExtKeyDownloadURL, "")
	set(bwCliKeyServerRegion, bitwardenCliServerEurope)

	migrateLegacySettingsDocument(document)

	assertSettingInt := func(key string, want int) {
		t.Helper()
		var got int
		if err := json.Unmarshal(document[key], &got); err != nil || got != want {
			t.Fatalf("%s = %d, %v; want %d", key, got, err, want)
		}
	}
	assertSettingInt(settingsSchemaVersionKey, currentSettingsSchemaVersion)
	assertSettingInt(bwExtKeySource, bitwardenSourceManualFolder)
	assertSettingInt(bwCliKeyServerRegion, bitwardenCliServerCurrent)
	assertSettingInt(bitwardenOnboardingNoticePendingKey, currentBitwardenOnboardingVersion)
}

func TestNewSettingsDocumentDoesNotMasqueradeAsLegacyUpgrade(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := writePromptBeforeTunnelConnect(databasePath, false); err != nil {
		t.Fatal(err)
	}
	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if _, present := document[bitwardenOnboardingNoticePendingKey]; present {
		t.Fatal("a new installation was marked as an upgraded Bitwarden installation")
	}
	var schemaVersion int
	if err := json.Unmarshal(document[settingsSchemaVersionKey], &schemaVersion); err != nil ||
		schemaVersion != currentSettingsSchemaVersion {
		t.Fatalf("schema version = %d, %v", schemaVersion, err)
	}
}

func TestPersistLegacySettingsMigrationMatchesWinUIStartup(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey: 5,
		bwCliKeyServerRegion:     bitwardenCliServerEurope,
	})

	result, err := persistLegacySettingsMigration(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated {
		t.Fatal("legacy settings were not persisted")
	}

	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if schema := readSettingsInteger(document, settingsSchemaVersionKey); schema != currentSettingsSchemaVersion {
		t.Fatalf("schema version = %d", schema)
	}
	if pending := readSettingsInteger(document, bitwardenOnboardingNoticePendingKey); pending != currentBitwardenOnboardingVersion {
		t.Fatalf("pending onboarding version = %d", pending)
	}
	if region := readSettingsInteger(document, bwCliKeyServerRegion); region != bitwardenCliServerCurrent {
		t.Fatalf("server region = %d", region)
	}

	result, err = persistLegacySettingsMigration(databasePath)
	if err != nil || result.Updated {
		t.Fatalf("second migration = %+v, %v", result, err)
	}
}

func TestPersistLegacySettingsMigrationLeavesMissingFileMissing(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	result, err := persistLegacySettingsMigration(databasePath)
	if err != nil || result.Updated {
		t.Fatalf("migration = %+v, %v", result, err)
	}
	_, settingsPath := authPaths(databasePath)
	if _, err := os.Stat(settingsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing settings file was created: %v", err)
	}
}

func TestBitwardenOnboardingNoticeMatchesWinUIVersionGateAndDismissal(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey:            5,
		bitwardenOnboardingNoticeSeenKey:    0,
		bitwardenOnboardingNoticePendingKey: 0,
	})

	notice, err := readBitwardenOnboardingNotice(databasePath, "0.8.0")
	if err != nil {
		t.Fatal(err)
	}
	if notice.Show {
		t.Fatal("notice was shown outside the WinUI 0.7 release gate")
	}

	notice, err = readBitwardenOnboardingNotice(databasePath, "0.7.1")
	if err != nil {
		t.Fatal(err)
	}
	if !notice.Show || notice.Title != "New Bitwarden integration" || notice.Message == "" {
		t.Fatalf("unexpected onboarding notice: %+v", notice)
	}
	if err := dismissBitwardenOnboardingNotice(databasePath); err != nil {
		t.Fatal(err)
	}
	notice, err = readBitwardenOnboardingNotice(databasePath, "0.7.1")
	if err != nil {
		t.Fatal(err)
	}
	if notice.Show {
		t.Fatal("dismissed notice was shown again")
	}

	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if seen := readSettingsInteger(document, bitwardenOnboardingNoticeSeenKey); seen != 1 {
		t.Fatalf("seen version = %d", seen)
	}
	if pending := readSettingsInteger(document, bitwardenOnboardingNoticePendingKey); pending != 0 {
		t.Fatalf("pending version = %d", pending)
	}
}

func TestBitwardenOnboardingNoticeRejectsInvalidVersion(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey:            currentSettingsSchemaVersion,
		bitwardenOnboardingNoticePendingKey: currentBitwardenOnboardingVersion,
	})
	for _, version := range []string{"", "dev", "0", "-1.7.0", "0.-7.0"} {
		notice, err := readBitwardenOnboardingNotice(databasePath, version)
		if err != nil {
			t.Fatal(err)
		}
		if notice.Show {
			t.Fatalf("notice shown for invalid version %q", version)
		}
	}
}

func TestBitwardenReadersApplyLegacySettingsMigrationInMemory(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey: 3,
		bwExtKeyPath:             `C:\legacy\bitwarden`,
		bwCliKeyServerRegion:     bitwardenCliServerEurope,
	})
	extension, err := readBitwardenExtensionSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := readBitwardenCliSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if extension.Source != bitwardenSourceManualFolder {
		t.Fatalf("extension source = %d", extension.Source)
	}
	if cli.ServerRegion != bitwardenCliServerCurrent {
		t.Fatalf("CLI server region = %d", cli.ServerRegion)
	}
}

func TestPromptReaderAppliesLegacySettingsMigrationInMemory(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		settingsSchemaVersionKey:     0,
		promptBeforeTunnelConnectKey: false,
	})
	enabled, err := readPromptBeforeTunnelConnect(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("pre-v1 prompt setting was not migrated to the WinUI default")
	}
}

func TestAutoCopyOnSelectDefaultsOnAndPersistsChanges(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")

	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.AutoCopyOnSelect {
		t.Fatal("auto-copy selection should be enabled by default")
	}

	if err := writeAutoCopyOnSelect(databasePath, false); err != nil {
		t.Fatal(err)
	}
	settings, err = readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.AutoCopyOnSelect {
		t.Fatal("disabled auto-copy selection setting was not persisted")
	}
}

func TestApplicationThemeReadsWinUIAndLegacyRepresentationsSafely(t *testing.T) {
	for name, test := range map[string]struct {
		value   any
		present bool
		want    applicationTheme
	}{
		"missing":        {want: applicationThemeSystem},
		"winui-system":   {value: 0, present: true, want: applicationThemeSystem},
		"winui-light":    {value: 1, present: true, want: applicationThemeLight},
		"winui-dark":     {value: 2, present: true, want: applicationThemeDark},
		"string-system":  {value: "System", present: true, want: applicationThemeSystem},
		"string-light":   {value: "light", present: true, want: applicationThemeLight},
		"invalid-number": {value: 42, present: true, want: applicationThemeSystem},
		"invalid-string": {value: "sepia", present: true, want: applicationThemeSystem},
		"invalid-type":   {value: true, present: true, want: applicationThemeSystem},
	} {
		t.Run(name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			if test.present {
				bitwardenTestWriteSettings(t, databasePath, map[string]any{themeKey: test.value})
			}
			settings, err := readAppSettings(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			if settings.Theme != test.want {
				t.Fatalf("theme = %q, want %q", settings.Theme, test.want)
			}
		})
	}
}

func TestWriteApplicationThemeUsesWinUIEnumAndPreservesOtherSettings(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		themeKey:                     1,
		"AppAuthenticationMode":      2,
		"AppAuthenticationFutureKey": "keep-auth",
		"FutureSetting":              map[string]any{"enabled": true},
	})

	if err := writeApplicationTheme(databasePath, applicationThemeDark); err != nil {
		t.Fatal(err)
	}

	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if string(document[themeKey]) != "2" {
		t.Fatalf("persisted Theme = %s, want WinUI enum value 2", document[themeKey])
	}
	var futureSetting map[string]bool
	if err := json.Unmarshal(document["FutureSetting"], &futureSetting); err != nil {
		t.Fatal(err)
	}
	if string(document["AppAuthenticationMode"]) != "2" ||
		string(document["AppAuthenticationFutureKey"]) != `"keep-auth"` ||
		!futureSetting["enabled"] {
		t.Fatalf("theme save dropped unrelated settings: %s", contents)
	}
}

func TestLegacyElectronThemeMigrationPreservesExplicitSharedTheme(t *testing.T) {
	for name, sharedTheme := range map[string]any{
		"valid":             "Light",
		"invalid-string":    "sepia",
		"invalid-number":    42,
		"explicit-null":     nil,
		"invalid-structure": map[string]any{"future": true},
	} {
		t.Run(name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			bitwardenTestWriteSettings(t, databasePath, map[string]any{
				themeKey:                sharedTheme,
				"AppAuthenticationMode": 1,
			})
			_, settingsPath := authPaths(databasePath)
			before, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			legacyTheme := "dark"
			result, err := migrateLegacyElectronTheme(databasePath, &legacyTheme)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Handled || result.Migrated {
				t.Fatalf("migration result = %+v", result)
			}
			after, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("explicit shared theme was rewritten:\n%s", after)
			}
		})
	}
}

func TestLegacyElectronThemeMigrationImportsAndPreservesOtherSettings(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		"AppAuthenticationMode": 1,
		"FutureSetting":         "keep-me",
	})

	legacyTheme := "dark"
	result, err := migrateLegacyElectronTheme(databasePath, &legacyTheme)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Handled || !result.Migrated {
		t.Fatalf("migration result = %+v", result)
	}

	_, settingsPath := authPaths(databasePath)
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if string(document[themeKey]) != "2" ||
		string(document["AppAuthenticationMode"]) != "1" ||
		string(document["FutureSetting"]) != `"keep-me"` {
		t.Fatalf("unexpected migrated settings: %s", contents)
	}

	beforeRetry := append([]byte(nil), contents...)
	retryTheme := "light"
	retry, err := migrateLegacyElectronTheme(databasePath, &retryTheme)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Handled || retry.Migrated {
		t.Fatalf("idempotent migration result = %+v", retry)
	}
	afterRetry, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRetry, beforeRetry) {
		t.Fatalf("idempotent migration rewrote settings:\n%s", afterRetry)
	}
}

func TestLegacyElectronThemeMigrationLeavesMalformedDocumentUntouched(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)
	malformed := []byte(`{"AppAuthenticationMode": 1, "Theme":`)
	if err := os.WriteFile(settingsPath, malformed, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyTheme := "light"
	result, err := migrateLegacyElectronTheme(databasePath, &legacyTheme)
	if err != nil {
		t.Fatal(err)
	}
	if result.Handled || result.Migrated {
		t.Fatalf("malformed settings were reported as handled: %+v", result)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, malformed) {
		t.Fatalf("malformed settings were overwritten: %q", after)
	}
}

func TestShellSettingsDefaultPersistAndClamp(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ConfirmOnTabClose || settings.SidebarWidth != defaultSidebarWidth {
		t.Fatalf("defaults = %+v", settings)
	}
	if err := writeConfirmOnTabClose(databasePath, false); err != nil {
		t.Fatal(err)
	}
	if err := writeSidebarWidth(databasePath, maxSidebarWidth+1000); err != nil {
		t.Fatal(err)
	}
	settings, err = readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ConfirmOnTabClose || settings.SidebarWidth != maxSidebarWidth {
		t.Fatalf("persisted settings = %+v", settings)
	}
}

func TestShellSettingsRejectBadLegacyValuesSafely(t *testing.T) {
	for name, test := range map[string]struct {
		value any
		want  int
	}{
		"invalid-type": {value: "wide", want: defaultSidebarWidth},
		"below-min":    {value: -42, want: minSidebarWidth},
		"above-max":    {value: 100000, want: maxSidebarWidth},
	} {
		t.Run(name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			bitwardenTestWriteSettings(t, databasePath, map[string]any{sidebarWidthKey: test.value})
			settings, err := readAppSettings(databasePath)
			if err != nil {
				t.Fatal(err)
			}
			if settings.SidebarWidth != test.want {
				t.Fatalf("sidebar width = %d, want %d", settings.SidebarWidth, test.want)
			}
		})
	}
}

func TestConnectionTreeExpansionStateDistinguishesMissingAndCollapsed(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ConnectionTreeExpansion != nil {
		t.Fatalf("missing expansion state = %#v, want nil", settings.ConnectionTreeExpansion)
	}

	if err := writeConnectionTreeExpansion(databasePath, connectionTreeExpansionState{
		DefaultExpanded: false,
		FolderIDs:       []string{},
	}); err != nil {
		t.Fatal(err)
	}
	settings, err = readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ConnectionTreeExpansion == nil || settings.ConnectionTreeExpansion.DefaultExpanded || len(settings.ConnectionTreeExpansion.FolderIDs) != 0 {
		t.Fatalf("collapse-all expansion state = %#v, want explicit collapsed default", settings.ConnectionTreeExpansion)
	}
}

func TestConnectionTreeExpansionStatePersistsUniqueFolderIDs(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := writeConnectionTreeExpansion(
		databasePath,
		connectionTreeExpansionState{
			DefaultExpanded: true,
			FolderIDs:       []string{"folder-b", "folder-a", "folder-b"},
		},
	); err != nil {
		t.Fatal(err)
	}
	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"folder-b", "folder-a"}
	if settings.ConnectionTreeExpansion == nil || !settings.ConnectionTreeExpansion.DefaultExpanded {
		t.Fatalf("expansion state = %#v, want expanded default", settings.ConnectionTreeExpansion)
	}
	if len(settings.ConnectionTreeExpansion.FolderIDs) != len(want) {
		t.Fatalf("expansion exceptions = %#v, want %#v", settings.ConnectionTreeExpansion.FolderIDs, want)
	}
	for index := range want {
		if settings.ConnectionTreeExpansion.FolderIDs[index] != want[index] {
			t.Fatalf("expansion exceptions = %#v, want %#v", settings.ConnectionTreeExpansion.FolderIDs, want)
		}
	}
}

func TestConnectionTreeExpansionStateSupportsMaximumCompactTree(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	folderIDs := make([]string, maxConnectionTreeExpansionFolderIDs)
	for index := range folderIDs {
		folderIDs[index] = fmt.Sprintf("%0128d", index)
	}
	if err := writeConnectionTreeExpansion(databasePath, connectionTreeExpansionState{
		DefaultExpanded: true,
		FolderIDs:       folderIDs,
	}); err != nil {
		t.Fatal(err)
	}
	settings, err := readAppSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ConnectionTreeExpansion == nil {
		t.Fatal("expansion state is missing")
	}
	if len(settings.ConnectionTreeExpansion.FolderIDs) != len(folderIDs) {
		t.Fatalf("expansion exception count = %d, want %d", len(settings.ConnectionTreeExpansion.FolderIDs), len(folderIDs))
	}
}

func TestConnectionTreeExpansionStateRejectsInvalidFolderIDs(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	for name, folderIDs := range map[string][]string{
		"nil":        nil,
		"empty id":   {""},
		"long id":    {strings.Repeat("x", maxConnectionTreeExpansionFolderIDBytes+1)},
		"whitespace": {" folder"},
		"control":    {"folder\n"},
		"too many":   make([]string, maxConnectionTreeExpansionFolderIDs+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := writeConnectionTreeExpansion(databasePath, connectionTreeExpansionState{
				FolderIDs: folderIDs,
			}); err == nil {
				t.Fatal("invalid expansion state was accepted")
			}
		})
	}
}
