package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
