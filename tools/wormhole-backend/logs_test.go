package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogRetentionDaysNormalization(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, defaultLogRetentionDays},
		{-1, defaultLogRetentionDays},
		{366, defaultLogRetentionDays},
		{999, defaultLogRetentionDays},
		{minimumLogRetentionDays, minimumLogRetentionDays},
		{maximumLogRetentionDays, maximumLogRetentionDays},
		{30, 30},
		{defaultLogRetentionDays, defaultLogRetentionDays},
	}
	for _, test := range tests {
		if actual := normalizeLogRetentionDays(test.input); actual != test.expected {
			t.Fatalf("normalizeLogRetentionDays(%d) = %d, want %d", test.input, actual, test.expected)
		}
	}
}

func TestLogLevelNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"debug", logLevelDebug},
		{"info", logLevelInfo},
		{"", logLevelInfo},
		{"DEBUG", logLevelInfo},
		{"verbose", logLevelInfo},
	}
	for _, test := range tests {
		if actual := normalizeLogLevel(test.input); actual != test.expected {
			t.Fatalf("normalizeLogLevel(%q) = %q, want %q", test.input, actual, test.expected)
		}
	}
}

func TestLogLevelDefaultsAndPersists(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")

	level, err := readLogLevel(databasePath)
	if err != nil || level != defaultLogLevel {
		t.Fatalf("absent level = %q, %v; want %q default", level, err, defaultLogLevel)
	}

	written, err := writeLogLevel(databasePath, "debug")
	if err != nil || written != logLevelDebug {
		t.Fatalf("writeLogLevel(debug) = %q, %v; want %q", written, err, logLevelDebug)
	}
	level, err = readLogLevel(databasePath)
	if err != nil || level != logLevelDebug {
		t.Fatalf("readLogLevel() = %q, %v; want %q", level, err, logLevelDebug)
	}

	written, err = writeLogLevel(databasePath, "not-a-level")
	if err != nil || written != defaultLogLevel {
		t.Fatalf("writeLogLevel(invalid) = %q, %v; want %q", written, err, defaultLogLevel)
	}
}

func TestLogsInfoPathsMatchDailyLayout(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	info, err := logsInfo(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	expectedDirectory := filepath.Join(filepath.Dir(databasePath), "logs")
	if info.LogsDirectoryPath != expectedDirectory {
		t.Fatalf("logs directory = %q, want %q", info.LogsDirectoryPath, expectedDirectory)
	}
	base := filepath.Base(info.CurrentLogFilePath)
	prefix := "wormhole-"
	if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ".log") {
		t.Fatalf("unexpected log file name %q", base)
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".log")
	if _, err := time.Parse("20060102", stamp); err != nil {
		t.Fatalf("log file name %q does not carry a yyyyMMdd date: %v", base, err)
	}
	if filepath.Dir(info.CurrentLogFilePath) != expectedDirectory {
		t.Fatalf("log file parent = %q, want %q", filepath.Dir(info.CurrentLogFilePath), expectedDirectory)
	}
	if info.LogRetentionDays != defaultLogRetentionDays {
		t.Fatalf("default retention = %d, want %d", info.LogRetentionDays, defaultLogRetentionDays)
	}
}

func TestLogRetentionSettingsMerge(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"Fallback": 1, "PromptBeforeTunnelConnect": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	written, err := writeLogRetentionDays(databasePath, 90)
	if err != nil {
		t.Fatalf("writeLogRetentionDays() error = %v", err)
	}
	if written != 90 {
		t.Fatalf("writeLogRetentionDays() = %d, want 90", written)
	}
	days, err := readLogRetentionDays(databasePath)
	if err != nil {
		t.Fatalf("readLogRetentionDays() error = %v", err)
	}
	if days != 90 {
		t.Fatalf("readLogRetentionDays() = %d, want 90", days)
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("saved settings are invalid JSON: %v", err)
	}
	for _, key := range []string{"Fallback", "PromptBeforeTunnelConnect"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("saved settings lost key %q: %s", key, contents)
		}
	}
	var saved int
	if err := json.Unmarshal(document[logRetentionDaysKey], &saved); err != nil || saved != 90 {
		t.Fatalf("saved %s = %s, want 90", logRetentionDaysKey, document[logRetentionDaysKey])
	}
}

func TestWriteLogRetentionDaysNormalizesAndReturnsSavedValue(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	written, err := writeLogRetentionDays(databasePath, 999)
	if err != nil {
		t.Fatal(err)
	}
	if written != defaultLogRetentionDays {
		t.Fatalf("writeLogRetentionDays(999) = %d, want %d", written, defaultLogRetentionDays)
	}
	days, err := readLogRetentionDays(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if days != defaultLogRetentionDays {
		t.Fatalf("readLogRetentionDays() = %d, want %d", days, defaultLogRetentionDays)
	}
}

func TestLogRetentionDefaultsWhenMissingOrInvalid(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)

	days, err := readLogRetentionDays(databasePath)
	if err != nil || days != defaultLogRetentionDays {
		t.Fatalf("absent setting = %d, %v; want %d default", days, err, defaultLogRetentionDays)
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, err = readLogRetentionDays(databasePath)
	if err != nil || days != defaultLogRetentionDays {
		t.Fatalf("invalid document = %d, %v; want %d default", days, err, defaultLogRetentionDays)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"LogRetentionDays": "not-a-number"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, err = readLogRetentionDays(databasePath)
	if err != nil || days != defaultLogRetentionDays {
		t.Fatalf("invalid value = %d, %v; want %d default", days, err, defaultLogRetentionDays)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"LogRetentionDays": 400}`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, err = readLogRetentionDays(databasePath)
	if err != nil || days != defaultLogRetentionDays {
		t.Fatalf("out-of-range value = %d, %v; want %d default", days, err, defaultLogRetentionDays)
	}
}

func TestEnsureCurrentDayLogFileCreatesFileAndDirectory(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	path := currentDayLogFilePath(databasePath)
	if err := ensureCurrentDayLogFile(databasePath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("today's log file was not created: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("today's log path %q is a directory", path)
	}
	if err := ensureCurrentDayLogFile(databasePath); err != nil {
		t.Fatalf("ensuring an existing log file failed: %v", err)
	}
}
