package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogLevelDefaultsAndPersists(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")

	_, level, err := readLogSettings(databasePath)
	if err != nil || level != "info" {
		t.Fatalf("absent level = %q, %v; want info", level, err)
	}

	for _, test := range []struct {
		input string
		want  string
	}{
		{"debug", "debug"},
		{"info", "info"},
		{"", "info"},
		{"DEBUG", "info"},
		{"verbose", "info"},
	} {
		initial := "debug"
		if test.want == "debug" {
			initial = "info"
		}
		if _, err := writeLogLevel(databasePath, initial); err != nil {
			t.Fatal(err)
		}
		written, err := writeLogLevel(databasePath, test.input)
		if err != nil || written != test.want {
			t.Fatalf("writeLogLevel(%q) = %q, %v; want %q", test.input, written, err, test.want)
		}
		_, level, err := readLogSettings(databasePath)
		if err != nil || level != test.want {
			t.Fatalf("read after writeLogLevel(%q) = %q, %v; want %q", test.input, level, err, test.want)
		}
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
	days, _, err := readLogSettings(databasePath)
	if err != nil {
		t.Fatalf("readLogSettings() retention error = %v", err)
	}
	if days != 90 {
		t.Fatalf("readLogSettings() retention = %d, want 90", days)
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
	for _, test := range []struct {
		input int
		want  int
	}{
		{-1, 14},
		{0, 14},
		{1, 1},
		{30, 30},
		{365, 365},
		{366, 14},
	} {
		if _, err := writeLogRetentionDays(databasePath, 90); err != nil {
			t.Fatal(err)
		}
		written, err := writeLogRetentionDays(databasePath, test.input)
		if err != nil || written != test.want {
			t.Fatalf("writeLogRetentionDays(%d) = %d, %v; want %d", test.input, written, err, test.want)
		}
		days, _, err := readLogSettings(databasePath)
		if err != nil || days != test.want {
			t.Fatalf("read after writeLogRetentionDays(%d) = %d, %v; want %d", test.input, days, err, test.want)
		}
	}
}

func TestLogRetentionDefaultsWhenMissingOrInvalid(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)

	days, _, err := readLogSettings(databasePath)
	if err != nil || days != 14 {
		t.Fatalf("absent setting = %d, %v; want %d default", days, err, 14)
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, _, err = readLogSettings(databasePath)
	if err != nil || days != 14 {
		t.Fatalf("invalid document = %d, %v; want %d default", days, err, 14)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"LogRetentionDays": "not-a-number"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, _, err = readLogSettings(databasePath)
	if err != nil || days != 14 {
		t.Fatalf("invalid value = %d, %v; want %d default", days, err, 14)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"LogRetentionDays": 400}`), 0o600); err != nil {
		t.Fatal(err)
	}
	days, _, err = readLogSettings(databasePath)
	if err != nil || days != 14 {
		t.Fatalf("out-of-range value = %d, %v; want %d default", days, err, 14)
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

func TestOpenLogTargetsCreatesPathsAndWrapsShellFailures(t *testing.T) {
	original := openLocalLogPath
	t.Cleanup(func() { openLocalLogPath = original })
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	var opened []string
	openLocalLogPath = func(path string) error {
		opened = append(opened, path)
		return nil
	}
	if err := openCurrentDayLogFile(databasePath); err != nil {
		t.Fatal(err)
	}
	if err := openLogsDirectory(databasePath); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 2 || opened[0] != currentDayLogFilePath(databasePath) || opened[1] != logsDirectoryPath(databasePath) {
		t.Fatalf("opened log paths = %#v", opened)
	}
	if !fileExists(currentDayLogFilePath(databasePath)) || !directoryExists(logsDirectoryPath(databasePath)) {
		t.Fatal("log targets were not created before opening")
	}
	openLocalLogPath = func(string) error { return errors.New("shell failed") }
	if err := openCurrentDayLogFile(databasePath); err == nil || !strings.Contains(err.Error(), "today's log file") {
		t.Fatalf("current log shell error = %v", err)
	}
	if err := openLogsDirectory(databasePath); err == nil || !strings.Contains(err.Error(), "logs folder") {
		t.Fatalf("logs directory shell error = %v", err)
	}
}
