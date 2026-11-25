package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Log files mirror the WinUI 3 app: one daily file (wormhole-YYYYMMDD.log) under
// <data dir>/logs, with the retention count stored in the shared settings.json document
// (see authPaths). Go owns both the paths and the setting; the renderer only reads and
// writes them through the logs-info / settings-set-log-retention operations.
const (
	logRetentionDaysKey     = "LogRetentionDays"
	logLevelKey             = "LogLevel"
	defaultLogRetentionDays = 14
	defaultLogLevel         = logLevelInfo
	minimumLogRetentionDays = 1
	maximumLogRetentionDays = 365
)

type logsInfoResponse struct {
	CurrentLogFilePath string `json:"currentLogFilePath"`
	LogsDirectoryPath  string `json:"logsDirectoryPath"`
	LogRetentionDays   int    `json:"logRetentionDays"`
	LogLevel           string `json:"logLevel"`
}

var openLocalLogPath = openLocalPathWithShell

func logsDirectoryPath(databasePath string) string {
	return filepath.Join(filepath.Dir(databasePath), "logs")
}

func currentDayLogFilePath(databasePath string) string {
	return dailyLogFilePath(logsDirectoryPath(databasePath), time.Now().Format("20060102"))
}

func dailyLogFilePath(directory, day string) string {
	return filepath.Join(directory, logFileNamePrefix+day+logFileNameSuffix)
}

func normalizeLogRetentionDays(days int) int {
	if days >= minimumLogRetentionDays && days <= maximumLogRetentionDays {
		return days
	}
	return defaultLogRetentionDays
}

// normalizeLogLevel maps an arbitrary value to a supported log level, defaulting to Info.
func normalizeLogLevel(level string) string {
	if level == logLevelDebug {
		return logLevelDebug
	}
	return logLevelInfo
}

func readLogSettings(databasePath string) (int, string, error) {
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return defaultLogRetentionDays, defaultLogLevel, nil
	}
	if err != nil {
		return defaultLogRetentionDays, defaultLogLevel, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil {
		return defaultLogRetentionDays, defaultLogLevel, nil
	}
	var days int
	var level string
	_ = json.Unmarshal(document[logRetentionDaysKey], &days)
	_ = json.Unmarshal(document[logLevelKey], &level)
	return normalizeLogRetentionDays(days), normalizeLogLevel(level), nil
}

// writeLogLevel merges the level into settings.json, preserving every other key, and
// returns the normalized value that was persisted.
func writeLogLevel(databasePath string, level string) (string, error) {
	normalized := normalizeLogLevel(level)
	_, settingsPath := authPaths(databasePath)
	document := map[string]json.RawMessage{}
	contents, err := readAuthSettingsFile(settingsPath)
	if err == nil {
		_ = json.Unmarshal(contents, &document)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if document == nil {
		document = map[string]json.RawMessage{}
	}
	value, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	document[logLevelKey] = value

	contents, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return "", fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}
	temporaryPath := settingsPath + ".tmp"
	if err := os.WriteFile(temporaryPath, append(contents, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("cannot write Wormhole settings: %w", err)
	}
	if err := replaceAuthFile(temporaryPath, settingsPath); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("cannot save Wormhole settings: %w", err)
	}
	return normalized, nil
}

// writeLogRetentionDays merges the setting into settings.json, preserving every other key
// (including the app-authentication settings) that already lives in the document, and
// returns the normalized value that was persisted.
func writeLogRetentionDays(databasePath string, days int) (int, error) {
	normalized := normalizeLogRetentionDays(days)
	_, settingsPath := authPaths(databasePath)
	document := map[string]json.RawMessage{}
	contents, err := readAuthSettingsFile(settingsPath)
	if err == nil {
		_ = json.Unmarshal(contents, &document)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if document == nil {
		document = map[string]json.RawMessage{}
	}
	value, err := json.Marshal(normalized)
	if err != nil {
		return 0, fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	document[logRetentionDaysKey] = value

	contents, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return 0, fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}
	temporaryPath := settingsPath + ".tmp"
	if err := os.WriteFile(temporaryPath, append(contents, '\n'), 0o600); err != nil {
		return 0, fmt.Errorf("cannot write Wormhole settings: %w", err)
	}
	if err := replaceAuthFile(temporaryPath, settingsPath); err != nil {
		_ = os.Remove(temporaryPath)
		return 0, fmt.Errorf("cannot save Wormhole settings: %w", err)
	}
	return normalized, nil
}

func logsInfo(databasePath string) (logsInfoResponse, error) {
	days, level, err := readLogSettings(databasePath)
	if err != nil {
		return logsInfoResponse{}, err
	}
	return logsInfoResponse{
		CurrentLogFilePath: currentDayLogFilePath(databasePath),
		LogsDirectoryPath:  logsDirectoryPath(databasePath),
		LogRetentionDays:   days,
		LogLevel:           level,
	}, nil
}

// ensureCurrentDayLogFile creates the logs directory and today's file when either is
// missing, mirroring the WinUI 3 "Open today's log" behavior.
func ensureCurrentDayLogFile(databasePath string) error {
	file, err := openDailyLog(currentDayLogFilePath(databasePath))
	if err != nil {
		return fmt.Errorf("cannot create today's log file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot open today's log file: %w", err)
	}
	return nil
}

func openCurrentDayLogFile(databasePath string) error {
	if err := ensureCurrentDayLogFile(databasePath); err != nil {
		return err
	}
	if err := openLocalLogPath(currentDayLogFilePath(databasePath)); err != nil {
		return fmt.Errorf("cannot open today's log file: %w", err)
	}
	return nil
}

func openLogsDirectory(databasePath string) error {
	path := logsDirectoryPath(databasePath)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("cannot create the Wormhole logs directory: %w", err)
	}
	root, err := openLogDirectory(path)
	if err != nil {
		return fmt.Errorf("cannot open the Wormhole logs folder: %w", err)
	}
	_ = root.Close()
	if err := openLocalLogPath(path); err != nil {
		return fmt.Errorf("cannot open the Wormhole logs folder: %w", err)
	}
	return nil
}
