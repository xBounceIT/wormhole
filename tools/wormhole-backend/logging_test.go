package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppLoggerWritesDailyFile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	defer logger.close()

	logger.write("INF", "test message %d", 42)

	path := currentDayLogFilePath(databasePath)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("daily log file was not written: %v", err)
	}
	line := string(contents)
	if !strings.Contains(line, "[INF]") {
		t.Fatalf("log line %q has no level token", line)
	}
	if !strings.Contains(line, "test message 42") {
		t.Fatalf("log line %q misses the message", line)
	}
	if !strings.HasPrefix(line, time.Now().Format("2006-01-02 15:04")) {
		t.Fatalf("log line %q misses the timestamp prefix", line)
	}
}

func TestZeroValueLoggerIsNoop(t *testing.T) {
	logger := &appLogger{}
	logger.write("INF", "must not panic")
	logger.close()
}

func TestAppLoggerFiltersDebugUnderInfoLevel(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	defer logger.close()

	// Default level is Info: DEBUG messages are dropped, INFO/WRN/ERR are kept.
	logger.write("DBG", "debug trace")
	logger.write("INF", "info message")
	logger.write("WRN", "warning message")
	logger.write("ERR", "error message")

	path := currentDayLogFilePath(databasePath)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("daily log file was not written: %v", err)
	}
	text := string(contents)
	if strings.Contains(text, "debug trace") {
		t.Fatalf("debug trace was written under Info level:\n%s", text)
	}
	for _, expected := range []string{"info message", "warning message", "error message"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("log under Info level misses %q:\n%s", expected, text)
		}
	}
}

func TestAppLoggerWritesDebugUnderDebugLevel(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	defer logger.close()
	if _, err := writeLogLevel(databasePath, logLevelDebug); err != nil {
		t.Fatal(err)
	}

	logger.write("DBG", "debug trace")
	logger.write("INF", "info message")

	path := currentDayLogFilePath(databasePath)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("daily log file was not written: %v", err)
	}
	text := string(contents)
	for _, expected := range []string{"debug trace", "info message"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("log under Debug level misses %q:\n%s", expected, text)
		}
	}
}

func TestBackendFailuresIncludeTracebackAtInfoLevel(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	previous := appLog
	appLog = logger
	t.Cleanup(func() {
		logger.close()
		appLog = previous
	})

	var protocol bytes.Buffer
	writer := &backendLineWriter{writer: bufio.NewWriter(&protocol)}
	if err := writer.write(backendResponse{
		ID: "test-request", OK: false, Error: "private-cookie-value", diagnosticCause: io.ErrUnexpectedEOF,
	}); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, expected := range []string{
		"[ERR] [go pid=",
		"backend request failed (cause=unexpected-eof)",
		"traceback:",
		"backendLineWriter).write",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Info log misses %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "private-cookie-value") || !strings.Contains(protocol.String(), "private-cookie-value") {
		t.Fatal("a protocol error leaked into the log or its IPC response was changed")
	}
}

func TestPruneLogFilesKeepsNewestDailyFiles(t *testing.T) {
	directory := t.TempDir()
	var expected []string
	for day := 1; day <= 8; day++ {
		name := "wormhole-2026010" + string(rune('0'+day)) + ".log"
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if day >= 6 {
			expected = append(expected, name)
		}
	}

	if err := pruneLogFiles(directory, 3, ""); err != nil {
		t.Fatal(err)
	}

	remaining, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != len(expected) {
		t.Fatalf("pruned directory has %d files, want %d", len(remaining), len(expected))
	}
	for _, entry := range remaining {
		found := false
		for _, name := range expected {
			if entry.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unexpected surviving file %q", entry.Name())
		}
	}
}

func TestPruneLogFilesIgnoresNonDailyFiles(t *testing.T) {
	directory := t.TempDir()
	unrelated := filepath.Join(directory, "wormhole-backup.log")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wormhole-20260101.log", "wormhole-20260102.log"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := pruneLogFiles(directory, 1, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("non-daily file was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "wormhole-20260102.log")); err != nil {
		t.Fatalf("newest daily file was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "wormhole-20260101.log")); !os.IsNotExist(err) {
		t.Fatalf("oldest daily file should have been pruned, got %v", err)
	}
}

func TestAppLoggerRollsToNewDay(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	defer logger.close()

	// Simulate a process that crossed midnight after pruning yesterday's log files.
	yesterday := time.Now().AddDate(0, 0, -1).Format("20060102")
	yesterdayPath := filepath.Join(logger.directory, logFileNamePrefix+yesterday+logFileNameSuffix)
	if err := appendLogLine(yesterdayPath, "yesterday\n"); err != nil {
		t.Fatal(err)
	}
	logger.prunedDay = yesterday

	logger.write("INF", "new day")

	todayPath := currentDayLogFilePath(databasePath)
	if _, err := os.Stat(todayPath); err != nil {
		t.Fatalf("logger did not roll to today's file: %v", err)
	}
	contents, err := os.ReadFile(todayPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "new day") {
		t.Fatalf("rolled file %q misses the new-day message", contents)
	}
}

func TestAppLoggerRecoversWhenDailyFileBecomesWritable(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	path := currentDayLogFilePath(databasePath)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	var fallback bytes.Buffer
	logger := newAppLogger(databasePath, &fallback)
	defer logger.close()
	logger.write("ERR", "first failure")
	logger.write("ERR", "second failure")
	if strings.Count(fallback.String(), logUnavailablePrefix) != 1 {
		t.Fatalf("sink failure should be reported once: %s", &fallback)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	logger.write("ERR", "after recovery")
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("after recovery")) ||
		!bytes.Contains(data, []byte("diagnostic log recovered")) {
		t.Fatalf("log did not recover: %s, %v", data, err)
	}
}

func TestIndependentLoggersAppendCompleteRecords(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	const loggers, records = 4, 10
	var writes sync.WaitGroup
	for loggerID := range loggers {
		writes.Go(func() {
			logger := newAppLogger(databasePath, nil)
			defer logger.close()
			for record := range records {
				logger.write("INF", "logger=%d record=%d", loggerID, record)
			}
		})
	}
	writes.Wait()
	data, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	for loggerID := range loggers {
		for record := range records {
			want := []byte(fmt.Sprintf("logger=%d record=%d\n", loggerID, record))
			if bytes.Count(data, want) != 1 {
				t.Fatalf("missing or interleaved record %q", want)
			}
		}
	}
}

func TestLoggerAndRetentionRejectLinkedLogDirectory(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	otherDirectory := t.TempDir()
	olderLog := dailyLogFilePath(otherDirectory, "20260101")
	newerLog := dailyLogFilePath(otherDirectory, "20260102")
	for _, path := range []string{olderLog, newerLog} {
		if err := os.WriteFile(path, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory := logsDirectoryPath(databasePath)
	if err := os.Symlink(otherDirectory, directory); err != nil {
		t.Skipf("cannot create an isolated directory link on this host: %v", err)
	}
	var fallback bytes.Buffer
	logger := newAppLogger(databasePath, &fallback)
	logger.write("ERR", "failed workspace")
	if !strings.Contains(fallback.String(), logUnavailablePrefix+" invalid-path") {
		t.Fatalf("primary log failure did not reach stderr: %s", &fallback)
	}
	if err := pruneLogFiles(directory, 1, ""); !errors.Is(err, errInvalidLogPath) {
		t.Fatalf("retention did not reject the linked directory: %v", err)
	}
	if err := ensureCurrentDayLogFile(databasePath); !errors.Is(err, errInvalidLogPath) {
		t.Fatalf("open today's log did not reject the linked directory: %v", err)
	}
	entries, err := os.ReadDir(otherDirectory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("logging touched another directory: %v, %v", entries, err)
	}
	for _, path := range []string{olderLog, newerLog} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "untouched" {
			t.Fatalf("logging changed an unrelated file: %s, %v", data, err)
		}
	}
}

func TestAppLoggerCoalescesRapidFailuresAtTheSameSite(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	source := func() { logOperationFailure("serial input", io.ErrUnexpectedEOF) }
	previous := appLog
	appLog = logger
	t.Cleanup(func() { appLog = previous })
	for range 100 {
		source()
	}
	logOperationFailure("serial input", io.ErrUnexpectedEOF) // A distinct call site.
	for key, occurrence := range logger.recentErrors {
		occurrence.at = occurrence.at.Add(-10 * time.Second)
		logger.recentErrors[key] = occurrence
	}
	source()
	data, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil || bytes.Count(data, []byte("serial input failed")) != 3 ||
		!bytes.Contains(data, []byte("(repeated=99)")) {
		t.Fatalf("repeated errors were not grouped by site: %s, %v", data, err)
	}
}

func TestAppLoggerPicksUpSettingsAndKeepsExactRetention(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	defer logger.close()
	logger.write("DBG", "before settings change")
	if _, err := writeLogLevel(databasePath, logLevelDebug); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLogRetentionDays(databasePath, 1); err != nil {
		t.Fatal(err)
	}
	oldPath := dailyLogFilePath(logger.directory, time.Now().AddDate(0, 0, -1).Format("20060102"))
	if err := appendLogLine(oldPath, "old log"); err != nil {
		t.Fatal(err)
	}
	futurePath := dailyLogFilePath(logger.directory, time.Now().AddDate(0, 0, 1).Format("20060102"))
	if err := appendLogLine(futurePath, "log from before a clock change"); err != nil {
		t.Fatal(err)
	}
	logger.refreshSettings()
	logger.write("DBG", "after settings change")

	data, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil || !bytes.Contains(data, []byte("after settings change")) ||
		bytes.Contains(data, []byte("before settings change")) {
		t.Fatalf("settings change was not applied: %s, %v", data, err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old log was kept past the new retention limit: %v", err)
	}
	if _, err := os.Stat(futurePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("out-of-date future log displaced the active log: %v", err)
	}
}

func TestAppLoggerRetriesRetentionAfterTemporaryFileLock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows file sharing is required to reproduce the temporary lock")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	oldPath := dailyLogFilePath(logger.directory, time.Now().AddDate(0, 0, -1).Format("20060102"))
	if err := appendLogLine(oldPath, "old log"); err != nil {
		t.Fatal(err)
	}
	if _, err := writeLogRetentionDays(databasePath, 1); err != nil {
		t.Fatal(err)
	}
	locked, err := os.Open(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	logger.write("INF", "cleanup is blocked")
	data, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil || !bytes.Contains(data, []byte("log retention cleanup failed")) {
		t.Fatalf("retention failure is missing: %s, %v", data, err)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	logger.write("INF", "before retry")
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("retention unexpectedly retried before the deadline: %v", err)
	}
	logger.pruneAttempt = logger.pruneAttempt.Add(-time.Minute)
	logger.write("INF", "after retry")
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retention failed to recover after the lock was released: %v", err)
	}
}

func TestLogCLIWorksWhenWorkspaceSchemaCannotOpen(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	corrupt := []byte("not a database")
	if err := os.WriteFile(databasePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := openLocalLogPath
	openLocalLogPath = func(_ string) error { return nil }
	t.Cleanup(func() { openLocalLogPath = previous })
	for _, operation := range []string{"logs-info", "open-log-file", "open-logs-folder"} {
		var output, stderr bytes.Buffer
		status := runBackendCLI([]string{"--database", databasePath, "--operation", operation}, strings.NewReader(""), &output, &stderr)
		if status != 0 || !json.Valid(output.Bytes()) || stderr.Len() != 0 {
			t.Fatalf("%s requires a working workspace: status=%d, stdout=%q, stderr=%q", operation, status, &output, &stderr)
		}
	}
	data, err := os.ReadFile(databasePath)
	if err != nil || !bytes.Equal(data, corrupt) {
		t.Fatalf("a log operation touched the workspace database: %v", err)
	}
}

func TestVaultUpdateFailureSkipsLegacyLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	if err := os.WriteFile(vaultSlotPath(path), []byte("vault marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runBackendCLI([]string{"--database", path, "--operation", "update-download"}, strings.NewReader("{invalid"), &stdout, &stderr); code != 1 {
		t.Fatal("invalid download accepted")
	}
	if _, err := os.Stat(logsDirectoryPath(path)); !os.IsNotExist(err) {
		t.Fatal("vault update created legacy diagnostics", err)
	}
}

func TestCLIEarlyAndStreamingFailuresAreLogged(t *testing.T) {
	for _, test := range []struct {
		operation       string
		stage           string
		corruptDatabase bool
	}{
		{"startup", "workspace schema initialization failed", true},
		{"update-download", "update-download failed", false},
	} {
		t.Run(test.operation, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			if test.corruptDatabase {
				if err := os.WriteFile(databasePath, []byte("not a database"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var output, stderr bytes.Buffer
			status := runBackendCLI([]string{"--database", databasePath, "--operation", test.operation},
				strings.NewReader("{invalid private-value"), &output, &stderr)
			if status != 1 || output.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid CLI failure envelope: status=%d, stdout=%q, stderr=%q", status, &output, &stderr)
			}
			data, err := os.ReadFile(currentDayLogFilePath(databasePath))
			if err != nil || !bytes.Contains(data, []byte(test.stage)) || bytes.Contains(data, []byte("private-value")) {
				t.Fatalf("early failure missing or unsafe: %s, %v", data, err)
			}
		})
	}
}

func TestNativeErrorEventsAreLoggedWithoutCopyingProtocolData(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger := newAppLogger(databasePath, nil)
	previous := appLog
	appLog = logger
	t.Cleanup(func() { logger.close(); appLog = previous })

	var ssh, serial bytes.Buffer
	sshWriter := &sshEventWriter{encoder: json.NewEncoder(&ssh)}
	serialWriter := &serialEventWriter{encoder: json.NewEncoder(&serial)}
	sshWriter.write(sshWireEvent{Type: "sftp.transfer", TransferState: "failed", Error: "private-path"})
	serialWriter.write(serialWireEvent{Type: "error", Error: "private-device"})
	data, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil || !bytes.Contains(data, []byte("SSH sftp.transfer failed")) ||
		!bytes.Contains(data, []byte("serial session failed")) || bytes.Contains(data, []byte("private-")) {
		t.Fatalf("error events missing or unsafe: %s, %v", data, err)
	}
	if !strings.Contains(ssh.String(), "private-path") || !strings.Contains(serial.String(), "private-device") {
		t.Fatal("native event data was changed")
	}
}
