package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppLoggerWritesDailyFile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger, err := newAppLogger(databasePath)
	if err != nil {
		t.Fatal(err)
	}
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

	pruneLogFiles(directory, 3)

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

	pruneLogFiles(directory, 1)

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
	logger, err := newAppLogger(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.close()

	// Simulate a process that crossed midnight by pointing the logger at yesterday's file.
	yesterday := time.Now().AddDate(0, 0, -1).Format("20060102")
	yesterdayPath := filepath.Join(logger.directory, logFileNamePrefix+yesterday+logFileNameSuffix)
	if err := os.WriteFile(yesterdayPath, []byte("yesterday\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger.day = yesterday
	logger.file.Close()
	oldFile, err := os.OpenFile(yesterdayPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	logger.file = oldFile

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
