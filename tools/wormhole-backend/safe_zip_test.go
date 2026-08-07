package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractZipSafelyCountsDirectoryEntries(t *testing.T) {
	zipPath := writeSafeZipTestArchive(t, map[string]string{
		"one/": "",
		"two/": "",
	})
	err := extractZipSafely(zipPath, t.TempDir(), safeZipTestOptions(1, 1024))
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("expected directory entry limit error, got %v", err)
	}
}

func TestExtractZipSafelyRejectsEntryLargerThanBudget(t *testing.T) {
	zipPath := writeSafeZipTestArchive(t, map[string]string{"payload": "x"})
	err := extractZipSafely(zipPath, t.TempDir(), safeZipTestOptions(10, 0))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected extracted size limit error, got %v", err)
	}
}

func TestExtractZipSafelyRejectsAlternateDataStreamPath(t *testing.T) {
	zipPath := writeSafeZipTestArchive(t, map[string]string{"manifest.json:payload": `{}`})
	err := extractZipSafely(zipPath, t.TempDir(), safeZipTestOptions(10, 1024))
	if err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("expected alternate data stream path error, got %v", err)
	}
}

func TestExtractZipSafelyRejectsWindowsNormalizedTraversalAndDevices(t *testing.T) {
	for _, name := range []string{
		".. /outside.txt",
		"folder./manifest.json",
		"CON",
		"nested/NUL.json",
		"COM1.txt",
		"file?.js",
	} {
		t.Run(name, func(t *testing.T) {
			zipPath := writeSafeZipTestArchive(t, map[string]string{name: "payload"})
			err := extractZipSafely(zipPath, t.TempDir(), safeZipTestOptions(10, 1024))
			if err == nil || !strings.Contains(err.Error(), "unsafe path") {
				t.Fatalf("expected unsafe portable path error for %q, got %v", name, err)
			}
		})
	}
}

func TestExtractZipSafelyRejectsDuplicateFiles(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, contents := range []string{"first", "second"} {
		entry, err := writer.Create("manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(zipPath, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	err := extractZipSafely(zipPath, t.TempDir(), safeZipTestOptions(10, 1024))
	if err == nil || !strings.Contains(err.Error(), "extraction failed") {
		t.Fatalf("expected duplicate entry error, got %v", err)
	}
}

func safeZipTestOptions(maxEntries int, maxBytes int64) safeZipExtractionOptions {
	return safeZipExtractionOptions{
		maxEntries:           maxEntries,
		maxExtractedBytes:    maxBytes,
		unsafePathError:      "unsafe path",
		unsupportedTypeError: "unsupported type",
		tooManyEntriesError:  "too many entries",
		tooLargeError:        "too large",
		extractionError:      "extraction failed",
	}
}

func writeSafeZipTestArchive(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, contents := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(zipPath, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return zipPath
}
