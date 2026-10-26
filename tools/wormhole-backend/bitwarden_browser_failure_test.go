package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBitwardenBrowserFailureAcceptsOnlyFixedClassifications(t *testing.T) {
	for _, stage := range []string{"prepare", "profile", "migrations", "read", "capture", "restore", "commit", "flush", "marker", "background", "bridge", "checkpoint", "popup"} {
		for _, reason := range []string{"failed", "timeout", "closed", "unavailable", "conflict"} {
			code := stage + "/" + reason
			if !validBitwardenBrowserFailure(code) {
				t.Fatalf("rejected fixed code %q", code)
			}
			if err := validateBackendCommand(backendCommand{ID: "diagnostic", Action: "bitwarden.browser-failure", Value: code}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, code := range []string{"", "popup", "private-value/failed", "popup/private-value", "popup/failed\nprivate-value", "popup/failed/extra", strings.Repeat("x", 10000)} {
		if validBitwardenBrowserFailure(code) {
			t.Fatal("accepted an unclassified diagnostic")
		}
		if err := validateBackendCommand(backendCommand{ID: "diagnostic", Action: "bitwarden.browser-failure", Value: code}); err == nil {
			t.Fatal("accepted an invalid diagnostic command")
		}
		if _, err := reportBitwardenBrowserFailure(code); err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("invalid diagnostic did not return a sanitized error")
		}
	}
}

func TestBitwardenBrowserFailureReachesTheApplicationLogWithoutVaultData(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	logger, err := newAppLogger(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	previous := appLog
	appLog = logger
	t.Cleanup(func() { logger.close(); appLog = previous })
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	manager := newVncManager(nil, newBackendLineWriter(writer))
	// The log must remain available while the CLI is disabled or locked and must not
	// wait for a vault operation or try to restore its session.
	manager.bitwardenOperationMu.Lock()
	defer manager.bitwardenOperationMu.Unlock()
	manager.handle(backendCommand{ID: "failure", Action: "bitwarden.browser-failure", Value: "capture/timeout", Password: "private-password", LocalJSON: `{"token":"private-token"}`})
	var response backendResponse
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.ID != "failure" {
		t.Fatal("browser diagnostic dispatch failed")
	}
	contents, err := os.ReadFile(currentDayLogFilePath(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "[ERR] Bitwarden browser operation failed (code=capture/timeout)") {
		t.Fatal("browser failure is missing from the application log")
	}
	if strings.Contains(text, "private-password") || strings.Contains(text, "private-token") {
		t.Fatal("browser diagnostic exposed vault data")
	}
}
