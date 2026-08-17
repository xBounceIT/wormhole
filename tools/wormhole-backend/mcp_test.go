package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type callbackWriteCloser struct {
	write func([]byte) (int, error)
}

type mcpTestSecretStore struct {
	values        map[string]string
	nextReference int
}

func (writer callbackWriteCloser) Write(data []byte) (int, error) {
	if writer.write == nil {
		return len(data), nil
	}
	return writer.write(data)
}

func (writer callbackWriteCloser) Close() error { return nil }

const mcpTestPlatformEncoding = "test-platform-secret-store-v1"

func installMcpTestSecretStore(t *testing.T) *mcpTestSecretStore {
	t.Helper()
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	previousUnprotect := mcpUnprotectStoredSecret
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
		mcpUnprotectStoredSecret = previousUnprotect
	})

	secretStore := &mcpTestSecretStore{values: make(map[string]string)}
	credentialSecretStore = func(id, _ string, value string) (string, string, error) {
		if id != mcpTokenCredentialID {
			t.Fatalf("stored secret id = %q", id)
		}
		secretStore.nextReference++
		reference := fmt.Sprintf("platform-reference-%d", secretStore.nextReference)
		secretStore.values[reference] = value
		return reference, mcpTestPlatformEncoding, nil
	}
	credentialSecretDelete = func(id, encoded, encoding string) error {
		if id != mcpTokenCredentialID || encoding != mcpTestPlatformEncoding {
			t.Fatalf("deleted secret = id:%q encoding:%q", id, encoding)
		}
		delete(secretStore.values, encoded)
		return nil
	}
	mcpUnprotectStoredSecret = func(id, encoded, encoding string, _ ...string) ([]byte, error) {
		if id != mcpTokenCredentialID || encoding != mcpTestPlatformEncoding {
			return nil, errors.New("unexpected platform secret reference")
		}
		value, ok := secretStore.values[encoded]
		if !ok {
			return nil, errors.New("platform secret is missing")
		}
		return []byte(value), nil
	}
	return secretStore
}

func TestMcpAuthorizationRequiresExactBearerToken(t *testing.T) {
	if !isMcpAuthorized("Bearer secret-token", "secret-token") {
		t.Fatal("valid bearer token was rejected")
	}
	if !isMcpAuthorized("bearer secret-token", "secret-token") {
		t.Fatal("case-insensitive bearer scheme was rejected")
	}
	for _, header := range []string{
		"",
		"Basic secret-token",
		"Bearer",
		"Bearer ",
		"Bearer wrong-token",
		"Bearer secret-token-extra",
	} {
		if isMcpAuthorized(header, "secret-token") {
			t.Errorf("invalid authorization header was accepted: %q", header)
		}
	}
}

func TestMcpGetOrCreateTokenReadsStoredToken(t *testing.T) {
	if !isWindowsRuntime() {
		t.Skip("Windows DPAPI is Windows-only")
	}
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")

	// First process: no token row exists yet, so a fresh token is generated and persisted.
	first := newMcpController(&sshServer{databasePath: databasePath})
	created, err := first.getOrCreateToken()
	if err != nil {
		t.Fatalf("first getOrCreateToken: %v", err)
	}
	if created == "" {
		t.Fatal("first getOrCreateToken returned an empty token")
	}

	// Second process: the row already exists and must decrypt to the same token instead of
	// failing or silently replacing the stored value.
	second := newMcpController(&sshServer{databasePath: databasePath})
	read, err := second.getOrCreateToken()
	if err != nil {
		t.Fatalf("getOrCreateToken could not read the stored token: %v", err)
	}
	if read != created {
		t.Fatal("stored token round-trip mismatch")
	}
}

func TestMcpTokenLifecycleUsesPlatformSecretStore(t *testing.T) {
	secretStore := installMcpTestSecretStore(t)

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	first := newMcpController(&sshServer{databasePath: databasePath})
	created, err := first.getOrCreateToken()
	if err != nil {
		t.Fatalf("first getOrCreateToken: %v", err)
	}
	if created == "" || len(secretStore.values) != 1 {
		t.Fatalf("created token present = %t, platform entries = %d", created != "", len(secretStore.values))
	}

	second := newMcpController(&sshServer{databasePath: databasePath})
	reread, err := second.getOrCreateToken()
	if err != nil {
		t.Fatalf("second getOrCreateToken: %v", err)
	}
	if reread != created {
		t.Fatal("platform token round-trip mismatch")
	}

	regenerated, err := second.regenerateToken()
	if err != nil {
		t.Fatalf("regenerateToken: %v", err)
	}
	if regenerated == "" || regenerated == created || len(secretStore.values) != 1 {
		t.Fatalf(
			"regenerated token present = %t, changed = %t, platform entries = %d",
			regenerated != "",
			regenerated != created,
			len(secretStore.values),
		)
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var encoded, encoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&encoded, &encoding); err != nil {
		t.Fatal(err)
	}
	if encoding != mcpTestPlatformEncoding || encoded == regenerated || secretStore.values[encoded] != regenerated {
		t.Fatalf("stored platform token = encoding:%q reference:%q", encoding, encoded)
	}

	third := newMcpController(&sshServer{databasePath: databasePath})
	final, err := third.getOrCreateToken()
	if err != nil {
		t.Fatalf("third getOrCreateToken: %v", err)
	}
	if final != regenerated {
		t.Fatal("regenerated token round-trip mismatch")
	}
}

func TestMcpTokenReplacementRollsBackPlatformSecretOnDatabaseFailure(t *testing.T) {
	secretStore := installMcpTestSecretStore(t)
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	controller := newMcpController(&sshServer{databasePath: databasePath})
	created, err := controller.getOrCreateToken()
	if err != nil {
		t.Fatalf("getOrCreateToken: %v", err)
	}

	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	var originalReference, originalEncoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&originalReference, &originalEncoding); err != nil {
		t.Fatal(err)
	}
	trigger := fmt.Sprintf(`
CREATE TRIGGER FailMcpTokenReplacement
BEFORE INSERT ON CredentialSecrets
WHEN NEW.Id = '%s'
BEGIN
    SELECT RAISE(ABORT, 'forced MCP token write failure');
END;`, normalizeID(mcpTokenCredentialID))
	if _, err := database.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := controller.regenerateToken(); err == nil {
		t.Fatal("regenerateToken succeeded despite the database failure")
	}
	if controller.currentToken() != created {
		t.Fatal("failed regeneration changed the live token")
	}
	if len(secretStore.values) != 1 || secretStore.values[originalReference] != created {
		t.Fatalf("failed regeneration left %d platform secrets", len(secretStore.values))
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var storedReference, storedEncoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&storedReference, &storedEncoding); err != nil {
		t.Fatal(err)
	}
	if storedReference != originalReference || storedEncoding != originalEncoding {
		t.Fatalf(
			"failed regeneration changed database row: reference:%q encoding:%q",
			storedReference,
			storedEncoding,
		)
	}
}

func TestMcpReadableLegacyTokenSurvivesMigrationFailure(t *testing.T) {
	previousStore := credentialSecretStore
	previousDelete := credentialSecretDelete
	previousUnprotect := mcpUnprotectStoredSecret
	t.Cleanup(func() {
		credentialSecretStore = previousStore
		credentialSecretDelete = previousDelete
		mcpUnprotectStoredSecret = previousUnprotect
	})

	const expected = "readable-legacy-token"
	mcpUnprotectStoredSecret = func(id, encoded, encoding string, _ ...string) ([]byte, error) {
		if id != mcpTokenCredentialID || encoded != "legacy-payload" || encoding != electronSafeStorageSecretEncoding {
			t.Fatalf("unexpected legacy secret read: id:%q encoded:%q encoding:%q", id, encoded, encoding)
		}
		return []byte(expected), nil
	}
	credentialSecretStore = func(id, _ string, value string) (string, string, error) {
		if id != mcpTokenCredentialID || value != expected {
			t.Fatalf("unexpected migration write: id:%q expected-token:%t", id, value == expected)
		}
		return "", "", errors.New("platform secret store unavailable")
	}
	credentialSecretDelete = func(string, string, string) error {
		t.Fatal("failed platform store must not request deletion")
		return nil
	}

	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`,
		normalizeID(mcpTokenCredentialID),
		"legacy-payload",
		electronSafeStorageSecretEncoding,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	controller := newMcpController(&sshServer{databasePath: databasePath})
	actual, err := controller.getOrCreateToken()
	if err != nil {
		t.Fatalf("readable legacy token was rejected after migration failure: %v", err)
	}
	if actual != expected {
		t.Fatal("readable legacy token changed after migration failure")
	}

	database, err = openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var encoded, encoding string
	if err := database.QueryRow(
		"SELECT Secret, Encoding FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&encoded, &encoding); err != nil {
		t.Fatal(err)
	}
	if encoded != "legacy-payload" || encoding != electronSafeStorageSecretEncoding {
		t.Fatalf("failed migration changed legacy row: encoded:%q encoding:%q", encoded, encoding)
	}
}

func TestMcpGetOrCreateTokenDoesNotReplaceUndecryptableToken(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	database, err := openDatabase(databasePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := ensureMigrationSchema(database); err != nil {
		t.Fatal(err)
	}
	const corrupt = "this-is-not-valid-base64!!!"
	_, err = database.Exec(`
INSERT INTO CredentialSecrets (Id, Secret, Encoding, UpdatedAt)
VALUES (?, ?, ?, ?);`,
		normalizeID(mcpTokenCredentialID),
		corrupt,
		protectedSecretEncoding,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatal(err)
	}

	controller := newMcpController(&sshServer{databasePath: databasePath})
	if _, err := controller.getOrCreateToken(); err == nil {
		t.Fatal("an undecryptable stored token must fail instead of being silently replaced")
	}

	var stored string
	if err := database.QueryRow(
		"SELECT Secret FROM CredentialSecrets WHERE lower(Id) = ?;",
		normalizeID(mcpTokenCredentialID),
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != corrupt {
		t.Fatalf("undecryptable token was replaced: got %q", stored)
	}
}

func TestMcpSettingsPreserveExistingSettings(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	settingsPath := filepath.Join(filepath.Dir(databasePath), authSettingsFilename)
	if err := os.WriteFile(settingsPath, []byte(`{"mode":"pin","McpServerPort":9000}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := saveMcpSettings(databasePath, mcpSettings{Enabled: true, Port: 9123}); err != nil {
		t.Fatal(err)
	}
	settings, err := loadMcpSettings(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Enabled || settings.Port != 9123 {
		t.Fatalf("unexpected MCP settings: %#v", settings)
	}
	contents, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contents, []byte(`"mode": "pin"`)) {
		t.Fatalf("existing auth setting was not preserved: %s", contents)
	}
}

func TestLoadPersistedMcpStatusDoesNotReportAResidentServer(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := saveMcpSettings(databasePath, mcpSettings{Enabled: true, Port: 9123}); err != nil {
		t.Fatal(err)
	}

	status, err := loadPersistedMcpStatus(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.Running || status.Port != 9123 || status.Endpoint != "http://127.0.0.1:9123/mcp" {
		t.Fatalf("unexpected persisted MCP status: %#v", status)
	}
}

func TestMcpSettingsRejectInvalidPorts(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if validateMcpPort(port) == nil {
			t.Errorf("invalid MCP port was accepted: %d", port)
		}
	}
	for _, port := range []int{1, 8765, 65535} {
		if err := validateMcpPort(port); err != nil {
			t.Errorf("valid MCP port was rejected: %d: %v", port, err)
		}
	}
}

func TestMcpReplayBufferUsesBoundedRawOutput(t *testing.T) {
	buffer := newMcpReplayBuffer(4)
	buffer.append([]byte("abcdef"))
	if got := string(buffer.snapshotTail(10)); got != "cdef" {
		t.Fatalf("unexpected replay tail: %q", got)
	}
	data, position, _, dropped := buffer.since(0)
	if string(data) != "cdef" || position != 6 || !dropped {
		t.Fatalf("unexpected replay cursor: %q at %d dropped=%v", data, position, dropped)
	}
}

func TestMcpCommandCaptureStripsMarkersAndAnsi(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("printf 'hello'")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, capture.start) || bytes.Contains(payload, capture.endPrefix) {
		t.Fatal("assembled markers leaked into the echoed shell payload")
	}
	capture.push(append(append([]byte{}, capture.start...), []byte("\r\n\x1b[32mhello\x1b[0m\r\n")...))
	capture.push(append(append([]byte{}, capture.endPrefix...), []byte("0@@\r\n")...))
	result := capture.finish(false)
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("unexpected command exit code: %#v", result.ExitCode)
	}
	if result.Output != "hello" {
		t.Fatalf("unexpected captured output: %q", result.Output)
	}
	if result.TimedOut || result.Truncated {
		t.Fatalf("capture was unexpectedly incomplete: %#v", result)
	}
}

func TestMcpCommandCaptureTimesOutWithPartialOutput(t *testing.T) {
	capture, _, err := newMcpCommandCapture("sleep 10")
	if err != nil {
		t.Fatal(err)
	}
	capture.push(append(append([]byte{}, capture.start...), []byte("partial")...))
	result := capture.finish(true)
	if !result.TimedOut || result.Output != "partial" {
		t.Fatalf("unexpected timeout result: %#v", result)
	}
}

func TestMcpCommandCaptureHidesPreStartWrapperOnTimeout(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	capture.push(append([]byte("root@example:/home/user# "), payload...))
	result := capture.finish(true)
	if !result.TimedOut || result.Output != "" || result.ExitCode != nil {
		t.Fatalf("unexpected pre-start timeout result: %#v", result)
	}
}

func TestMcpPresentationFilterHidesWrapperAfterConfirmedMarkers(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
	raw := append(bytes.TrimSuffix(payload, []byte("\r")), []byte("\r\n")...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nhello\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)

	visible := filter.filter(raw)
	if string(visible) != "echo hello\r\nhello\r\n" {
		t.Fatalf("unexpected visible terminal output: %q", visible)
	}
	if bytes.Contains(visible, capture.start) || bytes.Contains(visible, capture.endPrefix) {
		t.Fatalf("MCP markers leaked into visible output: %q", visible)
	}
	if !filter.complete {
		t.Fatal("presentation filter did not complete")
	}
}

func TestMcpPresentationFilterPreservesOutputBeforeEcho(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
	prefix := []byte("root@example:/home/user# ")
	if visible := filter.filter(prefix); string(visible) != string(prefix) {
		t.Fatalf("pending prompt was not preserved: %q", visible)
	}
	if filter.complete {
		t.Fatal("presentation filter stopped before the MCP echo arrived")
	}

	raw := append(bytes.TrimSuffix(payload, []byte("\r")), []byte("\r\n")...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nhello\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)
	if visible := filter.filter(raw); string(visible) != "echo hello\r\nhello\r\n" {
		t.Fatalf("filtered command after pending prompt = %q", visible)
	}
	if !filter.complete {
		t.Fatal("presentation filter did not complete")
	}
}

func TestMcpPresentationFilterHandlesStartMarkerWithoutTerminalEcho(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
	raw := append([]byte("root@example:/home/user# "), capture.start...)
	raw = append(raw, []byte("\r\nhello\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)

	visible := filter.filter(raw)
	if string(visible) != "root@example:/home/user# echo hello\r\nhello\r\n" {
		t.Fatalf("no-echo command output = %q", visible)
	}
	if !filter.complete {
		t.Fatal("presentation filter did not complete")
	}
}

func TestMcpPresentationFilterHidesReadlineRedrawnWrapperAtEverySplit(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	echo := bytes.TrimSuffix(payload, []byte("\r"))
	redraw := append([]byte("\r<"), echo[len(echo)-32:]...)
	raw := append([]byte("root@example:/home/user# "), redraw...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nhello\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)
	want := "root@example:/home/user# echo hello\r\nhello\r\n"

	for split := 0; split <= len(raw); split++ {
		filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
		visible := append(filter.filter(raw[:split]), filter.filter(raw[split:])...)
		if string(visible) != want || !filter.complete {
			t.Fatalf("split %d readline redraw output = %q complete=%v", split, visible, filter.complete)
		}
	}
}

func TestMcpPresentationFilterHandlesFragmentedLineEndingsAndMarkers(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("printf result")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("printf result", payload, capture.start, capture.endPrefix)
	echo := bytes.TrimSuffix(payload, []byte("\r"))
	if visible := filter.filter(append(append([]byte{}, echo...), '\r')); len(visible) != 0 {
		t.Fatalf("fragmented echo became visible: %q", visible)
	}
	if visible := filter.filter(append([]byte("\n"), append(capture.start, '\r')...)); string(visible) != "printf result\r\n" {
		t.Fatalf("fragmented start marker output = %q", visible)
	}
	if visible := filter.filter([]byte("\nbody")); string(visible) != "body" {
		t.Fatalf("fragmented start line ending output = %q", visible)
	}
	end := append(append([]byte(" tail"), capture.endPrefix...), []byte("17@@\r")...)
	if visible := filter.filter(end); string(visible) != " tail" {
		t.Fatalf("fragmented end marker output = %q", visible)
	}
	if visible := filter.filter([]byte("\nafter")); string(visible) != "after" || !filter.complete {
		t.Fatalf("end line ending output = %q complete=%v", visible, filter.complete)
	}
	if visible := filter.filter([]byte(" pass-through")); string(visible) != " pass-through" {
		t.Fatalf("completed filter output = %q", visible)
	}
}

func TestMcpPresentationFilterHandlesEveryPromptAndWrapperSplit(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte("root@example:/home/user# "), bytes.TrimSuffix(payload, []byte("\r"))...)
	raw = append(raw, []byte("\r\n")...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nhello\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\nroot@example:/home/user# ")...)
	want := "root@example:/home/user# echo hello\r\nhello\r\nroot@example:/home/user# "

	for split := 0; split <= len(raw); split++ {
		filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
		visible := append(filter.filter(raw[:split]), filter.filter(raw[split:])...)
		if string(visible) != want || !filter.complete {
			t.Fatalf("split %d output = %q complete=%v", split, visible, filter.complete)
		}
	}
}

func TestMcpPresentationRetirementDropsPartialWrapperPrefixes(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	echo := bytes.TrimSuffix(payload, []byte("\r"))
	for name, prefix := range map[string][]byte{
		"echo":         append([]byte(nil), echo[:len(echo)/2]...),
		"start-marker": append(append(append([]byte(nil), echo...), []byte("\r\n")...), capture.start[:len(capture.start)/2]...),
	} {
		t.Run(name, func(t *testing.T) {
			filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
			native := &sshNativeSession{mcpPresentation: filter}
			if visible := native.filterMcpPresentationLocked(prefix); len(visible) != 0 {
				t.Fatalf("speculative prefix became visible before interrupt: %q", visible)
			}
			native.abandonMcpCommandPresentation()
			native.retireAbandonedMcpCommandPresentationOnInterrupt([]byte{'\x03'})

			visible := native.filterMcpPresentationLocked([]byte("^C\r\nroot@example:/home/user# "))
			if string(visible) != "^C\r\nroot@example:/home/user# " {
				t.Fatalf("post-interrupt output exposed the speculative prefix: %q", visible)
			}
		})
	}
}

func TestMcpPresentationFilterFailsOpenAtEverySpeculativeBoundary(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo x")
	if err != nil {
		t.Fatal(err)
	}
	echo := bytes.TrimSuffix(payload, []byte("\r"))
	for name, input := range map[string][]byte{
		"echo-line-ending": append(append([]byte{}, echo...), 'x'),
		"start-marker":     append(append(append([]byte{}, echo...), '\n'), []byte("not-a-marker")...),
	} {
		t.Run(name, func(t *testing.T) {
			filter := newMcpCommandPresentationFilter("echo x", payload, capture.start, capture.endPrefix)
			if visible := filter.filter(input); len(visible) == 0 || !filter.complete {
				t.Fatalf("filter did not fail open: visible=%q complete=%v", visible, filter.complete)
			}
		})
	}
}

func TestMcpPresentationFilterHidesLargeWrapper(t *testing.T) {
	capture, _, err := newMcpCommandCapture("echo large")
	if err != nil {
		t.Fatal(err)
	}
	payload := append(bytes.Repeat([]byte{'x'}, mcpMaxCommandBytes+1024), '\r')
	filter := newMcpCommandPresentationFilter("echo large", payload, capture.start, capture.endPrefix)
	raw := append(bytes.TrimSuffix(payload, []byte("\r")), []byte("\r\n")...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nlarge\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)

	var visible []byte
	for start := 0; start < len(raw); start += sshOutputChunk {
		end := minInt(start+sshOutputChunk, len(raw))
		visible = append(visible, filter.filter(raw[start:end])...)
	}
	if string(visible) != "echo large\r\nlarge\r\n" || !filter.complete {
		t.Fatalf("large wrapper output = %q complete=%v", visible, filter.complete)
	}
}

func TestMcpPresentationFilterHidesMaximumWrapperByteByByte(t *testing.T) {
	capture, _, err := newMcpCommandCapture("echo large")
	if err != nil {
		t.Fatal(err)
	}
	payload := append(bytes.Repeat([]byte{'x'}, mcpMaxCommandBytes), '\r')
	filter := newMcpCommandPresentationFilter("echo large", payload, capture.start, capture.endPrefix)
	raw := append(bytes.TrimSuffix(payload, []byte("\r")), []byte("\r\n")...)
	raw = append(raw, capture.start...)
	raw = append(raw, []byte("\r\nlarge\r\n")...)
	raw = append(raw, capture.endPrefix...)
	raw = append(raw, []byte("0@@\r\n")...)

	var visible []byte
	for _, value := range raw {
		visible = append(visible, filter.filter([]byte{value})...)
	}
	if string(visible) != "echo large\r\nlarge\r\n" || !filter.complete {
		t.Fatalf("byte-wise maximum wrapper output = %q complete=%v", visible, filter.complete)
	}
}

func TestMcpEndMarkerSearchRetainsOnlyARealPrefixSuffix(t *testing.T) {
	filter := &mcpCommandPresentationFilter{endMarkerPrefix: []byte("@@END_")}
	for _, test := range []struct {
		pending string
		keep    int
	}{
		{"ordinary", 0},
		{"ordinary@@E", 3},
		{"ordinary@@END", 5},
		{"ordinary@@ENx", 0},
	} {
		filter.pending = []byte(test.pending)
		if actual := filter.longestPrefixSuffixLength(); actual != test.keep {
			t.Fatalf("suffix retained for %q = %d, want %d", test.pending, actual, test.keep)
		}
	}
	for _, pending := range []string{
		"@@END_", "@@END_x@@", "@@END_123", "@@END_123@", "@@END_123@x",
		"@@END_12345678901@@", "noise@@EN",
	} {
		filter.pending = []byte(pending)
		if search := filter.findEndMarker(); search.found {
			t.Fatalf("invalid marker %q was accepted: %#v", pending, search)
		}
	}
	filter.pending = []byte("noise@@END_255@@tail")
	if search := filter.findEndMarker(); !search.found || search.start != 5 {
		t.Fatalf("valid end marker search = %#v", search)
	}
}

func TestMcpReplayCaptureAndAnsiHelpersCoverInvalidBoundaries(t *testing.T) {
	if newMcpReplayBuffer(0).capacity != mcpReplayCapacity {
		t.Fatal("default replay capacity was not applied")
	}
	var nilBuffer *mcpReplayBuffer
	if nilBuffer.position() != 0 || nilBuffer.snapshotTail(10) != nil {
		t.Fatal("nil replay buffer returned data")
	}
	if data, position, notify, dropped := nilBuffer.since(7); data != nil || position != 7 || notify != nil || dropped {
		t.Fatalf("nil replay cursor = (%q, %d, %v, %v)", data, position, notify, dropped)
	}
	nilBuffer.append([]byte("ignored"))

	utf8Buffer := newMcpReplayBuffer(4)
	utf8Buffer.append([]byte("a€"))
	if tail := utf8Buffer.snapshotTail(2); len(tail) != 0 {
		t.Fatalf("UTF-8 continuation tail = %q", tail)
	}

	for _, command := range []string{"", strings.Repeat("x", mcpMaxCommandBytes+1)} {
		if _, _, err := newMcpCommandCapture(command); err == nil {
			t.Fatalf("invalid command length %d was accepted", len(command))
		}
	}
	for _, command := range []string{"echo\x00hidden", "echo\rnext", "echo\nnext", "echo\tnext", "echo\x1b[2J", "echo\x7f"} {
		if _, _, err := newMcpCommandCapture(command); err == nil {
			t.Fatalf("command with control bytes was accepted: %q", command)
		}
	}
	if _, _, err := newMcpCommandCapture("printf 'caffè'"); err != nil {
		t.Fatalf("Unicode command was rejected: %v", err)
	}
	capture := mcpCommandCapture{
		endPrefix: []byte("@@END_"), captured: make([]byte, mcpCommandCaptureBytes-1),
	}
	capture.push([]byte("overflow"))
	if !capture.truncated || len(capture.captured) != mcpCommandCaptureBytes {
		t.Fatalf("capture truncation = %v, bytes=%d", capture.truncated, len(capture.captured))
	}
	capture.completed = true
	capture.push([]byte("ignored"))

	for _, marker := range []string{"missing", "@@END_@@", "@@END_x@@", "@@END_256@@"} {
		if code, ok := parseMcpEndMarker([]byte(marker), []byte("@@END_")); ok || code != nil {
			t.Fatalf("invalid marker %q parsed as %v", marker, code)
		}
	}
	input := []byte("A\rB\r\n\x1b[31mC\x1b]title\aD\x1b]title\x1b\\E\x1bxF")
	if output := string(stripMcpAnsi(input)); output != "AB\nCDEF" {
		t.Fatalf("ANSI-stripped output = %q", output)
	}
}

func TestMcpRunCommandKeepsWrapperOutOfVisibleReplay(t *testing.T) {
	var output bytes.Buffer
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id:               "session",
		server:           &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}},
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		done:             make(chan struct{}),
	}
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		token := extractMcpPayloadToken(t, string(data))
		payloadEcho := strings.TrimSuffix(string(data), "\r")
		raw := "root@example:/home/user# " + payloadEcho + "\r\n" +
			"@@WHS_" + token + "@@\r\n" +
			"hello\r\n" +
			"@@WHE_" + token + "_0@@\r\n"
		native.publishTerminalData([]byte(raw))
		return len(data), nil
	}}

	result, err := native.runMcpCommand(context.Background(), "echo hello", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 || result.Output != "hello" {
		t.Fatalf("unexpected command result: %#v", result)
	}

	visible := string(native.mcpReplay.snapshotTail(4096))
	if strings.Contains(visible, "@@WHS_") ||
		strings.Contains(visible, "@@WHE_") ||
		strings.Contains(visible, "printf '@@WHS_%s@@") {
		t.Fatalf("wrapper leaked into visible replay: %q", visible)
	}
	if visible != "root@example:/home/user# echo hello\r\nhello\r\n" {
		t.Fatalf("unexpected visible replay: %q", visible)
	}

	raw := string(native.mcpCommandReplay.snapshotTail(4096))
	if !strings.Contains(raw, "@@WHS_") || !strings.Contains(raw, "@@WHE_") {
		t.Fatalf("raw command replay did not retain MCP markers: %q", raw)
	}
}

func TestMcpRunCommandTimeoutKeepsWrapperOutOfVisibleReplay(t *testing.T) {
	var output bytes.Buffer
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id:               "session",
		server:           &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}},
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		done:             make(chan struct{}),
	}
	writes := 0
	firstToken := ""
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		writes++
		token := extractMcpPayloadToken(t, string(data))
		payloadEcho := strings.TrimSuffix(string(data), "\r")
		if writes == 1 {
			firstToken = token
			native.publishTerminalData([]byte("root@example:/home/user# " + payloadEcho + "\r\n" +
				"@@WHS_" + token + "@@\r\npartial\r\n"))
			return len(data), nil
		}
		native.publishTerminalData([]byte(payloadEcho + "\r\n" +
			"@@WHS_" + token + "@@\r\nnext\r\n" +
			"@@WHE_" + token + "_0@@\r\n"))
		return len(data), nil
	}}

	result, err := native.runMcpCommand(context.Background(), "echo hello", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.Output != "partial" || result.ExitCode != nil {
		t.Fatalf("unexpected timeout result: %#v", result)
	}
	if _, err := native.runMcpCommand(context.Background(), "echo overlap", time.Second); !errors.Is(err, errMcpCommandInProgress) {
		t.Fatalf("overlapping command returned %v", err)
	}
	if writes != 1 {
		t.Fatalf("overlapping command wrote %d payloads", writes)
	}

	native.publishTerminalData([]byte("late\r\n@@WHE_" + firstToken + "_0@@\r\nroot@example:/home/user# "))
	visible := string(native.mcpReplay.snapshotTail(4096))
	if strings.Contains(visible, "@@WHS_") || strings.Contains(visible, "@@WHE_") ||
		strings.Contains(visible, "printf '@@WHS_%s@@") {
		t.Fatalf("late wrapper leaked into visible replay after timeout: %q", visible)
	}
	if visible != "root@example:/home/user# echo hello\r\npartial\r\nlate\r\nroot@example:/home/user# " {
		t.Fatalf("unexpected timeout replay: %q", visible)
	}

	next, err := native.runMcpCommand(context.Background(), "echo next", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if next.ExitCode == nil || *next.ExitCode != 0 || next.Output != "next" || next.TimedOut {
		t.Fatalf("unexpected follow-up result: %#v", next)
	}
}

func TestMcpRunCommandInterruptRetiresTimedOutPresentation(t *testing.T) {
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	interruptStarted := make(chan struct{})
	releaseInterrupt := make(chan struct{})
	native := &sshNativeSession{
		server:           &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(io.Discard)}},
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		inputQueue:       make(chan []byte, sshInputQueueCapacity),
		done:             make(chan struct{}),
	}
	defer native.close(false)
	defer func() {
		select {
		case <-releaseInterrupt:
		default:
			close(releaseInterrupt)
		}
	}()
	wrapperWrites := 0
	firstToken := ""
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		if bytes.Equal(data, []byte{'\x03'}) {
			close(interruptStarted)
			<-releaseInterrupt
			native.publishTerminalData([]byte("^C\r\nroot@example:/home/user# "))
			return len(data), nil
		}
		if bytes.Equal(data, []byte("still running")) {
			return len(data), nil
		}
		wrapperWrites++
		token := extractMcpPayloadToken(t, string(data))
		payloadEcho := strings.TrimSuffix(string(data), "\r")
		if wrapperWrites == 1 {
			firstToken = token
			native.publishTerminalData([]byte(payloadEcho + "\r\n" +
				"@@WHS_" + token + "@@\r\npartial\r\n"))
			return len(data), nil
		}
		native.publishTerminalData([]byte("late\r\n@@WHE_" + firstToken + "_130@@\r\n" +
			payloadEcho + "\r\n" +
			"@@WHS_" + token + "@@\r\nnext\r\n" +
			"@@WHE_" + token + "_0@@\r\n"))
		return len(data), nil
	}}
	native.startInputPump()

	result, err := native.runMcpCommand(context.Background(), "echo hello", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.Output != "partial" {
		t.Fatalf("unexpected timeout result: %#v", result)
	}
	if err := native.write([]byte("still running")); err != nil {
		t.Fatal(err)
	}
	if _, err := native.runMcpCommand(context.Background(), "echo overlap", time.Second); !errors.Is(err, errMcpCommandInProgress) {
		t.Fatalf("non-interrupting text cleared the timed-out presentation: %v", err)
	}
	if err := native.write([]byte{'\x03'}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-interruptStarted:
	case <-time.After(time.Second):
		t.Fatal("interrupt did not reach the SSH writer")
	}
	if _, err := native.runMcpCommand(context.Background(), "echo overlap", time.Second); !errors.Is(err, errMcpCommandInProgress) {
		t.Fatalf("queued interrupt cleared the timed-out presentation before it was written: %v", err)
	}
	close(releaseInterrupt)
	deadline := time.Now().Add(time.Second)
	for {
		native.terminalOutputMu.Lock()
		cleared := native.mcpPresentation == nil && len(native.mcpRetiredPresentations) == 1
		native.terminalOutputMu.Unlock()
		if cleared {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("written interrupt did not retire the timed-out presentation")
		}
		time.Sleep(time.Millisecond)
	}

	next, err := native.runMcpCommand(context.Background(), "echo next", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if next.ExitCode == nil || *next.ExitCode != 0 || next.Output != "next" || next.TimedOut {
		t.Fatalf("unexpected follow-up result: %#v", next)
	}
	native.terminalOutputMu.Lock()
	presentationCount := len(native.mcpRetiredPresentations)
	native.terminalOutputMu.Unlock()
	if presentationCount != 0 {
		t.Fatalf("late marker left %d retired presentations", presentationCount)
	}
	visible := string(native.mcpReplay.snapshotTail(4096))
	if strings.Contains(visible, "@@WHS_") || strings.Contains(visible, "@@WHE_") ||
		strings.Contains(visible, "printf '@@WHS_%s@@") {
		t.Fatalf("wrapper leaked into visible replay after interrupt: %q", visible)
	}
}

func TestMcpWrittenInterruptRetiresPresentationDespiteWriteError(t *testing.T) {
	writeErr := errors.New("partial write")
	native := &sshNativeSession{
		stdin: callbackWriteCloser{write: func([]byte) (int, error) {
			return 1, writeErr
		}},
		mcpPresentation: &mcpCommandPresentationFilter{abandoned: true},
	}

	if err := native.writeRemoteInput([]byte{'\x03', 'x'}); !errors.Is(err, writeErr) {
		t.Fatalf("partial write returned %v", err)
	}
	if native.mcpPresentation != nil || len(native.mcpRetiredPresentations) != 1 {
		t.Fatalf(
			"partial interrupt write left active = %t, retired = %d",
			native.mcpPresentation != nil,
			len(native.mcpRetiredPresentations),
		)
	}
}

func TestMcpWrittenInterruptEvictsOldestRetiredPresentationAtLimit(t *testing.T) {
	oldest := &mcpCommandPresentationFilter{retired: true}
	retired := make([]*mcpCommandPresentationFilter, mcpMaxRetiredPresentations)
	retired[0] = oldest
	for index := 1; index < len(retired); index++ {
		retired[index] = &mcpCommandPresentationFilter{retired: true}
	}
	current := &mcpCommandPresentationFilter{abandoned: true}
	native := &sshNativeSession{
		mcpPresentation:         current,
		mcpRetiredPresentations: retired,
	}

	native.retireAbandonedMcpCommandPresentationOnInterrupt([]byte{'\x03'})

	if native.mcpPresentation != nil || len(native.mcpRetiredPresentations) != mcpMaxRetiredPresentations {
		t.Fatalf(
			"capped retirement left active = %t, retired = %d",
			native.mcpPresentation != nil,
			len(native.mcpRetiredPresentations),
		)
	}
	if native.mcpRetiredPresentations[0] == oldest ||
		native.mcpRetiredPresentations[len(native.mcpRetiredPresentations)-1] != current ||
		!current.retired {
		t.Fatal("capped retirement did not evict the oldest filter and retain the current one")
	}
}

func TestMcpRunCommandReportsTruncatedWhenRawReplayDropsBytes(t *testing.T) {
	var output bytes.Buffer
	terminal, err := newSSHTerminalEmulator(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	native := &sshNativeSession{
		id:               "session",
		server:           &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}},
		terminal:         terminal,
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(128),
		done:             make(chan struct{}),
	}
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		token := extractMcpPayloadToken(t, string(data))
		payloadEcho := strings.TrimSuffix(string(data), "\r")
		raw := payloadEcho + "\r\n" +
			"@@WHS_" + token + "@@\r\n" +
			strings.Repeat("x", 256) + "\r\n" +
			"@@WHE_" + token + "_0@@\r\n"
		native.publishTerminalData([]byte(raw))
		return len(data), nil
	}}

	result, err := native.runMcpCommand(context.Background(), "printf x", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("unexpected command exit code: %#v", result.ExitCode)
	}
	if !result.Truncated {
		t.Fatalf("raw replay dropped bytes but result was not marked truncated: %#v", result)
	}
}

func TestMcpRunCommandDoesNotExecuteAfterQueuedContextCancellation(t *testing.T) {
	native := &sshNativeSession{
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		done:             make(chan struct{}),
	}
	writes := 0
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		writes++
		return len(data), nil
	}}
	if err := native.acquireMcpCommand(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer native.releaseMcpCommand()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := native.runMcpCommand(ctx, "echo should-not-run", time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued command returned %v", err)
	}
	if writes != 0 {
		t.Fatalf("cancelled queued command wrote %d payloads", writes)
	}
}

func extractMcpPayloadToken(t *testing.T, payload string) string {
	t.Helper()
	prefix := "printf '@@WHS_%s@@\\n' "
	start := strings.Index(payload, prefix)
	if start < 0 {
		t.Fatalf("MCP payload did not contain a start printf: %q", payload)
	}
	rest := payload[start+len(prefix):]
	end := strings.Index(rest, ";")
	if end <= 0 {
		t.Fatalf("MCP payload token was not delimited: %q", payload)
	}
	token := strings.TrimSpace(rest[:end])
	if token == "" {
		t.Fatalf("MCP payload token was empty: %q", payload)
	}
	return token
}

func waitForMcpApprovalRequest(t *testing.T, controller *mcpController) string {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		controller.approvalMu.Lock()
		var requestID string
		for id := range controller.pending {
			requestID = id
			break
		}
		controller.approvalMu.Unlock()
		if requestID != "" {
			return requestID
		}

		select {
		case <-deadline:
			t.Fatal("approval request was not created")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func waitForMcpApprovalWaiterCount(t *testing.T, controller *mcpController, expected int) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		controller.approvalMu.Lock()
		matched := false
		for _, waiter := range controller.pending {
			matched = waiter.waiters == expected
			break
		}
		controller.approvalMu.Unlock()
		if matched {
			return
		}

		select {
		case <-deadline:
			t.Fatalf("approval waiter count did not reach %d", expected)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestMcpApprovalWaiterBroadcastsToConcurrentCallers(t *testing.T) {
	server := &sshServer{}
	server.output = &sshEventWriter{encoder: json.NewEncoder(&bytes.Buffer{})}
	controller := newMcpController(server)
	controller.setLocked(false)
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- controller.ensureApproval(ctx, native, "read_terminal") }()
	}

	deadline := time.After(time.Second)
	requestID := waitForMcpApprovalRequest(t, controller)
	if err := controller.resolveApproval(requestID, true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("approval waiter failed: %v", err)
			}
		case <-deadline:
			t.Fatal("concurrent approval waiter did not complete")
		}
	}
}

func TestMcpApprovalCancellationReportsLockReason(t *testing.T) {
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&bytes.Buffer{})}}
	controller := newMcpController(server)
	controller.setLocked(false)
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- controller.ensureApproval(ctx, native, "read_terminal") }()

	waitForMcpApprovalRequest(t, controller)
	controller.setLocked(true)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "Wormhole is locked") {
			t.Fatalf("expected lock reason, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval waiter did not complete after lock")
	}
}

func TestMcpApprovalCancellationReportsSessionClosed(t *testing.T) {
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&bytes.Buffer{})}}
	controller := newMcpController(server)
	controller.setLocked(false)
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- controller.ensureApproval(ctx, native, "read_terminal") }()

	waitForMcpApprovalRequest(t, controller)
	controller.forgetSession(native.id)
	select {
	case err := <-result:
		if !errors.Is(err, errSSHSessionClosed) {
			t.Fatalf("expected session-closed error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval waiter did not complete after session close")
	}
}

func TestMcpCancelledConcurrentApprovalWaiterIsReleased(t *testing.T) {
	server := &sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&bytes.Buffer{})}}
	controller := newMcpController(server)
	controller.setLocked(false)
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderResult := make(chan error, 1)
	go func() { leaderResult <- controller.ensureApproval(leaderContext, native, "read_terminal") }()
	waitForMcpApprovalRequest(t, controller)

	followerContext, cancelFollower := context.WithCancel(context.Background())
	followerResult := make(chan error, 1)
	go func() { followerResult <- controller.ensureApproval(followerContext, native, "read_terminal") }()
	waitForMcpApprovalWaiterCount(t, controller, 2)
	cancelFollower()
	if err := <-followerResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled follower returned %v", err)
	}

	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled leader returned %v", err)
	}
	controller.approvalMu.Lock()
	pendingCount := len(controller.pending)
	targetCount := len(controller.pendingByTarget)
	controller.approvalMu.Unlock()
	if pendingCount != 0 || targetCount != 0 {
		t.Fatalf("cancelled waiters left stale approval state: pending=%d targets=%d", pendingCount, targetCount)
	}
}

func TestMcpCommandValidation(t *testing.T) {
	if _, _, err := newMcpCommandCapture(strings.Repeat("x", mcpMaxCommandBytes+1)); err == nil {
		t.Fatal("oversized command was accepted")
	}
	if _, _, err := newMcpCommandCapture(""); err == nil {
		t.Fatal("empty command was accepted")
	}
}

func TestMcpCommandTimeoutValidationRejectsOverflowingInput(t *testing.T) {
	for _, timeoutSeconds := range []int{0, -1, int(mcpMaxCommandTimeout / time.Second)} {
		timeout, err := mcpCommandTimeout(timeoutSeconds)
		if err != nil {
			t.Fatalf("timeout %d was rejected: %v", timeoutSeconds, err)
		}
		if timeoutSeconds <= 0 && timeout != mcpDefaultCommandTimeout {
			t.Fatalf("timeout %d used %s instead of the default", timeoutSeconds, timeout)
		}
	}

	maxInt := int(^uint(0) >> 1)
	if _, err := mcpCommandTimeout(maxInt); err == nil {
		t.Fatal("overflowing timeoutSeconds was accepted")
	}
}

func TestMcpServerRegistersTypedToolSurface(t *testing.T) {
	server := &sshServer{}
	server.output = &sshEventWriter{encoder: json.NewEncoder(&bytes.Buffer{})}
	controller := newMcpController(server)
	if newMcpServer(controller) == nil {
		t.Fatal("MCP server was not created")
	}
}

func TestMcpBearerMiddlewareRejectsAndAcceptsRequests(t *testing.T) {
	controller := newMcpController(&sshServer{})
	controller.token = "secret-token"
	handler := mcpBearerMiddleware(controller, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized request, got %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil)
	request.Header.Set("Authorization", "Bearer secret-token")
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("expected authorized request, got %d", authorized.Code)
	}
}

func TestMcpControllerLifecycleServesBearerProtectedLoopbackEndpoint(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	var output bytes.Buffer
	ssh := &sshServer{
		databasePath: databasePath,
		output:       &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:     make(map[string]*sshNativeSession),
	}
	controller := newMcpController(ssh)
	ssh.mcp = controller
	port := reserveMcpTestPort(t)

	initial, err := controller.status()
	if err != nil || initial.Running || initial.Port != McpDefaultPort {
		t.Fatalf("initial status = %#v, %v", initial, err)
	}
	configured, err := controller.setPort(port)
	if err != nil || configured.Port != port || configured.Running {
		t.Fatalf("configured status = %#v, %v", configured, err)
	}
	if err := controller.start(port, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.stop(false) })
	if err := controller.start(port, true); err != nil {
		t.Fatalf("idempotent start failed: %v", err)
	}
	if err := controller.start(reserveMcpTestPort(t), false); err == nil {
		t.Fatal("running MCP server changed ports")
	}
	if _, err := controller.setPort(reserveMcpTestPort(t)); err == nil {
		t.Fatal("running MCP server accepted a port change")
	}

	status, err := controller.status()
	if err != nil || !status.Enabled || !status.Running || status.Endpoint != mcpEndpointURL(port) {
		t.Fatalf("running status = %#v, %v", status, err)
	}
	token := controller.currentToken()
	if token == "" {
		t.Fatal("MCP start did not provision a token")
	}

	unauthorized, err := http.Get(status.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}
	request, err := http.NewRequest(http.MethodGet, status.Endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	authorized, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, authorized.Body)
	_ = authorized.Body.Close()
	if authorized.StatusCode == http.StatusUnauthorized {
		t.Fatal("valid MCP bearer token was rejected")
	}

	regenerated, err := controller.regenerateToken()
	if err != nil || regenerated == "" || regenerated == token || controller.currentToken() != regenerated {
		t.Fatalf(
			"regeneration error = %v, token present = %t, changed = %t, live = %t",
			err,
			regenerated != "",
			regenerated != token,
			controller.currentToken() == regenerated,
		)
	}
	if err := controller.stop(true); err != nil {
		t.Fatal(err)
	}
	if err := controller.stop(false); err != nil {
		t.Fatalf("idempotent stop failed: %v", err)
	}
	stopped, err := controller.status()
	if err != nil || stopped.Enabled || stopped.Running || stopped.Port != port {
		t.Fatalf("stopped status = %#v, %v", stopped, err)
	}
}

func TestMcpControllerListsAndResolvesLiveSessions(t *testing.T) {
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(io.Discard)},
		sessions: make(map[string]*sshNativeSession),
	}
	controller := newMcpController(server)
	if _, err := controller.listSessions(); err == nil {
		t.Fatal("locked MCP controller exposed sessions")
	}
	controller.setLocked(false)
	server.sessions["two"] = &sshNativeSession{id: "two", mcpSession: mcpSessionInfo{ID: "two", Host: "two.example"}}
	server.sessions["one"] = &sshNativeSession{id: "one", mcpSession: mcpSessionInfo{ID: "one", Host: "one.example"}}
	closed := &sshNativeSession{id: "closed", mcpSession: mcpSessionInfo{ID: "closed"}, closed: true}
	server.sessions["closed"] = closed

	sessions, err := controller.listSessions()
	if err != nil || len(sessions) != 2 || sessions[0].ID != "one" || sessions[1].ID != "two" {
		t.Fatalf("sessions = %#v, %v", sessions, err)
	}
	resolved, err := controller.resolveSession("one")
	if err != nil || resolved != server.sessions["one"] {
		t.Fatalf("resolved = %#v, %v", resolved, err)
	}
	for _, sessionID := range []string{"", " spaced ", strings.Repeat("x", 129), "missing", "closed"} {
		if _, err := controller.resolveSession(sessionID); err == nil {
			t.Fatalf("invalid session %q was resolved", sessionID)
		}
	}
}

func TestHandleMcpDispatchesControllerOperations(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	var output bytes.Buffer
	server := &sshServer{
		databasePath: databasePath,
		output:       &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions:     make(map[string]*sshNativeSession),
	}
	server.handleMcp(sshWireCommand{Type: "mcp.status", RequestID: ""})
	server.handleMcp(sshWireCommand{Type: "mcp.status", RequestID: "no-controller"})
	server.mcp = newMcpController(server)
	port := reserveMcpTestPort(t)
	commands := []sshWireCommand{
		{Type: "mcp.status", RequestID: "status"},
		{Type: "mcp.set-port", RequestID: "set-port", Port: port},
		{Type: "mcp.get-token", RequestID: "get-token"},
		{Type: "mcp.regenerate-token", RequestID: "regenerate-token"},
		{Type: "mcp.unlock", RequestID: "unlock"},
		{Type: "mcp.lock", RequestID: "lock"},
		{Type: "mcp.approve", RequestID: "approve-missing", ApprovalID: "missing", Approved: true},
		{Type: "mcp.unsupported", RequestID: "unsupported"},
		{Type: "mcp.start", RequestID: "start", Port: port},
		{Type: "mcp.stop", RequestID: "stop"},
	}
	for _, command := range commands {
		server.handleMcp(command)
	}
	t.Cleanup(func() { _ = server.mcp.stop(false) })

	decoder := json.NewDecoder(&output)
	var events []sshWireEvent
	for decoder.More() {
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != len(commands)+2 {
		t.Fatalf("MCP events = %d, want %d", len(events), len(commands)+2)
	}
	byID := make(map[string]sshWireEvent, len(events))
	for _, event := range events {
		byID[event.RequestID] = event
	}
	for _, id := range []string{"status", "set-port", "get-token", "regenerate-token", "unlock", "lock", "start", "stop"} {
		if byID[id].Error != "" {
			t.Fatalf("MCP command %s failed: %#v", id, byID[id])
		}
	}
	for _, id := range []string{"", "no-controller", "approve-missing", "unsupported"} {
		if byID[id].Error == "" {
			t.Fatalf("MCP command %q did not report an error", id)
		}
	}
}

func reserveMcpTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
