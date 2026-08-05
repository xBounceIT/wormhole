package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func (writer callbackWriteCloser) Write(data []byte) (int, error) {
	if writer.write == nil {
		return len(data), nil
	}
	return writer.write(data)
}

func (writer callbackWriteCloser) Close() error { return nil }

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

func TestMcpPresentationFilterFailsOpenOnMismatch(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
	input := []byte("regular terminal output\r\n")
	if visible := filter.filter(input); string(visible) != string(input) {
		t.Fatalf("presentation filter did not fail open: %q", visible)
	}
	if !filter.complete {
		t.Fatal("presentation filter remained active after a mismatch")
	}
}

func TestMcpPresentationFilterDrainPendingFailsOpen(t *testing.T) {
	capture, payload, err := newMcpCommandCapture("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	filter := newMcpCommandPresentationFilter("echo hello", payload, capture.start, capture.endPrefix)
	partial := payload[:minInt(8, len(payload))]
	if visible := filter.filter(partial); len(visible) != 0 {
		t.Fatalf("partial echo was released too early: %q", visible)
	}
	if drained := filter.drainPending(); !bytes.Equal(drained, partial) {
		t.Fatalf("pending bytes were not released on cleanup: %q", drained)
	}
	if !filter.complete {
		t.Fatal("presentation filter did not complete after drain")
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
		raw := payloadEcho + "\r\n" +
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
	if visible != "echo hello\r\nhello\r\n" {
		t.Fatalf("unexpected visible replay: %q", visible)
	}

	raw := string(native.mcpCommandReplay.snapshotTail(4096))
	if !strings.Contains(raw, "@@WHS_") || !strings.Contains(raw, "@@WHE_") {
		t.Fatalf("raw command replay did not retain MCP markers: %q", raw)
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
