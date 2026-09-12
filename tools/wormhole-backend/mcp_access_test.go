package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMcpRevocationRequiresNewApprovalForEachSessionTool(t *testing.T) {
	for _, tool := range []string{"run_command", "send_text", "read_terminal"} {
		t.Run(tool, func(t *testing.T) {
			var output bytes.Buffer
			native := &sshNativeSession{id: "session", done: make(chan struct{}), mcpReplay: newMcpReplayBuffer(mcpReplayCapacity)}
			server := &sshServer{
				output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
				sessions: map[string]*sshNativeSession{"session": native},
			}
			controller := newMcpController(server)
			server.mcp = controller
			controller.locked = false
			controller.accessRunning = true
			controller.decisions["session"] = true
			controller.decisions["other"] = true
			server.handle(sshWireCommand{Type: "mcp.revoke-session", RequestID: "revoke", SessionID: "session"})
			decoder := json.NewDecoder(&output)
			var access, response sshWireEvent
			if err := decoder.Decode(&access); err != nil {
				t.Fatal(err)
			}
			if err := decoder.Decode(&response); err != nil {
				t.Fatal(err)
			}
			if access.Type != "mcp.access" || access.SessionID != "session" || access.McpAccessible == nil || *access.McpAccessible {
				t.Fatalf("revoked access = %#v", access)
			}
			if response.Type != "mcp.response" || response.RequestID != "revoke" || response.Error != "" {
				t.Fatalf("revocation response = %#v", response)
			}
			if !controller.decisions["other"] || native.isClosed() || server.sessions["session"] != native {
				t.Fatal("revocation affected another grant or the SSH connection")
			}
			output.Reset()
			controller.setLocked(true)
			controller.setLocked(false)
			controller.setAccessRunning(false)
			controller.setAccessRunning(true)
			if _, exists := controller.decisions["session"]; exists {
				t.Fatal("lock or restart restored the revoked decision")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := newMcpServer(controller).Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer serverSession.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			clientSession, err := client.Connect(ctx, clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clientSession.Close()
			done := make(chan error, 1)
			arguments := map[string]any{"sessionId": "session"}
			switch tool {
			case "run_command":
				arguments["command"] = "echo example"
				arguments["timeoutSeconds"] = float64(9)
			case "send_text":
				arguments["text"] = "echo example\r"
			case "read_terminal":
				arguments["maxBytes"] = float64(256)
			}
			go func() {
				result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
				if err == nil && !result.IsError {
					err = errors.New("tool ran without renewed consent")
				}
				done <- err
			}()
			requestID := waitForMcpApprovalRequest(t, controller)
			server.output.mu.Lock()
			wire := append([]byte(nil), output.Bytes()...)
			server.output.mu.Unlock()
			decoder = json.NewDecoder(bytes.NewReader(wire))
			var approval sshWireEvent
			for approval.Type != "mcp.approval" || approval.RequestID != requestID {
				if err := decoder.Decode(&approval); err != nil {
					t.Fatal(err)
				}
			}
			if approval.Tool != tool || approval.ExecutionPreview == nil {
				t.Fatalf("renewed approval is missing execution details: %#v", approval)
			}
			var previewArguments map[string]any
			if err := json.Unmarshal([]byte(approval.ExecutionPreview.Content), &previewArguments); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(previewArguments, arguments) {
				t.Fatalf("renewed approval arguments = %#v, want %#v", previewArguments, arguments)
			}
			select {
			case err := <-done:
				t.Fatalf("tool completed before approval: %v", err)
			default:
			}
			if err := controller.resolveApproval(requestID, false); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}

			// A subsequent explicit grant restores access to the same live terminal.
			if err := controller.revokeSessionAccess("session"); err != nil {
				t.Fatal(err)
			}
			go func() {
				done <- controller.ensureApproval(ctx, native, "read_terminal", mcpExecutionArguments{SessionID: native.id, MaxBytes: mcpDefaultReadBytes})
			}()
			requestID = waitForMcpApprovalRequest(t, controller)
			if err := controller.resolveApproval(requestID, true); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
				Name: "read_terminal", Arguments: map[string]any{"sessionId": "session"},
			})
			if err != nil || result.IsError {
				t.Fatalf("renewed grant failed: %v, %#v", err, result)
			}
		})
	}
}

func TestMcpRevocationValidatesTargetAndCancelsStaleApprovals(t *testing.T) {
	var output bytes.Buffer
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	server := &sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: map[string]*sshNativeSession{"session": native, "closed": {id: "closed", closed: true}},
	}
	controller := newMcpController(server)
	server.mcp = controller
	controller.decisions["session"] = true
	if err := controller.revokeSessionAccess("session"); err == nil || !controller.decisions["session"] {
		t.Fatalf("locked revocation changed the grant: %v", err)
	}
	controller.locked = false
	for _, id := range []string{"", " session", "session ", strings.Repeat("x", 129), "missing", "closed"} {
		server.handle(sshWireCommand{Type: "mcp.revoke-session", RequestID: "invalid", SessionID: id})
		var event sshWireEvent
		if err := json.NewDecoder(&output).Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "mcp.response" || event.Error == "" || !controller.decisions["session"] {
			t.Fatalf("invalid target %q: %#v", id, event)
		}
		output.Reset()
	}
	toolContext, finish := controller.trackSessionTool(context.Background(), "session")
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(toolContext.Err(), context.Canceled) {
		t.Fatal("revocation did not cancel an admitted tool")
	}
	output.Reset()
	finish()
	var access sshWireEvent
	if err := json.NewDecoder(&output).Decode(&access); err != nil {
		t.Fatal(err)
	}
	if access.McpAccessible == nil || *access.McpAccessible {
		t.Fatal("late completion restored access")
	}
	output.Reset()
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("repeated revocation emitted a new grant")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- controller.ensureApproval(ctx, native, "read_terminal", mcpExecutionArguments{SessionID: native.id, MaxBytes: mcpDefaultReadBytes})
	}()
	requestID := waitForMcpApprovalRequest(t, controller)
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "disconnected AI-agent control") {
		t.Fatalf("cancelled approval returned %v", err)
	}
	if err := controller.resolveApproval(requestID, true); err == nil {
		t.Fatal("a stale approval restored revoked access")
	}
	if len(controller.pending) != 0 || len(controller.pendingByTarget) != 0 || native.isClosed() {
		t.Fatal("revocation left pending permissions or closed SSH")
	}
	requireMcpApprovalCancellationSequence(t, &output, requestID, "session")
}

func TestMcpRevocationPreventsQueuedCommandExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writes := make(chan struct{}, 1)
	native := &sshNativeSession{
		id: "session", done: make(chan struct{}),
		mcpReplay:        newMcpReplayBuffer(mcpReplayCapacity),
		mcpCommandReplay: newMcpReplayBuffer(mcpReplayCapacity),
		stdin: callbackWriteCloser{write: func([]byte) (int, error) {
			writes <- struct{}{}
			return 0, errors.New("unexpected remote write")
		}},
	}
	if err := native.acquireMcpCommand(ctx); err != nil {
		t.Fatal(err)
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			native.releaseMcpCommand()
		}
	}()
	controller := newMcpController(&sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(io.Discard)},
		sessions: map[string]*sshNativeSession{"session": native},
	})
	controller.locked = false
	controller.accessRunning = true
	controller.decisions["session"] = true
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := newMcpServer(controller).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	done := make(chan error, 1)
	go func() {
		result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
			Name: "run_command", Arguments: map[string]any{"sessionId": "session", "command": "echo queued"},
		})
		if err == nil && !result.IsError {
			err = errors.New("revoked tool completed successfully")
		}
		done <- err
	}()
	for {
		controller.approvalMu.Lock()
		active := len(controller.activeTools["session"]) > 0
		controller.approvalMu.Unlock()
		if active {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("command did not reach the occupied execution gate")
		case <-time.After(time.Millisecond):
		}
	}
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	// Let the next queued command contend for the gate after consent was revoked.
	native.releaseMcpCommand()
	gateHeld = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("revoked queued command did not finish")
	}
	select {
	case <-writes:
		t.Fatal("a queued command executed after AI-agent access was revoked")
	default:
	}
	if native.isClosed() {
		t.Fatal("revoking queued work closed the user's SSH session")
	}
	controller.approvalMu.Lock()
	remaining := len(controller.activeTools)
	controller.approvalMu.Unlock()
	if remaining != 0 {
		t.Fatal("revoked command retained its access registration")
	}
}

func TestMcpRevocationIsolatesOtherSessionsAndRenewedAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	native := &sshNativeSession{id: "session", done: make(chan struct{})}
	controller := newMcpController(&sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(io.Discard)},
		sessions: map[string]*sshNativeSession{"session": native},
	})
	controller.locked = false
	controller.accessRunning = true
	controller.decisions["session"] = true
	controller.decisions["other"] = true
	firstContext, firstRelease := controller.trackSessionTool(ctx, "session")
	secondContext, secondRelease := controller.trackSessionTool(ctx, "session")
	otherContext, otherRelease := controller.trackSessionTool(ctx, "other")
	defer firstRelease()
	defer secondRelease()
	defer otherRelease()
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	if firstContext.Err() != context.Canceled || secondContext.Err() != context.Canceled {
		t.Fatal("revocation did not cancel every request for the selected session")
	}
	if otherContext.Err() != nil || !controller.decisions["other"] {
		t.Fatal("revocation affected another session")
	}
	type authorization struct {
		ctx     context.Context
		release func()
		err     error
	}
	done := make(chan authorization, 1)
	go func() {
		requestContext, release, err := controller.authorizeSessionTool(ctx, native, "read_terminal", mcpExecutionArguments{SessionID: native.id, MaxBytes: mcpDefaultReadBytes})
		done <- authorization{requestContext, release, err}
	}()
	requestID := waitForMcpApprovalRequest(t, controller)
	if err := controller.resolveApproval(requestID, true); err != nil {
		t.Fatal(err)
	}
	var renewed authorization
	select {
	case renewed = <-done:
	case <-ctx.Done():
		t.Fatal("renewed authorization did not finish")
	}
	if renewed.err != nil {
		t.Fatal(renewed.err)
	}
	defer renewed.release()
	firstRelease()
	secondRelease()
	if renewed.ctx.Err() != nil || len(controller.activeTools["session"]) != 1 {
		t.Fatal("old request cleanup invalidated renewed access")
	}
	if err := controller.revokeSessionAccess("session"); err != nil {
		t.Fatal(err)
	}
	if renewed.ctx.Err() != context.Canceled || otherContext.Err() != nil {
		t.Fatal("a later revocation did not target only renewed session access")
	}
	renewed.release()
	otherRelease()
	if len(controller.activeTools) != 0 {
		t.Fatal("finished request registrations leaked")
	}

	cancelled, cancelRequest := context.WithCancel(ctx)
	cancelRequest()
	if _, release, err := controller.authorizeSessionTool(cancelled, native, "read_terminal", mcpExecutionArguments{SessionID: native.id, MaxBytes: mcpDefaultReadBytes}); !errors.Is(err, context.Canceled) || release != nil {
		t.Fatalf("cancelled authorization = %v, release present = %v", err, release != nil)
	}
	if len(controller.pending) != 0 || len(controller.pendingByTarget) != 0 || len(controller.activeTools) != 0 {
		t.Fatal("cancelled authorization left an approval prompt or tool registration")
	}
}

func TestMcpRevocationRacingApprovalCannotRestoreAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, order := range []string{"approve-first", "revoke-first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			native := &sshNativeSession{id: "session", done: make(chan struct{})}
			controller := newMcpController(&sshServer{
				output:   &sshEventWriter{encoder: json.NewEncoder(io.Discard)},
				sessions: map[string]*sshNativeSession{"session": native},
			})
			controller.locked = false
			controller.accessRunning = true
			type authorization struct {
				ctx     context.Context
				release func()
				err     error
			}
			authorized := make(chan authorization, 1)
			go func() {
				requestContext, release, err := controller.authorizeSessionTool(ctx, native, "read_terminal", mcpExecutionArguments{SessionID: native.id, MaxBytes: mcpDefaultReadBytes})
				authorized <- authorization{requestContext, release, err}
			}()
			requestID := waitForMcpApprovalRequest(t, controller)
			approved := make(chan error, 1)
			if order == "approve-first" {
				approved <- controller.resolveApproval(requestID, true)
			} else if order == "concurrent" {
				go func() { approved <- controller.resolveApproval(requestID, true) }()
			}
			if err := controller.revokeSessionAccess("session"); err != nil {
				t.Fatal(err)
			}
			if order == "revoke-first" {
				approved <- controller.resolveApproval(requestID, true)
			}
			if err := <-approved; err != nil && !strings.Contains(err.Error(), "no longer pending") {
				t.Fatalf("concurrent approval: %v", err)
			}
			var result authorization
			select {
			case result = <-authorized:
			case <-ctx.Done():
				t.Fatal("revoked authorization did not finish")
			}
			if result.err == nil {
				if result.ctx.Err() != context.Canceled {
					t.Fatal("old approval retained live access after revocation")
				}
				result.release()
			} else if !errors.Is(result.err, context.Canceled) && !strings.Contains(result.err.Error(), "disconnected AI-agent control") {
				t.Fatalf("revoked authorization: %v", result.err)
			}
			if len(controller.decisions) != 0 || len(controller.pending) != 0 || len(controller.activeTools) != 0 {
				t.Fatal("approval race left access or request registrations behind")
			}
		})
	}
}

func TestMcpAccessTracksApprovalAndAvailability(t *testing.T) {
	installMcpTestSecretStore(t)
	var output bytes.Buffer
	controller := newMcpController(&sshServer{
		databasePath: filepath.Join(t.TempDir(), "wormhole.db"),
		output:       &sshEventWriter{encoder: json.NewEncoder(&output)},
	})
	t.Cleanup(func() { _ = controller.stop(false) })
	controller.setLocked(false)
	if err := controller.start(reserveMcpTestPort(t), false); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("unapproved sessions must not publish access")
	}

	check := func(want bool) {
		t.Helper()
		var event sshWireEvent
		decoder := json.NewDecoder(&output)
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "mcp.access" || event.SessionID != "approved" || event.McpAccessible == nil || *event.McpAccessible != want {
			t.Fatalf("access event = %#v, want %v", event, want)
		}
		if err := decoder.Decode(&event); err != io.EOF {
			t.Fatalf("unexpected extra access event: %#v, %v", event, err)
		}
		output.Reset()
	}
	controller.pending["request"] = &mcpApprovalWaiter{
		requestID: "request", sessionID: "approved", rememberDecision: true, done: make(chan struct{}),
	}
	if err := controller.resolveApproval("request", true); err != nil {
		t.Fatal(err)
	}
	check(true)
	controller.decisions["denied"] = false
	controller.setLocked(true)
	check(false)
	controller.setLocked(false)
	check(true)
	if err := controller.stop(false); err != nil {
		t.Fatal(err)
	}
	check(false)
	controller.setLocked(true)
	check(false)
	controller.setLocked(false)
	check(false) // Unlocking while stopped must not make a retained grant accessible.
	if err := controller.start(reserveMcpTestPort(t), false); err != nil {
		t.Fatal(err)
	}
	check(true)
	controller.forgetSession("approved")
	check(false)
	controller.forgetSession("denied")
	controller.forgetSession("missing")
	controller.setLocked(true)
	controller.setLocked(false)
	if output.Len() != 0 {
		t.Fatal("forgotten sessions regained access")
	}
}

func TestMcpAccessRemainsVisibleWhileAnAdmittedToolDrains(t *testing.T) {
	for _, tool := range []string{"send_text", "run_command"} {
		t.Run(tool, func(t *testing.T) { testMcpAccessToolDrain(t, tool) })
	}
}

func testMcpAccessToolDrain(t *testing.T, tool string) {
	t.Helper()
	var output bytes.Buffer
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	native := &sshNativeSession{id: "session", stdin: callbackWriteCloser{write: func(data []byte) (int, error) {
		close(started)
		<-release
		if tool == "run_command" {
			return 0, errors.New("test remote write failed")
		}
		return len(data), nil
	}}}
	native.mcpReplay = newMcpReplayBuffer(mcpReplayCapacity)
	native.mcpCommandReplay = newMcpReplayBuffer(mcpReplayCapacity)
	controller := newMcpController(&sshServer{
		output:   &sshEventWriter{encoder: json.NewEncoder(&output)},
		sessions: map[string]*sshNativeSession{"session": native},
	})
	controller.locked = false
	controller.accessRunning = true
	controller.decisions["session"] = true
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := newMcpServer(controller).Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	done := make(chan error, 1)
	go func() {
		arguments := map[string]any{"sessionId": "session"}
		if tool == "send_text" {
			arguments["text"] = "echo example\r"
		} else {
			arguments["command"] = "echo example"
		}
		result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
			Name: tool, Arguments: arguments,
		})
		if err == nil && result.IsError != (tool == "run_command") {
			err = errors.New("unexpected tool outcome")
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("tool did not start")
	}
	if err := controller.stop(false); err != nil {
		t.Fatal(err)
	}
	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || !*event.McpAccessible {
		t.Fatal("stopping MCP hid a tool that still has access to the live terminal")
	}
	output.Reset()
	release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tool did not finish")
	}
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || *event.McpAccessible {
		t.Fatal("completed tool retained access while MCP was stopped")
	}
}

func TestMcpAccessTracksOverlappingRequestsAndSessionClosure(t *testing.T) {
	var output bytes.Buffer
	controller := newMcpController(&sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}})
	controller.locked = false
	controller.accessRunning = true
	controller.decisions["session"] = true
	_, first := controller.trackSessionTool(context.Background(), "session")
	_, second := controller.trackSessionTool(context.Background(), "session")
	if output.Len() != 0 {
		t.Fatal("tools changed an already visible grant")
	}
	if err := controller.stop(false); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	first()
	if output.Len() != 0 {
		t.Fatal("finishing one request hid a concurrent request")
	}
	controller.forgetSession("session")
	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || *event.McpAccessible {
		t.Fatal("closed session retained access")
	}
	output.Reset()
	second()
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || *event.McpAccessible {
		t.Fatal("late completion restored closed-session access")
	}
	if len(controller.activeTools) != 0 {
		t.Fatal("completed tool counters leaked")
	}

	controller.decisions["session"] = true
	_, finish := controller.trackSessionTool(context.Background(), "session") // Admitted immediately before stop, resumed afterward.
	output.Reset()
	controller.setLocked(true)
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || *event.McpAccessible {
		t.Fatal("locked session retained access")
	}
	finish()
}

func TestMcpAccessDoesNotGrantForDenialOrOpenApproval(t *testing.T) {
	for _, scenario := range []struct {
		name                       string
		approved, remember, locked bool
		event                      bool
	}{
		{name: "denied", remember: true, event: true},
		{name: "open", approved: true},
		{name: "locked", approved: true, remember: true, locked: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var output bytes.Buffer
			controller := newMcpController(&sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}})
			controller.locked = scenario.locked
			controller.accessRunning = true
			controller.pending["request"] = &mcpApprovalWaiter{sessionID: "session", rememberDecision: scenario.remember, done: make(chan struct{})}
			if err := controller.resolveApproval("request", scenario.approved); err != nil {
				t.Fatal(err)
			}
			if !scenario.event {
				if output.Len() != 0 {
					t.Fatal("non-session approval published access")
				}
				return
			}
			var event sshWireEvent
			if err := json.NewDecoder(&output).Decode(&event); err != nil {
				t.Fatal(err)
			}
			if event.McpAccessible == nil || *event.McpAccessible {
				t.Fatalf("denied access = %#v", event)
			}
		})
	}
	// Metadata emission is also safe in headless test/backend configurations.
	controller := newMcpController(nil)
	controller.decisions["session"] = true
	controller.setAccessRunning(true)
	controller.server = &sshServer{}
	controller.setLocked(false)
}

func TestMcpAccessClearsOnUnexpectedServerExit(t *testing.T) {
	var output bytes.Buffer
	controller := newMcpController(&sshServer{output: &sshEventWriter{encoder: json.NewEncoder(&output)}})
	controller.locked = false
	controller.accessRunning = true
	controller.decisions["session"] = true
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{}
	controller.httpServer = server
	controller.serve(server, listener)
	var event sshWireEvent
	if err := json.NewDecoder(&output).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.McpAccessible == nil || *event.McpAccessible {
		t.Fatalf("stopped access = %#v", event)
	}
}
