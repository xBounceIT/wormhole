package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newMcpApprovalTestController(t *testing.T) (*mcpController, *sshNativeSession, *synchronizedBuffer) {
	t.Helper()
	output := &synchronizedBuffer{}
	server := &sshServer{
		databasePath: createMcpConnectionTestDatabase(t),
		output:       &sshEventWriter{encoder: json.NewEncoder(output)},
		sessions:     make(map[string]*sshNativeSession),
	}
	controller := newMcpController(server)
	server.mcp = controller
	controller.setLocked(false)
	native := &sshNativeSession{
		id: "session", done: make(chan struct{}),
		mcpSession: mcpSessionInfo{ID: "session", Host: "host.example", Port: 22, Username: "user", Title: "Shell", Status: "connected"},
		mcpReplay:  newMcpReplayBuffer(4096), mcpCommandReplay: newMcpReplayBuffer(4096),
	}
	native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
		if strings.Contains(string(data), "@@WHS_") {
			token := extractMcpPayloadToken(t, string(data))
			native.mcpCommandReplay.append([]byte("@@WHS_" + token + "@@\r\nhello\r\n@@WHE_" + token + "_0@@\r\n"))
		}
		return len(data), nil
	}}
	server.sessions[native.id] = native
	controller.sessionConnected(native)
	t.Cleanup(func() { controller.cancelPending("test finished") })
	return controller, native, output
}

func mcpApprovalEvents(t *testing.T, output *synchronizedBuffer) []sshWireEvent {
	t.Helper()
	var events []sshWireEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for decoder.More() {
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "mcp.approval" {
			events = append(events, event)
		}
	}
	return events
}

func TestMcpApprovalModesApplyToEveryTool(t *testing.T) {
	for _, mode := range []mcpApprovalMode{mcpApprovalFullAccess, mcpApprovalAlwaysAsk, mcpApprovalOnFirstAccess} {
		t.Run(string(mode), func(t *testing.T) {
			controller, native, output := newMcpApprovalTestController(t)
			var writes atomic.Int64
			writer := native.stdin
			native.stdin = callbackWriteCloser{write: func(data []byte) (int, error) {
				writes.Add(1)
				return writer.Write(data)
			}}
			if _, err := controller.setApprovalMode(mode); err != nil {
				t.Fatal(err)
			}
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
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
			calls := []struct {
				name      string
				arguments map[string]any
				session   bool
			}{
				{"list_connections", map[string]any{"limit": 1}, false},
				{"list_sessions", map[string]any{}, false},
				{"read_terminal", map[string]any{"sessionId": "session"}, true},
				{"send_text", map[string]any{"sessionId": "session", "text": "hello"}, true},
				{"run_command", map[string]any{"sessionId": "session", "command": "echo hello"}, true},
				{"open_connection", map[string]any{"connectionId": "ssh-node"}, false},
			}
			granted := false
			for attempt := range 3 {
				for _, call := range calls {
					denied := mode == mcpApprovalAlwaysAsk && attempt == 2
					previousWrites := writes.Load()
					before := len(mcpApprovalEvents(t, output))
					done := make(chan error, 1)
					go func() {
						result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.arguments})
						if err == nil && result.IsError != denied {
							err = errors.New("tool returned an unexpected approval outcome")
						}
						done <- err
					}()
					prompt := mode == mcpApprovalAlwaysAsk || mode == mcpApprovalOnFirstAccess && call.session && !granted
					// Full-access opens still acknowledge the target through the renderer, without showing a popup.
					if prompt || call.name == "open_connection" {
						id := waitForMcpApprovalRequest(t, controller)
						events := mcpApprovalEvents(t, output)
						if len(events) != before+1 || events[before].Tool != call.name || events[before].ApprovalMode != mode {
							t.Fatalf("unexpected approval for %s: %#v", call.name, events)
						}
						if err := controller.resolveApproval(id, !denied); err != nil {
							t.Fatal(err)
						}
						if call.session {
							granted = true
						}
					} else if mode == mcpApprovalFullAccess && len(mcpApprovalEvents(t, output)) != before {
						t.Fatal("full access requested approval")
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatalf("%s: %v", call.name, err)
						}
					case <-ctx.Done():
						t.Fatalf("%s did not finish", call.name)
					}
					if !prompt && call.name != "open_connection" && len(mcpApprovalEvents(t, output)) != before {
						t.Fatalf("unexpected popup for %s", call.name)
					}
					if denied && writes.Load() != previousWrites {
						t.Fatalf("denied %s wrote to the SSH session", call.name)
					}
				}
			}
		})
	}
}

func TestMcpAlwaysAskSeparatesConcurrentDecisionsAndDoesNotRememberDenials(t *testing.T) {
	controller, native, output := newMcpApprovalTestController(t)
	if _, err := controller.setApprovalMode(mcpApprovalAlwaysAsk); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- controller.ensureApproval(ctx, native, "send_text") }()
	}
	waitForMcpPendingRequestCount(t, controller, 2)
	events := mcpApprovalEvents(t, output)
	if events[0].RequestID == events[1].RequestID {
		t.Fatal("concurrent actions shared approval")
	}
	if err := controller.resolveApproval(events[0].RequestID, false); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err == nil {
		t.Fatal("denied action was allowed")
	}
	waitForMcpPendingRequestCount(t, controller, 1)
	if err := controller.resolveApproval(events[1].RequestID, true); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	if len(controller.decisions) != 0 {
		t.Fatal("always-ask remembered a decision")
	}
	go func() { results <- controller.ensureApproval(ctx, native, "read_terminal") }()
	id := waitForMcpApprovalRequest(t, controller)
	if err := controller.resolveApproval(id, true); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestMcpApprovalPolicyChangesCancelRequestsAndRevokeGrants(t *testing.T) {
	for _, target := range []mcpApprovalMode{mcpApprovalFullAccess, mcpApprovalAlwaysAsk} {
		t.Run(string(target), func(t *testing.T) {
			controller, native, _ := newMcpApprovalTestController(t)
			controller.decisions["old-session"] = true
			controller.decisions["denied-session"] = false
			result := make(chan error, 1)
			go func() { result <- controller.ensureApproval(context.Background(), native, "read_terminal") }()
			id := waitForMcpApprovalRequest(t, controller)
			controller.approvalMu.Lock()
			waiter := controller.pending[id]
			controller.approvalMu.Unlock()
			if _, err := controller.setApprovalMode(target); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil || !strings.Contains(err.Error(), "mode changed") {
				t.Fatalf("change returned %v", err)
			}
			if err := controller.resolveApproval(id, true); err == nil {
				t.Fatal("stale approval accepted")
			}
			if err := controller.checkApprovalGeneration(waiter); err == nil {
				t.Fatal("stale generation accepted")
			}
			if len(controller.decisions) != 0 || len(controller.pendingByTarget) != 0 {
				t.Fatal("policy change kept old grants")
			}
			controller.setLocked(true)
			if err := controller.checkApprovalGeneration(waiter); err == nil {
				t.Fatal("locked approval accepted")
			}
		})
	}
}

func TestMcpApprovalCancellationAndBoundsInAlwaysAsk(t *testing.T) {
	for _, reason := range []string{"cancel", "close", "lock", "stop", "policy"} {
		t.Run(reason, func(t *testing.T) {
			controller, native, _ := newMcpApprovalTestController(t)
			if _, err := controller.setApprovalMode(mcpApprovalAlwaysAsk); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			results := make(chan error, 2)
			for range 2 {
				go func() { results <- controller.ensureApproval(ctx, native, "read_terminal") }()
			}
			waitForMcpPendingRequestCount(t, controller, 2)
			switch reason {
			case "cancel":
				cancel()
			case "close":
				controller.forgetSession(native.id)
			case "lock":
				controller.setLocked(true)
			case "stop":
				if err := controller.stop(false); err != nil {
					t.Fatal(err)
				}
			case "policy":
				if _, err := controller.setApprovalMode(mcpApprovalOnFirstAccess); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				select {
				case err := <-results:
					if err == nil {
						t.Fatal("cancelled action was allowed")
					}
				case <-time.After(time.Second):
					t.Fatal("request was not cancelled")
				}
			}
			waitForMcpPendingRequestCount(t, controller, 0)
		})
	}
	controller, native, _ := newMcpApprovalTestController(t)
	if _, err := controller.setApprovalMode(mcpApprovalAlwaysAsk); err != nil {
		t.Fatal(err)
	}
	for index := range mcpMaxPendingApprovals {
		id := strings.Repeat("r", index+1)
		controller.pending[id] = &mcpApprovalWaiter{requestID: id, done: make(chan struct{})}
	}
	if err := controller.ensureApproval(context.Background(), native, "send_text"); err == nil {
		t.Fatal("approval bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := controller.ensureApproval(ctx, native, "send_text"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call: %v", err)
	}
	native.closed = true
	if err := controller.ensureApproval(context.Background(), native, "read_terminal"); !errors.Is(err, errSSHSessionClosed) {
		t.Fatalf("closed session: %v", err)
	}
}

func TestMcpApprovalModePersistenceAndValidation(t *testing.T) {
	installMcpTestSecretStore(t)
	controller, _, _ := newMcpApprovalTestController(t)
	for _, raw := range []string{`{}`, `{"McpApprovalMode":"unknown"}`, `{"McpApprovalMode":true}`, `{"McpApprovalMode":null}`} {
		_, settingsPath := authPaths(controller.server.databasePath)
		if err := os.WriteFile(settingsPath, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		settings, err := loadMcpSettings(controller.server.databasePath)
		if err != nil || settings.ApprovalMode != mcpApprovalOnFirstAccess {
			t.Fatalf("legacy mode: %#v, %v", settings, err)
		}
	}
	for _, mode := range []mcpApprovalMode{mcpApprovalFullAccess, mcpApprovalAlwaysAsk, mcpApprovalOnFirstAccess} {
		status, err := controller.setApprovalMode(mode)
		if err != nil || status.ApprovalMode != mode {
			t.Fatalf("save: %#v, %v", status, err)
		}
		port := reserveMcpTestPort(t)
		if err := controller.start(port, true); err != nil {
			t.Fatal(err)
		}
		if err := controller.start(port, true); err != nil {
			t.Fatal(err)
		}
		if err := controller.stop(true); err != nil {
			t.Fatal(err)
		}
		status, err = controller.setPort(reserveMcpTestPort(t))
		if err != nil || status.ApprovalMode != mode {
			t.Fatalf("port reset mode: %#v, %v", status, err)
		}
		restarted := newMcpController(controller.server)
		if err := restarted.start(reserveMcpTestPort(t), false); err != nil {
			t.Fatal(err)
		}
		if restarted.approvalMode != mode {
			t.Fatal("restart lost approval mode")
		}
		if err := restarted.stop(false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := controller.setApprovalMode("invalid"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	_, settingsPath := authPaths(filepath.Join(t.TempDir(), "wormhole.db"))
	if err := os.Mkdir(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	controller.server.databasePath = filepath.Join(filepath.Dir(settingsPath), "wormhole.db")
	if _, err := controller.setApprovalMode(mcpApprovalFullAccess); err == nil {
		t.Fatal("settings failure ignored")
	}
	if controller.approvalMode != mcpApprovalOnFirstAccess {
		t.Fatal("failed save changed active mode")
	}
}

func TestMcpFullAccessStillRequiresUnlockAndAlwaysAskShowsOnlyActiveTools(t *testing.T) {
	controller, native, output := newMcpApprovalTestController(t)
	if _, err := controller.setApprovalMode(mcpApprovalFullAccess); err != nil {
		t.Fatal(err)
	}
	controller.decisions[native.id] = false
	if err := controller.ensureApproval(context.Background(), native, "send_text"); err != nil {
		t.Fatal(err)
	}
	controller.setAccessRunning(true)
	controller.sessionConnected(&sshNativeSession{id: "new-session"})
	controller.sessionConnected(&sshNativeSession{id: "already-closed", closed: true})
	if controller.trackedSessions["already-closed"] {
		t.Fatal("closed session regained access")
	}
	controller.setLocked(true)
	if err := controller.ensureApproval(context.Background(), native, "send_text"); err == nil {
		t.Fatal("full access bypassed app lock")
	}
	if err := controller.ensureApproval(context.Background(), nil, "list_sessions"); err == nil {
		t.Fatal("locked inventory allowed")
	}
	controller.setLocked(false)
	if _, err := controller.setApprovalMode(mcpApprovalAlwaysAsk); err != nil {
		t.Fatal(err)
	}
	before := output.Len()
	finish := controller.trackSessionTool(native.id)
	if _, err := controller.setApprovalMode(mcpApprovalOnFirstAccess); err != nil {
		t.Fatal(err)
	}
	finish()
	var start, changed, end sshWireEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()[before:]))
	if err := decoder.Decode(&start); err != nil {
		t.Fatal(err)
	}
	// The policy change publishes both tracked sessions, preserving active access until it drains.
	for range 2 {
		if err := decoder.Decode(&changed); err != nil {
			t.Fatal(err)
		}
	}
	if err := decoder.Decode(&end); err != nil {
		t.Fatal(err)
	}
	if start.McpAccessible == nil || !*start.McpAccessible || end.McpAccessible == nil || *end.McpAccessible {
		t.Fatal("action access indicator was not scoped to the active tool")
	}
}

func TestMcpAdmittedToolDoesNotRestoreClosedSessionAccess(t *testing.T) {
	controller, native, output := newMcpApprovalTestController(t)
	native.server = controller.server
	if _, err := controller.setApprovalMode(mcpApprovalFullAccess); err != nil {
		t.Fatal(err)
	}
	controller.setAccessRunning(true)
	if err := controller.ensureApproval(context.Background(), native, "read_terminal"); err != nil {
		t.Fatal(err)
	}
	// The SSH session can close after approval, before the HTTP tool starts tracking access.
	native.close(false)
	before := output.Len()
	finish := controller.trackSessionTool(native.id)
	finish()
	controller.setLocked(true)
	controller.setLocked(false)
	if controller.trackedSessions[native.id] || len(controller.activeTools) != 0 {
		t.Error("an admitted tool restored a closed session or leaked its counter")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()[before:]))
	for decoder.More() {
		var event sshWireEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.McpAccessible != nil && *event.McpAccessible {
			t.Error("a closed session regained AI access after unlock")
		}
	}
}
