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
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
	first := controller.trackSessionTool("session")
	second := controller.trackSessionTool("session")
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
	finish := controller.trackSessionTool("session") // Admitted immediately before stop, resumed afterward.
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
