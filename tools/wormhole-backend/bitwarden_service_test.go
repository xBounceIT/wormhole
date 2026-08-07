package main

import (
	"bufio"
	"bytes"
	"testing"
	"time"
)

func TestBitwardenClearSessionBypassesLongRunningCliOperation(t *testing.T) {
	var output bytes.Buffer
	manager := newVncManager(nil, &backendLineWriter{writer: bufio.NewWriter(&output)})
	generation := manager.bitwardenGeneration()
	if !manager.setBitwardenSessionForGeneration("session-key", generation) {
		t.Fatal("could not seed Bitwarden session")
	}
	pending := newVncSession("pending", manager.output, manager)
	pendingContext, ok := pending.beginConnect()
	if !ok {
		t.Fatal("could not seed pending VNC handshake")
	}
	manager.sessions[pending.id] = pending

	manager.bitwardenOperationMu.Lock()
	done := make(chan struct{})
	go func() {
		manager.handle(backendCommand{ID: "clear", Action: "bitwarden.clear-session"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		manager.bitwardenOperationMu.Unlock()
		t.Fatal("clear-session waited for the Bitwarden CLI operation mutex")
	}
	manager.bitwardenOperationMu.Unlock()

	if session := manager.bitwardenSession(); session != "" {
		t.Fatalf("session after clear = %q, want empty", session)
	}
	if manager.bitwardenGenerationIs(generation) {
		t.Fatal("clear-session did not invalidate the previous session generation")
	}
	select {
	case <-pendingContext.Done():
	default:
		t.Fatal("clear-session did not cancel the pending VNC handshake")
	}
	pending.endConnect()
}

func TestBitwardenSessionCannotBeRestoredByInvalidatedOperation(t *testing.T) {
	manager := newVncManager(nil, nil)
	generation := manager.bitwardenGeneration()
	manager.clearBitwardenSession()

	if manager.setBitwardenSessionForGeneration("late-session-key", generation) {
		t.Fatal("an operation from the previous generation restored the Bitwarden session")
	}
	if session := manager.bitwardenSession(); session != "" {
		t.Fatalf("session after stale commit = %q, want empty", session)
	}
}
