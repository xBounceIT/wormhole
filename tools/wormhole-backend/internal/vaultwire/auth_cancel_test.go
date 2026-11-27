package vaultwire

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAuthenticationCancellationExitsAndRetiresHandler(t *testing.T) {
	started := make(chan struct{})
	h := startServer(t, &testHandler{exitOnCancel: true, handle: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		// Even a handler that finished installing keys cannot keep the process
		// alive after cancellation of its authentication operation.
		return json.RawMessage(`{"unlocked":true}`), nil
	}}, time.Second)
	h.send(t, 1, "unlock", 0)
	<-started
	h.send(t, 2, "cancel", 1)
	h.finished(t, nil)
}

func TestNonAuthenticationCancellationStillKeepsServiceAlive(t *testing.T) {
	started := make(chan struct{})
	h := startServer(t, &testHandler{exitOnCancel: true, handle: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}, time.Second)
	h.send(t, 1, "metadata-read", 0)
	<-started
	h.send(t, 2, "cancel", 1)
	for range 2 {
		h.read(t)
	}
	h.send(t, 3, "heartbeat", 0)
	if response := h.read(t); response.ID != 3 || response.Error != "" {
		t.Fatal(response)
	}
}

func TestRetiredSessionExitsWithoutPublishingHandlerResult(t *testing.T) {
	h := startServer(t, &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"unlocked":true,"secret":"must-not-leak"}`), errors.Join(ErrRetired, errors.New("private storage diagnostic"))
	}}, time.Second)
	h.send(t, 1, "unlock", 0)
	h.finished(t, ErrRetired)
	if line, _ := h.reader.ReadString('\n'); line != "" {
		t.Fatalf("retired result leaked: %s", line)
	}
}
