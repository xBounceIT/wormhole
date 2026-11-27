package vaultwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandlerMayReturnBorrowedPayload(t *testing.T) {
	h := startServer(t, &testHandler{handle: func(_ context.Context, _ string, payload json.RawMessage) (json.RawMessage, error) {
		return payload, nil
	}}, 5*time.Second)
	for id := uint64(1); id <= 20; id++ {
		if err := json.NewEncoder(h.input).Encode(Request{Version: 1, ID: id, Operation: "echo", Payload: json.RawMessage(`{"metadata":"approved"}`)}); err != nil {
			t.Fatal(err)
		}
		r := h.read(t)
		if r.Error != "" || string(r.Result) != `{"metadata":"approved"}` {
			t.Fatalf("borrowed response was corrupted: %+v", r)
		}
	}
}

func TestEncodedResponseCannotExceedFrameLimit(t *testing.T) {
	h := startServer(t, &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`"` + strings.Repeat("<", MaxFrameBytes/2) + `"`), nil
	}}, 5*time.Second)
	h.send(t, 1, "read", 0)
	line, err := h.reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(line)-1 > MaxFrameBytes {
		t.Fatalf("encoded output exceeded frame limit: %d", len(line)-1)
	}
	var r Response
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatal(err)
	}
	if r.Error != "vault_invalid_response" {
		t.Fatal("oversized encoded response not rejected")
	}
}

func TestCloseWaitsForActiveHandler(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var finished, closedTooEarly atomic.Bool
	h := startServer(t, &testHandler{
		handle: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release
			finished.Store(true)
			return nil, ctx.Err()
		},
		onClose: func() error {
			if !finished.Load() {
				closedTooEarly.Store(true)
			}
			return nil
		},
	}, time.Second)
	h.send(t, 1, "wait", 0)
	<-started
	h.input.Close()
	<-cancelled
	// Hold Handle at its cleanup barrier. Close must never race this lifetime.
	select {
	case err := <-h.done:
		h.done <- err
		closedTooEarly.Store(true)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	h.finished(t, nil)
	if closedTooEarly.Load() {
		t.Fatal("Close ran while Handle still owned resources")
	}
}

func TestInputRejectsUnterminatedFrame(t *testing.T) {
	h := startServer(t, &testHandler{}, time.Second)
	io.WriteString(h.input, `{"version":1,"id":1,"operation":"heartbeat"}`)
	h.input.Close()
	// A stdio frame is complete only after the newline. EOF must not execute a
	// partial final write, even when its prefix happens to be valid JSON.
	h.finished(t, ErrProtocol)
}

func TestQueuedCompletionCannotDefeatAcceptedCancellation(t *testing.T) {
	// This result has already left the worker when the event loop accepts cancel.
	// Its worker-side context check is therefore necessarily stale.
	queue := make(chan completed, 1)
	result := json.RawMessage(`{"metadata":"approved"}`)
	queue <- completed{id: 1, result: result}
	response := (<-queue).response(true)
	if response.ID != 1 || response.Error != "vault_cancelled" || len(response.Result) != 0 {
		t.Fatal("queued success survived cancellation")
	}
	if !bytes.Equal(result, make([]byte, len(result))) {
		t.Fatal("cancelled result was not wiped")
	}
}

func TestUnknownCancellationDoesNotClaimSuccess(t *testing.T) {
	h := startServer(t, &testHandler{}, time.Second)
	h.send(t, 2, "cancel", 1)
	if r := h.read(t); string(r.Result) != `{"cancelled":false}` {
		t.Fatal("unknown request claimed cancelled")
	}
}

func TestShutdownReportsCloseFailureWithoutLeakingError(t *testing.T) {
	h := startServer(t, &testHandler{onClose: func() error { return errors.New("secret close details") }}, time.Second)
	h.input.Close()
	h.finished(t, ErrCleanup)
	err := <-h.done
	h.done <- err
	if strings.Contains(err.Error(), "secret close details") {
		t.Fatal("cleanup error exposed handler detail")
	}
}

func TestShutdownIsBoundedForNonCooperativeHandler(t *testing.T) {
	started, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := startServer(t, &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		close(started)
		<-release
		return json.RawMessage(`{}`), nil
	}, onClose: func() error { close(closed); return nil }}, 5*time.Second)
	h.send(t, 1, "wait", 0)
	<-started
	h.input.Close()
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, ErrShutdown) {
			t.Errorf("wrong shutdown error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("shutdown waited indefinitely")
	}
	select {
	case <-closed:
		t.Error("Close overlapped noncooperative Handle")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("deferred cleanup did not finish")
	}
}

func TestFrameTerminatorAndExactBounds(t *testing.T) {
	valid := []byte(`{"version":1,"id":1,"operation":"heartbeat"}`)
	valid = append(valid, bytes.Repeat([]byte{' '}, MaxFrameBytes-len(valid))...)
	if _, err := decodeRequest(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequest(append(valid, ' ')); err != ErrProtocol {
		t.Fatal("oversized direct decode accepted")
	}
	for _, terminator := range []string{"\n", "\r\n"} {
		frame := append(bytes.Clone(valid), terminator...)
		scanner := bufio.NewScanner(bytes.NewReader(frame))
		scanner.Split(splitFrame)
		scanner.Buffer(make([]byte, 4096), MaxFrameBytes+2)
		if !scanner.Scan() || len(scanner.Bytes()) != MaxFrameBytes {
			t.Fatalf("exact frame rejected: %v", scanner.Err())
		}
		if scanner.Scan() || scanner.Err() != nil {
			t.Fatal("bad frame termination")
		}
	}
	invalid := append([]byte(`{"version":1,"id":1,"operation":"read","payload":"`), 0xff)
	invalid = append(invalid, []byte(`"}`)...)
	if _, err := decodeRequest(invalid); err != ErrProtocol {
		t.Fatal("invalid UTF-8 normalized into a different request")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func (shortWriter) Close() error                { return nil }

func TestShortWriteStopsTransport(t *testing.T) {
	ir, iw := io.Pipe()
	defer iw.Close()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), ir, shortWriter{}, &testHandler{}, time.Second) }()
	if err := json.NewEncoder(iw).Encode(Request{Version: 1, ID: 1, Operation: "heartbeat"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrOutput) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("short write was ignored")
	}
}
