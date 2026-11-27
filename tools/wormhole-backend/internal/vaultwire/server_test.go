package vaultwire

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testHandler struct {
	handle       func(context.Context, string, json.RawMessage) (json.RawMessage, error)
	onClose      func() error
	closed       atomic.Bool
	exitOnCancel bool
	events       chan struct{}
}

func (h *testHandler) SharedCatalogEvents() <-chan struct{} { return h.events }

func TestCatalogEventsDuringRequest(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := &testHandler{events: make(chan struct{}, 1), handle: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		close(entered)
		select {
		case <-release:
			return json.RawMessage(`{"ok":true}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	s := startServer(t, h, time.Second)
	s.send(t, 1, "catalog", 0)
	<-entered
	h.events <- struct{}{}
	event := s.read(t)
	if event.Version != 1 || event.ID != 0 || event.Event != "shared-catalog-changed" || event.Result != nil || event.Error != "" {
		t.Fatal("invalid event", event)
	}
	s.send(t, 2, "heartbeat", 0)
	if r := s.read(t); r.ID != 2 || string(r.Result) != `{"alive":true}` {
		t.Fatal("heartbeat blocked", r)
	}
	close(release)
	if r := s.read(t); r.ID != 1 || string(r.Result) != `{"ok":true}` {
		t.Fatal("request lost", r)
	}
	close(h.events)
	s.send(t, 3, "heartbeat", 0)
	if r := s.read(t); r.ID != 3 {
		t.Fatal("closed event source spun")
	}
}

func (h *testHandler) ExitOnCancel(operation string) bool {
	return h.exitOnCancel && operation == "unlock"
}

func (h *testHandler) Handle(ctx context.Context, operation string, payload json.RawMessage) (json.RawMessage, error) {
	return h.handle(ctx, operation, payload)
}
func (h *testHandler) Close() error {
	h.closed.Store(true)
	if h.onClose != nil {
		return h.onClose()
	}
	return nil
}

type harness struct {
	input   *io.PipeWriter
	output  *io.PipeReader
	reader  *bufio.Reader
	done    chan error
	handler *testHandler
}

func startServer(t *testing.T, h *testHandler, timeout time.Duration) *harness {
	t.Helper()
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), ir, ow, h, timeout) }()
	t.Cleanup(func() {
		iw.Close()
		or.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("server did not exit")
		}
	})
	return &harness{iw, or, bufio.NewReader(or), done, h}
}
func (h *harness) send(t *testing.T, id uint64, operation string, target uint64) {
	t.Helper()
	if err := json.NewEncoder(h.input).Encode(Request{Version: 1, ID: id, Operation: operation, TargetID: target}); err != nil {
		t.Fatal(err)
	}
}
func (h *harness) read(t *testing.T) Response {
	t.Helper()
	result := make(chan Response, 1)
	errs := make(chan error, 1)
	go func() {
		line, err := h.reader.ReadBytes('\n')
		if err != nil {
			errs <- err
			return
		}
		var response Response
		err = json.Unmarshal(line, &response)
		if err != nil {
			errs <- err
			return
		}
		result <- response
	}()
	select {
	case r := <-result:
		return r
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("response timed out")
	}
	return Response{}
}
func (h *harness) finished(t *testing.T, want error) {
	t.Helper()
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, want) {
			t.Fatalf("exit got %v want %v", err, want)
		}
		if !h.handler.closed.Load() {
			t.Fatal("handler not closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exit timed out")
	}
}

func TestSerializedRequestsCancellationAndRedactedErrors(t *testing.T) {
	started := make(chan struct{}, 1)
	h := startServer(t, &testHandler{handle: func(ctx context.Context, op string, _ json.RawMessage) (json.RawMessage, error) {
		switch op {
		case "wait":
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		case "fail":
			return json.RawMessage(`{"secret":"must-not-leak"}`), errors.New("password=must-not-leak")
		default:
			return json.RawMessage(`{"ready":true}`), nil
		}
	}}, time.Second)
	h.send(t, 1, "wait", 0)
	<-started
	h.send(t, 2, "another", 0)
	if r := h.read(t); r.ID != 2 || r.Error != "vault_busy" {
		t.Fatal(r)
	}
	h.send(t, 3, "heartbeat", 0)
	if r := h.read(t); r.ID != 3 || r.Error != "" {
		t.Fatal(r)
	}
	h.send(t, 4, "cancel", 1)
	a, b := h.read(t), h.read(t)
	if a.ID > b.ID {
		a, b = b, a
	}
	if a.ID != 1 || a.Error != "vault_cancelled" || b.ID != 4 {
		t.Fatalf("cancel responses: %+v %+v", a, b)
	}
	h.send(t, 5, "fail", 0)
	if r := h.read(t); r.Error != "vault_operation_failed" || len(r.Result) != 0 {
		t.Fatal("handler error leaked")
	}
	h.send(t, 6, "read", 0)
	if r := h.read(t); r.Error != "" || string(r.Result) != `{"ready":true}` {
		t.Fatal(r)
	}
	h.send(t, 7, "cancel", 1)
	if r := h.read(t); r.ID != 7 || r.Error != "" {
		t.Fatal(r)
	}
	h.send(t, 8, "lock", 0)
	h.finished(t, nil)
}

func TestEOFAndHeartbeatCancelActiveWork(t *testing.T) {
	for _, mode := range []string{"eof", "heartbeat", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			started, cancelled := make(chan struct{}), make(chan struct{})
			h := startServer(t, &testHandler{handle: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
				close(started)
				<-ctx.Done()
				close(cancelled)
				return nil, ctx.Err()
			}}, 100*time.Millisecond)
			h.send(t, 1, "wait", 0)
			<-started
			var expected error
			switch mode {
			case "eof":
				h.input.Close()
			case "heartbeat":
				expected = ErrHeartbeat
			case "malformed":
				io.WriteString(h.input, "{broken}\n")
				expected = ErrProtocol
			}
			h.finished(t, expected)
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("work not cancelled")
			}
		})
	}
}

func TestProtocolRejectsReplayAndInvalidFrames(t *testing.T) {
	for _, frame := range []string{
		`null`, `[]`, `{}`, `{"version":2,"id":1,"operation":"read"}`, `{"version":1,"id":0,"operation":"read"}`,
		`{"version":1,"id":9007199254740992,"operation":"read"}`, `{"version":1,"id":1,"operation":"read","unknown":1}`,
		`{"version":1,"id":1,"id":2,"operation":"read"}`, `{"version":1,"ID":1,"operation":"read"}`,
		`{"version":1,"id":1,"operation":"read"} {}`, `{"version":1,"id":1,"operation":"cancel","targetId":2}`,
		`{"version":1,"id":1,"operation":"heartbeat","payload":{}}`, `{"version":1,"id":1,"operation":"read","targetId":1}`,
		`{"version":1,"id":1,"operation":"!"}`, `{"version":1,"id":1,"operation":""}`,
	} {
		if _, err := decodeRequest([]byte(frame)); err != ErrProtocol {
			t.Fatalf("accepted invalid frame %s", frame)
		}
	}
	h := startServer(t, &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		t.Fatal("handler called")
		return nil, nil
	}}, time.Second)
	h.send(t, 1, "heartbeat", 0)
	h.read(t)
	h.send(t, 1, "heartbeat", 0)
	h.finished(t, ErrProtocol)
}

func TestInvalidResponsesAndOutputFailure(t *testing.T) {
	for _, result := range []string{"invalid", strings.Repeat("x", MaxFrameBytes)} {
		h := startServer(t, &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(result), nil
		}}, time.Second)
		h.send(t, 1, "read", 0)
		if r := h.read(t); r.Error != "vault_invalid_response" {
			t.Fatal(r)
		}
		h.input.Close()
		h.finished(t, nil)
	}
	h := startServer(t, &testHandler{}, time.Second)
	h.output.Close()
	h.send(t, 1, "heartbeat", 0)
	h.finished(t, ErrOutput)
}

func TestOversizeInputAndBackpressure(t *testing.T) {
	h := startServer(t, &testHandler{}, time.Second)
	io.WriteString(h.input, strings.Repeat("x", MaxFrameBytes+1)+"\n")
	h.finished(t, ErrProtocol)
	h = startServer(t, &testHandler{}, time.Second)
	// No reader: stdout backpressure must not prevent lock/heartbeat processing.
	for id := uint64(1); id <= 12; id++ {
		if err := json.NewEncoder(h.input).Encode(Request{Version: 1, ID: id, Operation: "heartbeat"}); err != nil {
			break
		}
	}
	h.finished(t, ErrOutput)
}

func TestContextCancellation(t *testing.T) {
	ir, iw := io.Pipe()
	or, ow := io.Pipe()
	defer iw.Close()
	defer or.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &testHandler{}
	if err := Serve(ctx, ir, ow, h, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzRequest(f *testing.F) {
	f.Add([]byte(`{"version":1,"id":1,"operation":"heartbeat"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < MaxFrameBytes {
			_, _ = decodeRequest(data)
		}
	})
}
