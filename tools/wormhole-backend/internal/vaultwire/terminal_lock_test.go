package vaultwire

import (
	"context"
	"encoding/json"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// Model a native stdin whose next synchronous Read cannot be interrupted by
// Close. A decoded terminal lock must not initiate that unnecessary operation.
type terminalLockReader struct {
	frame   []byte
	reads   atomic.Int32
	unblock chan struct{}
}

func (r *terminalLockReader) Read(p []byte) (int, error) {
	if r.reads.Add(1) == 1 {
		return copy(p, r.frame), nil
	}
	<-r.unblock
	return 0, io.EOF
}
func (*terminalLockReader) Close() error { return nil }

type terminalLockOutput struct{ io.Writer }

func (terminalLockOutput) Close() error { return nil }

func TestTerminalLockDoesNotReadAnotherFrame(t *testing.T) {
	frame, err := json.Marshal(Request{Version: Version, ID: 1, Operation: "lock"})
	if err != nil {
		t.Fatal(err)
	}
	input := &terminalLockReader{frame: append(frame, '\n'), unblock: make(chan struct{})}
	retired := make(chan struct{})
	h := &testHandler{handle: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		t.Error("terminal control reached the application handler")
		return nil, nil
	}, onClose: func() error { close(retired); return nil }}
	err = Serve(context.Background(), input, terminalLockOutput{io.Discard}, h, time.Minute)
	close(input.unblock)
	select {
	case <-retired:
	case <-time.After(ShutdownTimeout):
		t.Fatal("owner was not retired")
	}
	if err != nil {
		t.Fatal("decoded terminal lock waited for another input read", err)
	}
	if input.reads.Load() != 1 {
		t.Fatal("read past the terminal lock", input.reads.Load())
	}
	if !h.closed.Load() {
		t.Fatal("lock did not close the original handler")
	}
}
