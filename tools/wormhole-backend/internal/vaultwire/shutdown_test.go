package vaultwire

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type stalledCloser struct {
	io.ReadCloser
	entered, release chan struct{}
}

func (s stalledCloser) Close() error { close(s.entered); <-s.release; return s.ReadCloser.Close() }

type discardCloser struct{}

func (discardCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardCloser) Close() error                { return nil }

func TestShutdownDeadlineIncludesPipeClose(t *testing.T) {
	ir, iw := io.Pipe()
	defer iw.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), stalledCloser{ir, entered, release}, discardCloser{}, &testHandler{}, 5*time.Second)
	}()
	io.WriteString(iw, "{\"version\":1,\"id\":1,\"operation\":\"lock\"}\n")
	<-entered
	var result error
	select {
	case result = <-done:
	case <-time.After(ShutdownTimeout + 500*time.Millisecond):
		t.Error("pipe Close escaped the shutdown deadline")
	}
	close(release)
	if result == nil {
		select {
		case result = <-done:
		case <-time.After(time.Second):
			t.Fatal("server never returned")
		}
	}
	if !errors.Is(result, ErrShutdown) {
		t.Fatalf("expected shutdown timeout, got %v", result)
	}
}

type failedCloser struct{ io.Reader }

func (failedCloser) Close() error { return errors.New("private path in close error") }

func TestPipeCloseFailureIsRedacted(t *testing.T) {
	err := Serve(context.Background(), failedCloser{strings.NewReader("")}, discardCloser{}, &testHandler{}, time.Second)
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("pipe close failure not reported: %v", err)
	}
	if strings.Contains(err.Error(), "private path") {
		t.Fatal("raw close error escaped")
	}
}
