package workers

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestShutdownStopsWorkersAndWaitJoins: workers observe the shared context and
// Wait blocks until all have returned.
func TestShutdownStopsWorkersAndWaitJoins(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), nil)
	var stopped atomic.Int32
	for range 3 {
		if !m.Go("w", func(ctx context.Context) {
			<-ctx.Done()
			stopped.Add(1)
		}) {
			t.Fatal("Go rejected before shutdown")
		}
	}
	if m.Active() != 3 {
		t.Fatalf("Active = %d, want 3", m.Active())
	}
	m.Shutdown()
	done := make(chan struct{})
	go func() { m.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Shutdown")
	}
	if stopped.Load() != 3 {
		t.Fatalf("stopped = %d, want 3", stopped.Load())
	}
	if m.Active() != 0 {
		t.Fatalf("Active = %d after Wait, want 0", m.Active())
	}
}

// TestGoAfterShutdownRejected: a worker started after Shutdown must be refused
// (returning false), never silently spawned against a cancelled context.
func TestGoAfterShutdownRejected(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), nil)
	m.Shutdown()
	if m.Go("late", func(context.Context) { t.Error("late worker ran") }) {
		t.Fatal("Go accepted a worker after Shutdown")
	}
}

// TestPanicTriggersHandlerAndShutdown: a worker panic is recovered, routed to
// the panic handler, and shuts the whole manager down (cancelling siblings).
func TestPanicTriggersHandlerAndShutdown(t *testing.T) {
	t.Parallel()
	var handled atomic.Bool
	m := NewManager(context.Background(), nil,
		WithPanicHandler(func(worker string, recovered any) { handled.Store(true) }))
	sibling := make(chan struct{})
	m.Go("sibling", func(ctx context.Context) {
		<-ctx.Done()
		close(sibling)
	})
	m.Go("bomb", func(context.Context) { panic("boom") })

	select {
	case <-sibling:
	case <-time.After(5 * time.Second):
		t.Fatal("sibling was not cancelled by the panicking worker")
	}
	m.Wait()
	if !handled.Load() {
		t.Fatal("panic handler was not invoked")
	}
}

// TestShutdownIdempotent: repeated Shutdown calls are safe.
func TestShutdownIdempotent(t *testing.T) {
	t.Parallel()
	m := NewManager(context.Background(), nil)
	m.Shutdown()
	m.Shutdown()
	m.Wait()
}
