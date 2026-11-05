package ipsec

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/session"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestSignalDeathCoalesces pins the cap-1 semantics: several deaths fired before
// the supervisor consumes any collapse into a single pending reconnect.
func TestSignalDeathCoalesces(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	c.signalDeath()
	c.signalDeath()
	c.signalDeath()
	if got := len(c.deathSig); got != 1 {
		t.Fatalf("deathSig len = %d, want 1 (cap-1 coalescing)", got)
	}
}

// TestSuperviseOneDeathOneReconnect verifies a single death triggers exactly one
// reconnect and nothing spurious afterwards.
func TestSuperviseOneDeathOneReconnect(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	var count atomic.Int32
	ran := make(chan struct{}, 4)
	c.reconnectFn = func() {
		count.Add(1)
		ran <- struct{}{}
	}
	c.superWG.Add(1)
	go c.supervise()

	c.signalDeath()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect not invoked after a death signal")
	}
	// No second reconnect should follow a single death.
	select {
	case <-ran:
		t.Fatal("a spurious second reconnect ran")
	case <-time.After(100 * time.Millisecond):
	}

	c.superCancel()
	c.superWG.Wait()
	if count.Load() != 1 {
		t.Fatalf("reconnect count = %d, want 1", count.Load())
	}
}

// TestSuperviseCoalescesWhileBusy proves that deaths arriving while a reconnect
// is in flight coalesce into a single follow-up reconnect (cap-1 deathSig).
func TestSuperviseCoalescesWhileBusy(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	var count atomic.Int32
	enter := make(chan struct{})
	release := make(chan struct{})
	c.reconnectFn = func() {
		count.Add(1)
		enter <- struct{}{} // announce we are running
		<-release           // stay busy until released
	}
	c.superWG.Add(1)
	go c.supervise()

	// First death → reconnect #1 starts and blocks.
	c.signalDeath()
	<-enter
	// While #1 is busy the supervisor is not in its select, so these three deaths
	// collapse into a single buffered signal.
	c.signalDeath()
	c.signalDeath()
	c.signalDeath()
	release <- struct{}{} // finish #1; supervisor loops and consumes the one signal

	<-enter               // reconnect #2 (the coalesced one)
	release <- struct{}{} // finish #2; no signals remain

	c.superCancel()
	c.superWG.Wait()
	if count.Load() != 2 {
		t.Fatalf("reconnect count = %d, want 2 (3 deaths-while-busy coalesced to 1)", count.Load())
	}
}

// TestRedialBackoffInterruptedByClose checks the redial loop unwinds promptly
// with errClientClosing when Close cancels superCtx mid-backoff.
func TestRedialBackoffInterruptedByClose(t *testing.T) {
	c := newClient(Config{
		Logger:                  discardLogger(),
		ReconnectBackoffBase:    50 * time.Millisecond,
		ReconnectBackoffMax:     50 * time.Millisecond,
		ReconnectAttemptTimeout: time.Second,
	})
	var attempts atomic.Int32
	c.dialSession = func(context.Context) (*session.Session, error) {
		attempts.Add(1)
		return nil, errors.New("dial boom")
	}

	done := make(chan error, 1)
	go func() {
		_, err := c.redialWithBackoff()
		done <- err
	}()

	time.Sleep(120 * time.Millisecond) // let a couple of attempts fail
	c.superCancel()

	select {
	case err := <-done:
		if !errors.Is(err, errClientClosing) {
			t.Fatalf("err = %v, want errClientClosing", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redialWithBackoff did not return after Close")
	}
	if attempts.Load() < 1 {
		t.Fatal("expected at least one dial attempt")
	}
}

// TestRedialBackoffSucceedsAfterRetries verifies the loop returns the dialed
// session once an attempt succeeds, after retrying the failures.
func TestRedialBackoffSucceedsAfterRetries(t *testing.T) {
	c := newClient(Config{
		Logger:                  discardLogger(),
		ReconnectBackoffBase:    10 * time.Millisecond,
		ReconnectBackoffMax:     20 * time.Millisecond,
		ReconnectAttemptTimeout: time.Second,
	})
	want := session.New(session.Config{Logger: discardLogger()})
	var attempts atomic.Int32
	c.dialSession = func(context.Context) (*session.Session, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("dial boom")
		}
		return want, nil
	}

	got, err := c.redialWithBackoff()
	if err != nil {
		t.Fatalf("redialWithBackoff: %v", err)
	}
	if got != want {
		t.Fatal("redialWithBackoff did not return the dialed session")
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
}

// TestCloseDuringReconnect is the critical ordering check: Close must wait for an
// in-flight reconnect to finish (it blocks in superWG.Wait) and then complete
// cleanly, with no panic or leaked goroutine. Run under -race.
func TestCloseDuringReconnect(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	c.session.Store(session.New(session.Config{Logger: discardLogger()}))

	inReconnect := make(chan struct{})
	proceed := make(chan struct{})
	c.reconnectFn = func() {
		close(inReconnect)
		<-proceed // simulate a long in-flight reconnect
	}
	c.superWG.Add(1)
	go c.supervise()

	c.signalDeath()
	<-inReconnect // a reconnect is now in flight

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()

	// Close must not return while the reconnect is still running.
	select {
	case <-closeDone:
		t.Fatal("Close returned before the in-flight reconnect finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(proceed) // let the reconnect return; supervisor then sees superCtx.Done
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not complete after the reconnect finished")
	}
}

// TestReconnectNoopWhenClosing checks the real reconnect bails out immediately
// when the client is already closing, never touching the (absent) data plane.
func TestReconnectNoopWhenClosing(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	c.superCancel() // mark closing

	done := make(chan struct{})
	go func() { c.reconnect(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reconnect did not bail out when closing")
	}
}

// TestStartWorkersSwapsManager verifies each generation gets a fresh worker
// manager published under mu. superCtx is cancelled up front so the workers exit
// immediately (the IKE driver takes the ctx.Done path and the rx demux sees no
// session), isolating the manager-swap behavior.
func TestStartWorkersSwapsManager(t *testing.T) {
	log := discardLogger()
	c := newClient(Config{Logger: log})
	c.superCancel() // managers are born cancelled → workers return at once

	c.startWorkers(session.New(session.Config{Logger: log}))
	c.mu.Lock()
	m1 := c.mgr
	c.mu.Unlock()
	if m1 == nil {
		t.Fatal("no manager after the first startWorkers")
	}
	m1.Wait()

	c.startWorkers(session.New(session.Config{Logger: log}))
	c.mu.Lock()
	m2 := c.mgr
	c.mu.Unlock()
	m2.Wait()

	if m1 == m2 {
		t.Fatal("startWorkers did not install a new manager generation")
	}
}
