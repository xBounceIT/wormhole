// Package workers provides a small lifecycle manager for the long-running
// goroutines that pump packets between the IKE control plane and the ESP data
// plane. It centralises cancellation (a single Shutdown cancels a shared
// context, sync.Once-guarded), panic recovery (a panic in any worker is logged
// and triggers Shutdown instead of crashing), and observability (named workers,
// an Active count). The design mirrors go-openvpn's workers.Manager.
package workers

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// Manager coordinates the lifecycle of a set of cooperating worker goroutines.
// The zero value is invalid; use NewManager.
type Manager struct {
	log *slog.Logger

	ctx          context.Context
	cancel       context.CancelFunc
	shutdownOnce sync.Once

	// onPanic, when non-nil, is invoked from the recover branch of every
	// worker before Shutdown. Implementations must be brief and must not
	// re-enter the manager.
	onPanic func(worker string, recovered any)

	// mu serialises Go and Shutdown so a late wg.Add cannot race a concurrent
	// Wait (which would panic "WaitGroup reused before previous Wait").
	mu       sync.Mutex
	shutdown bool

	wg     sync.WaitGroup
	active atomic.Int32
}

// Option configures NewManager.
type Option func(*Manager)

// WithPanicHandler installs a callback invoked when a worker panics. The
// manager still logs the panic and initiates shutdown regardless.
func WithPanicHandler(fn func(worker string, recovered any)) Option {
	return func(m *Manager) { m.onPanic = fn }
}

// NewManager returns a Manager whose context derives from parent (Background if
// nil). A nil log discards output.
func NewManager(parent context.Context, log *slog.Logger, opts ...Option) *Manager {
	if parent == nil {
		parent = context.Background()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{log: log, ctx: ctx, cancel: cancel}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Context returns the manager's shared cancellation context.
func (m *Manager) Context() context.Context { return m.ctx }

// ShouldShutdown returns a channel closed when Shutdown is invoked (or the
// parent context fires).
func (m *Manager) ShouldShutdown() <-chan struct{} { return m.ctx.Done() }

// Active returns the number of workers currently running.
func (m *Manager) Active() int32 { return m.active.Load() }

// Go starts a named worker. The function receives the manager's context and is
// expected to return when it fires. Panics are recovered, logged, and trigger
// Shutdown. Returns false if the manager has already begun shutting down.
func (m *Manager) Go(name string, fn func(ctx context.Context)) bool {
	m.mu.Lock()
	if m.shutdown {
		m.mu.Unlock()
		m.log.Warn("worker rejected after shutdown", "worker", name)
		return false
	}
	m.wg.Add(1)
	m.active.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer m.active.Add(-1)
		defer func() {
			if r := recover(); r != nil {
				m.log.Error("worker panic",
					"worker", name,
					"recovered", fmt.Sprint(r),
					"stack", string(debug.Stack()),
				)
				if m.onPanic != nil {
					m.onPanic(name, r)
				}
				m.Shutdown()
			}
		}()
		m.log.Debug("worker started", "worker", name)
		fn(m.ctx)
		m.log.Debug("worker stopped", "worker", name)
	}()
	return true
}

// Shutdown cancels the manager's context. Safe to call multiple times. Use Wait
// to block until workers have returned.
func (m *Manager) Shutdown() {
	m.shutdownOnce.Do(func() {
		m.mu.Lock()
		m.shutdown = true
		m.mu.Unlock()
		m.cancel()
	})
}

// Wait blocks until every worker has returned. It does NOT call Shutdown.
func (m *Manager) Wait() { m.wg.Wait() }
