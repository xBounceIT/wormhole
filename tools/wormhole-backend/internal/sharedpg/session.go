package sharedpg

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	ErrSessionClosed  = errors.New("shared PostgreSQL session is unavailable")
	ErrSessionStarted = errors.New("shared PostgreSQL session was already started")
	ErrSessionCleanup = errors.New("shared PostgreSQL connection cleanup is not confirmed")
)

type ownedConnection interface {
	Close(context.Context) error
	IsClosed() bool
	CleanupDone() chan struct{}
}

type connectionSlot struct {
	gate       chan struct{}
	conn       ownedConnection
	subscribed bool // protected by this slot's lease
}

// Session is the single native owner of a query connection and an optional
// notification connection. It retains only a native-memory session capability,
// never login credentials, and does not reconnect implicitly.
// Allocate with NewSession, call Open once, and call Close even if Open fails.
// A failed/timed-out Close must be retried before discarding the owner.
type Session struct {
	lifetime                 context.Context
	cancel                   context.CancelFunc
	control                  chan struct{}
	ready                    atomic.Bool
	started                  bool              // protected by control
	capability               *securemem.Buffer // protected by control; never serialized
	requireLocked            bool              // authenticated transport policy; protected by control
	requirePrivateStatements bool              // Standard and above require log_statement=none
	admission                AdmissionRequest  // authenticated identities; protected by control
	authEpoch                uint64            // account epoch at successful authentication
	administrator            bool              // role assertion from the same audited admission
	slots                    [2]connectionSlot
}

func NewSession() *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{lifetime: ctx, cancel: cancel, control: make(chan struct{}, 1)}
	for i := range s.slots {
		s.slots[i].gate = make(chan struct{}, 1)
	}
	return s
}

// Done closes when the transport owner is invalidated or explicitly closed.
// Consumers must still call Close and confirm cleanup before dropping the owner.
func (s *Session) Done() <-chan struct{} { return s.lifetime.Done() }

// Open's context governs startup only. Workspace lock must call Close, which
// cancels both active and queued operations before waiting for their leases.
func (s *Session) Open(ctx context.Context, settings Settings, secret []byte, policy ChangePolicy) error {
	return s.open(ctx, policy.UseNotifications(), func(ctx context.Context) (ownedConnection, error) {
		s.requireLocked = settings.Profile == vault.Hardened || settings.Profile == vault.Paranoid
		s.requirePrivateStatements = settings.Profile != vault.Default
		conn, err := Connect(ctx, settings, secret)
		if err != nil {
			return nil, err
		}
		return conn, nil
	})
}

func (s *Session) open(ctx context.Context, notifications bool, dial func(context.Context) (ownedConnection, error)) error {
	if ctx == nil {
		return ErrConfiguration
	}
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	if s.lifetime.Err() != nil {
		return ErrSessionClosed
	}
	if s.started {
		return ErrSessionStarted
	}
	s.started = true
	opCtx, cancel := context.WithTimeout(ctx, connectionDeadline)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer func() { stop(); cancel() }()
	count := 1
	if notifications {
		count = 2
	}
	for i := 0; i < count; i++ {
		conn, err := dial(opCtx)
		if conn != nil {
			s.slots[i].conn = conn
		}
		if err == nil {
			err = opCtx.Err()
		}
		if err == nil && conn == nil {
			err = ErrConnection
		}
		if err != nil {
			s.cancel()
			cleanupCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
			cleanupErr := s.closeLocked(cleanupCtx)
			done()
			if cleanupErr != nil {
				return ErrSessionCleanup
			}
			return err
		}
	}
	s.ready.Store(true)
	return nil
}

// lease is package-private: SQL/notification APIs must release it after all
// protocol reads finish and must use the returned cancellation-aware context.
// A lease never permits concurrent operations on the same pgx connection.
func (s *Session) lease(ctx context.Context, index int) (ownedConnection, context.Context, func(), error) {
	if ctx == nil || index < 0 || index >= len(s.slots) {
		return nil, nil, nil, ErrConfiguration
	}
	if !s.ready.Load() || s.lifetime.Err() != nil {
		return nil, nil, nil, ErrSessionClosed
	}
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	slot := &s.slots[index]
	if err := take(opCtx, slot.gate); err != nil {
		stop()
		cancel()
		return nil, nil, nil, err
	}
	if s.lifetime.Err() != nil || slot.conn == nil || slot.conn.IsClosed() {
		give(slot.gate)
		stop()
		cancel()
		return nil, nil, nil, ErrSessionClosed
	}
	var once sync.Once
	release := func() { once.Do(func() { stop(); cancel(); give(slot.gate) }) }
	return slot.conn, opCtx, release, nil
}

func (s *Session) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s.ready.Store(false)
	s.cancel()
	if err := take(ctx, s.control); err != nil {
		return err
	}
	defer give(s.control)
	return s.closeLocked(ctx)
}

// Keep uncertain connections attached to the owner. Successful repeated Close
// calls are idempotent, but an expired caller context never reports success.
func (s *Session) closeLocked(ctx context.Context) error {
	var result error
	s.admission = AdmissionRequest{}
	s.authEpoch = 0
	s.administrator = false
	if s.capability != nil {
		if err := s.capability.Close(); err != nil {
			result = ErrSessionCleanup
		} else {
			s.capability = nil
		}
	}
	for i := range s.slots {
		slot := &s.slots[i]
		if err := take(ctx, slot.gate); err != nil {
			return err
		}
		if slot.conn != nil {
			_ = slot.conn.Close(ctx)
			if !slot.conn.IsClosed() {
				result = ErrSessionCleanup
			} else {
				select {
				case <-slot.conn.CleanupDone():
					slot.conn = nil
				case <-ctx.Done():
					give(slot.gate)
					return ctx.Err()
				}
			}
		}
		give(slot.gate)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return result
}

func take(ctx context.Context, gate chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			give(gate)
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func give(gate chan struct{}) { <-gate }
