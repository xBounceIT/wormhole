// Package secretclipboard owns expiring native clipboard releases. It retains
// only an ownership ticket, never the copied plaintext, after Write returns.
package secretclipboard

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

var ErrUnavailable = errors.New("vault_clipboard_unavailable")
var ErrInput = errors.New("vault_clipboard_invalid")
var ErrClosed = errors.New("vault_clipboard_closed")

type Ticket uint64

// Write must publish history-exclusion markers together with text. An error may
// carry a ticket when cleanup still needs retrying. Clear is a no-op if another
// writer replaced that ticket. No implementation may retain the borrowed bytes.
type Driver interface {
	Write(context.Context, []byte) (Ticket, error)
	Clear(context.Context, Ticket) error
	Close() error
}
type timer interface{ Stop() bool }
type Manager struct {
	mu         sync.Mutex
	driver     Driver
	ticket     Ticket
	timer      timer
	generation uint64
	closed     bool
	after      func(time.Duration, func()) timer
}

func New(driver Driver) *Manager {
	return &Manager{driver: driver, after: func(d time.Duration, f func()) timer { return time.AfterFunc(d, f) }}
}
func validValue(value []byte) bool {
	return len(value) > 0 && len(value) <= 16384 && utf8.Valid(value) && bytes.IndexByte(value, 0) < 0
}
func (m *Manager) Copy(ctx context.Context, value []byte, ttl time.Duration) error {
	if (ttl != 20*time.Second && ttl != 30*time.Second) || !validValue(value) {
		return ErrInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ticket, err := m.driver.Write(ctx, value)
	if ticket == 0 {
		if err == nil {
			return ErrUnavailable
		}
		return err
	}
	if m.timer != nil {
		m.timer.Stop()
	}
	m.generation++
	m.ticket = ticket
	// Cancellation after a native write still owns a cleanup obligation.
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		clearErr := m.driver.Clear(cleanup, ticket)
		cancel()
		if clearErr == nil {
			m.ticket = 0
		} else {
			m.schedule(time.Second)
		}
		return errors.Join(err, clearErr)
	}
	m.schedule(ttl)
	return nil
}
func (m *Manager) schedule(delay time.Duration) {
	generation := m.generation
	m.timer = m.after(delay, func() { m.expire(generation) })
}
func (m *Manager) expire(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ticket == 0 || generation != m.generation {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.driver.Clear(ctx, m.ticket); err != nil {
		m.schedule(time.Second)
		return
	}
	m.ticket = 0
	m.timer = nil
}

// Close rejects new copies even if native cleanup needs a later Close retry.
// Never dispose the driver while an owned value still requires clearing.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	if m.ticket != 0 {
		if err := m.driver.Clear(ctx, m.ticket); err != nil {
			return err
		}
		m.ticket = 0
	}
	return m.driver.Close()
}
