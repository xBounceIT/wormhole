// Package securemem owns native, non-Go-heap buffers for long-lived vault keys.
// Buffers are explicitly closed, never returned as strings, and never serialized.
package securemem

import (
	"errors"
	"runtime"
	"sync"
)

var (
	ErrSize        = errors.New("securemem_invalid_size")
	ErrClosed      = errors.New("securemem_closed")
	ErrUnavailable = errors.New("securemem_lock_unavailable")
)

const MaxBytes = 1024 * 1024

type Buffer struct {
	mu      sync.Mutex
	data    []byte
	locked  bool
	retired bool
}

// New refuses unlocked memory when required (Hardened and above). A successful
// optional allocation must still be checked with Locked to display a warning.
func New(size int, requireLocked bool) (*Buffer, error) {
	return newBuffer(size, requireLocked, allocate, release)
}

func newBuffer(size int, requireLocked bool, alloc func(int) ([]byte, bool, error), free func([]byte, bool) error) (*Buffer, error) {
	if size <= 0 || size > MaxBytes {
		return nil, ErrSize
	}
	data, locked, err := alloc(size)
	if err != nil {
		return nil, ErrUnavailable
	}
	if requireLocked && !locked {
		clear(data)
		_ = free(data, false)
		return nil, ErrUnavailable
	}
	return &Buffer{data: data, locked: locked}, nil
}

func (b *Buffer) Locked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.retired && b.data != nil && b.locked
}

// With serializes use against Close. The callback must not retain the slice,
// create a string from it, or recursively call another method on this buffer.
func (b *Buffer) With(use func([]byte) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired || b.data == nil {
		return ErrClosed
	}
	return use(b.data)
}

func (b *Buffer) Close() error {
	return b.closeWith(release)
}

func (b *Buffer) closeWith(free func([]byte, bool) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Native release can unlock pages and then fail to unmap them. Retain the
	// allocation only for a cleanup retry, never for storing another key.
	b.retired = true
	if b.data == nil {
		return nil
	}
	clear(b.data)
	runtime.KeepAlive(b.data)
	err := free(b.data, b.locked)
	if err != nil {
		return ErrUnavailable
	}
	b.data = nil
	b.locked = false
	return nil
}
