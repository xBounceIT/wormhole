package secretclipboard

import (
	"context"
	"sync"
)

// AppKit calls are synchronous and serialized. The platform adapter copies the
// borrowed bytes before returning and maps native failures to fixed errors.
type pasteboardOps struct {
	write func([]byte) (Ticket, error)
	erase func(Ticket) error
	close func() error
}
type pasteboardDriver struct {
	mu     sync.Mutex
	ops    pasteboardOps
	closed bool
}

func (d *pasteboardDriver) Write(ctx context.Context, value []byte) (Ticket, error) {
	if !validValue(value) {
		return 0, ErrInput
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return d.ops.write(value)
}
func (d *pasteboardDriver) Clear(ctx context.Context, ticket Ticket) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ticket == 0 {
		return nil
	}
	return d.ops.erase(ticket)
}
func (d *pasteboardDriver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.ops.close()
}

func pasteboardError(code int) error {
	if code != 0 {
		return ErrUnavailable
	}
	return nil
}
