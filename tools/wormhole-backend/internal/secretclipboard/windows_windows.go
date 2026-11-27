package secretclipboard

import (
	"context"
	"runtime"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// Windows owns the clipboard from a private message-only window. Every call and
// message dispatch stays on its creating OS thread. Requests are synchronous:
// cancellation cannot return borrowed plaintext while the worker still uses it.
type windowsClipboard interface {
	initialize() error
	pump()
	destroy()
	open() bool
	close()
	empty() bool
	sequence() Ticket
	owned() bool
	set(uint32, []byte) bool
	formats() []uint32
}
type windowsRequest struct {
	ctx    context.Context
	value  []byte
	ticket Ticket
	stop   bool
	reply  chan windowsReply
}
type windowsReply struct {
	ticket Ticket
	err    error
}
type windowsDriver struct {
	requests  chan windowsRequest
	done      chan struct{}
	closeOnce sync.Once
}

func newWindowsDriver(api windowsClipboard) (*windowsDriver, error) {
	d := &windowsDriver{requests: make(chan windowsRequest), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(d.done)
		if err := api.initialize(); err != nil {
			ready <- err
			return
		}
		defer api.destroy()
		ready <- nil
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case request := <-d.requests:
				if request.stop {
					return
				}
				result := windowsReply{}
				if request.value != nil {
					result.ticket, result.err = windowsWrite(request.ctx, api, request.value)
				} else {
					result.err = windowsClear(request.ctx, api, request.ticket)
				}
				request.reply <- result
			case <-tick.C:
				api.pump()
			}
		}
	}()
	if err := <-ready; err != nil {
		<-d.done
		return nil, err
	}
	return d, nil
}
func (d *windowsDriver) request(request windowsRequest) (Ticket, error) {
	request.reply = make(chan windowsReply, 1)
	select {
	case <-d.done:
		return 0, ErrClosed
	case <-request.ctx.Done():
		return 0, request.ctx.Err()
	case d.requests <- request:
	}
	result := <-request.reply
	return result.ticket, result.err
}
func (d *windowsDriver) Write(ctx context.Context, value []byte) (Ticket, error) {
	if !validValue(value) {
		return 0, ErrInput
	}
	return d.request(windowsRequest{ctx: ctx, value: value})
}
func (d *windowsDriver) Clear(ctx context.Context, ticket Ticket) error {
	_, err := d.request(windowsRequest{ctx: ctx, ticket: ticket})
	return err
}
func (d *windowsDriver) Close() error {
	d.closeOnce.Do(func() {
		select {
		case d.requests <- windowsRequest{stop: true}:
		case <-d.done:
		}
	})
	<-d.done
	return nil
}
func windowsOpen(ctx context.Context, api windowsClipboard) error {
	// Contention is temporary, but must never stall lock or shutdown indefinitely.
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		if err := bounded.Err(); err != nil {
			return err
		}
		if api.open() {
			return nil
		}
		api.pump()
		select {
		case <-bounded.Done():
			return bounded.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func windowsWrite(ctx context.Context, api windowsClipboard, value []byte) (Ticket, error) {
	text := make([]byte, 0, 2*(len(value)+1))
	defer func() { vault.Wipe(text) }()
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		value = value[size:]
		if r <= 0xffff {
			text = append(text, byte(r), byte(r>>8))
		} else {
			hi, lo := utf16.EncodeRune(r)
			text = append(text, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	text = append(text, 0, 0)
	if err := windowsOpen(ctx, api); err != nil {
		return 0, err
	}
	defer api.close()
	if !api.empty() {
		return 0, ErrUnavailable
	}
	// Exclusion markers precede text while OpenClipboard excludes other writers.
	for _, format := range api.formats() {
		if !api.set(format, []byte{0, 0, 0, 0}) {
			return 0, ErrUnavailable
		}
	}
	if !api.set(13, text) {
		return 0, ErrUnavailable
	} // CF_UNICODETEXT
	return windowsTicket(api), nil
}
func windowsClear(ctx context.Context, api windowsClipboard, ticket Ticket) error {
	if ticket == 0 {
		return nil
	}
	if err := windowsOpen(ctx, api); err != nil {
		return err
	}
	defer api.close()
	// Compare under the same OS lock as EmptyClipboard, not before acquiring it.
	if !api.owned() || windowsTicket(api) != ticket {
		return nil
	}
	if !api.empty() {
		return ErrUnavailable
	}
	return nil
}

// Reserve a nonzero ticket even when the DWORD sequence wraps through zero.
// Clear additionally requires our private window to still own the clipboard.
func windowsTicket(api windowsClipboard) Ticket { return (1 << 32) | api.sequence() }
