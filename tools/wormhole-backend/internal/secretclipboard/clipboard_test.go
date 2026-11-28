package secretclipboard

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeDriver struct {
	next                   Ticket
	current                Ticket
	writes, clears, closes int
	failWrite, failClear   bool
	noTicket               bool
	cancel                 context.CancelFunc
}

func (d *fakeDriver) Write(_ context.Context, value []byte) (Ticket, error) {
	d.writes++
	if d.noTicket {
		if d.failWrite {
			return 0, ErrUnavailable
		}
		return 0, nil
	}
	d.next++
	d.current = d.next
	if d.cancel != nil {
		d.cancel()
	}
	if d.failWrite {
		return d.current, ErrUnavailable
	}
	return d.current, nil
}
func (d *fakeDriver) Clear(ctx context.Context, ticket Ticket) error {
	d.clears++
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.failClear {
		return ErrUnavailable
	}
	if d.current == ticket {
		d.current = 0
	}
	return nil
}
func (d *fakeDriver) Close() error { d.closes++; return nil }

type fakeTimer struct {
	stopped bool
	fire    func()
	delay   time.Duration
}

func (t *fakeTimer) Stop() bool { was := t.stopped; t.stopped = true; return !was }
func fixture() (*Manager, *fakeDriver, *[]*fakeTimer) {
	d := &fakeDriver{}
	m := New(d)
	timers := []*fakeTimer{}
	m.after = func(delay time.Duration, fire func()) timer {
		t := &fakeTimer{fire: fire, delay: delay}
		timers = append(timers, t)
		return t
	}
	return m, d, &timers
}
func TestClipboardLifecycleAndOwnership(t *testing.T) {
	m, d, timers := fixture()
	ctx := context.Background()
	value := []byte("synthetic password")
	original := bytes.Clone(value)
	if err := m.Copy(ctx, value, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, original) || (*timers)[0].delay != 30*time.Second {
		t.Fatal("borrow or TTL")
	}
	first := (*timers)[0]
	if err := m.Copy(ctx, value, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if !first.stopped || (*timers)[1].delay != 20*time.Second {
		t.Fatal("replace")
	}
	first.fire()
	if d.clears != 0 || d.current != 2 {
		t.Fatal("stale timer cleared replacement")
	}
	d.current = 99
	(*timers)[1].fire()
	if d.current != 99 || m.ticket != 0 {
		t.Fatal("external content cleared")
	}
	if err := m.Copy(ctx, value, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	(*timers)[2].fire()
	if d.current != 0 || m.ticket != 0 {
		t.Fatal("expiry")
	}
	if err := m.Copy(ctx, value, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if d.current != 0 || d.closes != 1 {
		t.Fatal("close")
	}
	(*timers)[3].fire()
	if err := m.Copy(ctx, value, 20*time.Second); err != ErrClosed {
		t.Fatal(err)
	}
}
func TestClipboardInvalidAndCancelled(t *testing.T) {
	m, d, _ := fixture()
	for _, value := range [][]byte{nil, {}, {255}, []byte("a\x00b"), make([]byte, 16385)} {
		if err := m.Copy(context.Background(), value, 20*time.Second); err != ErrInput {
			t.Fatal(err)
		}
	}
	for _, ttl := range []time.Duration{0, time.Second, 19 * time.Second, 21 * time.Second, 31 * time.Second} {
		if err := m.Copy(context.Background(), []byte("x"), ttl); err != ErrInput {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Copy(ctx, []byte("x"), 20*time.Second); err != context.Canceled {
		t.Fatal(err)
	}
	if d.writes != 0 {
		t.Fatal("invalid input wrote")
	}
}
func TestClipboardFailuresRetainOnlyCleanupTicket(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"no-ticket", "write-error", "partial", "cancelled", "retry"} {
		t.Run(mode, func(t *testing.T) {
			m, d, timers := fixture()
			copyCtx := ctx
			switch mode {
			case "no-ticket":
				d.noTicket = true
			case "write-error":
				d.noTicket = true
				d.failWrite = true
			case "partial":
				d.failWrite = true
				d.failClear = true
			case "cancelled":
				var cancel context.CancelFunc
				copyCtx, cancel = context.WithCancel(ctx)
				d.cancel = cancel
			case "retry":
				d.failClear = true
			}
			err := m.Copy(copyCtx, []byte("x"), 20*time.Second)
			if mode == "retry" {
				if err != nil {
					t.Fatal(err)
				}
				(*timers)[0].fire()
				if (*timers)[1].delay != time.Second || m.ticket == 0 {
					t.Fatal("expiry cleanup lost")
				}
			} else if err == nil {
				t.Fatal("failure acknowledged")
			}
			if mode == "partial" {
				if len(*timers) != 1 || m.ticket == 0 {
					t.Fatal("partial cleanup lost")
				}
			}
			if mode == "partial" || mode == "retry" {
				if err := m.Close(ctx); !errors.Is(err, ErrUnavailable) || d.closes != 0 {
					t.Fatal("closed with uncleared data", err)
				}
				d.failClear = false
				if err := m.Close(ctx); err != nil {
					t.Fatal(err)
				}
			} else if m.ticket != 0 {
				t.Fatal("failed copy retained ownership")
			}
		})
	}
}
func TestClipboardSerializesCopyExpiryAndClose(t *testing.T) {
	m, d, _ := fixture()
	ctx := context.Background()
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			err := m.Copy(ctx, []byte("x"), 20*time.Second)
			if err != nil && err != ErrClosed {
				t.Error(err)
			}
			m.expire(1)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	group.Wait()
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if d.current != 0 {
		t.Fatal("leaked clipboard")
	}
}
