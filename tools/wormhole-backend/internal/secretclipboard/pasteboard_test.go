package secretclipboard

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPasteboardBorrowingValidationAndLifecycle(t *testing.T) {
	writes, clears, closes := 0, 0, 0
	var copied []byte
	d := &pasteboardDriver{ops: pasteboardOps{
		write: func(value []byte) (Ticket, error) { writes++; copied = bytes.Clone(value); return 8, nil },
		erase: func(ticket Ticket) error {
			clears++
			if ticket != 8 {
				t.Fatal("ticket changed")
			}
			return nil
		},
		close: func() error { closes++; return nil },
	}}
	ctx := context.Background()
	for _, value := range [][]byte{nil, {}, []byte("a\x00b"), {255}, bytes.Repeat([]byte{'x'}, 16385)} {
		if _, err := d.Write(ctx, value); err != ErrInput {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := d.Write(cancelled, []byte("x")); err != context.Canceled {
		t.Fatal(err)
	}
	if err := d.Clear(cancelled, 8); err != context.Canceled {
		t.Fatal(err)
	}
	if err := d.Clear(ctx, 0); err != nil || clears != 0 {
		t.Fatal(err)
	}
	value := bytes.Repeat([]byte("é"), 8192)
	ticket, err := d.Write(ctx, value)
	if err != nil || ticket != 8 || !bytes.Equal(copied, value) || writes != 1 {
		t.Fatal("copy", err)
	}
	if err = d.Clear(ctx, ticket); err != nil || clears != 1 {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil || closes != 1 {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil || closes != 1 {
		t.Fatal("duplicate close", err)
	}
	if _, err = d.Write(ctx, []byte("x")); err != ErrClosed {
		t.Fatal(err)
	}
	if err = d.Clear(ctx, ticket); err != ErrClosed {
		t.Fatal(err)
	}
}
func TestPasteboardPartialWriteCancellationAndCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleared := false
	d := &pasteboardDriver{ops: pasteboardOps{
		write: func([]byte) (Ticket, error) { cancel(); return 9, nil },
		erase: func(ticket Ticket) error {
			if ticket != 9 {
				t.Fatal("lost ticket")
			}
			cleared = true
			return nil
		},
		close: func() error { return ErrUnavailable },
	}}
	m := New(d)
	if err := m.Copy(ctx, []byte("synthetic"), 20*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !cleared {
		t.Fatal("cancelled publication survived")
	}
	if err := m.Close(context.Background()); err != ErrUnavailable {
		t.Fatal("release error", err)
	}
	d = &pasteboardDriver{ops: pasteboardOps{
		write: func([]byte) (Ticket, error) { return 9, ErrUnavailable },
		erase: func(Ticket) error { return ErrUnavailable },
		close: func() error { return nil },
	}}
	ticket, err := d.Write(context.Background(), []byte("x"))
	if ticket != 9 || err != ErrUnavailable {
		t.Fatal("partial obligation lost", err)
	}
	if err = d.Clear(context.Background(), ticket); err != ErrUnavailable {
		t.Fatal(err)
	}
	d.Close()
}
func TestPasteboardCallsSerializeAgainstClose(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	d := &pasteboardDriver{ops: pasteboardOps{write: func([]byte) (Ticket, error) { close(started); <-resume; return 1, nil }, erase: func(Ticket) error { return nil }, close: func() error { return nil }}}
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		if _, err := d.Write(context.Background(), []byte("x")); err != nil {
			t.Error(err)
		}
	}()
	<-started
	group.Add(1)
	go func() { defer group.Done(); d.Close() }()
	close(resume)
	group.Wait()
	if _, err := d.Write(context.Background(), []byte("x")); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestPasteboardNativeErrorMapping(t *testing.T) {
	if pasteboardError(0) != nil {
		t.Fatal("success mapping")
	}
	for _, code := range []int{-1, 1, 7} {
		if pasteboardError(code) != ErrUnavailable {
			t.Fatal("native diagnostic escaped")
		}
	}
}
