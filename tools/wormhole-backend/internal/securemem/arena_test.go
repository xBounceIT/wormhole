package securemem

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestNativeBufferLifecycle(t *testing.T) {
	b, err := New(32, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.With(func(data []byte) error {
		if !bytes.Equal(data, make([]byte, 32)) {
			t.Fatal("allocation not zeroed")
		}
		copy(data, []byte("test key"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.With(func(data []byte) error {
		if string(data[:8]) != "test key" {
			t.Fatal("key lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("callback error")
	if b.With(func([]byte) error { return sentinel }) != sentinel {
		t.Fatal("error lost")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if b.Locked() {
		t.Fatal("closed buffer reports locked")
	}
	if b.With(func([]byte) error { t.Fatal("closed buffer accessible"); return nil }) != ErrClosed {
		t.Fatal("closed access accepted")
	}
	if err := b.Close(); err != nil {
		t.Fatal("close not idempotent")
	}
}

func TestRequiredLockAndBounds(t *testing.T) {
	for _, size := range []int{-1, 0, MaxBytes + 1} {
		if _, err := New(size, false); err != ErrSize {
			t.Fatal("invalid size accepted")
		}
	}
	b, err := New(32, true)
	if err == ErrUnavailable {
		t.Log("host refused locked pages; strict allocation correctly refused")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Locked() {
		t.Fatal("strict allocation returned unlocked memory")
	}
}

func TestLargeNativeAllocation(t *testing.T) {
	b, err := New(MaxBytes, true)
	if err == ErrUnavailable {
		t.Log("host correctly refused a large required lock")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Locked() {
		t.Fatal("large allocation was not locked")
	}
	if err := b.With(func(data []byte) error { data[len(data)-1] = 1; return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestUseAndCloseAreSerialized(t *testing.T) {
	b, err := New(32, false)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			err := b.With(func(data []byte) error { data[0]++; return nil })
			if err != nil && err != ErrClosed {
				t.Error(err)
			}
		})
	}
	wg.Go(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
}

func TestWipePrecedesReleaseAndFailedReleaseCanRetry(t *testing.T) {
	b, err := New(32, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.With(func(data []byte) error {
		for i := range data {
			data[i] = 0xff
		}
		return nil
	})
	if err := b.closeWith(func(data []byte, locked bool) error {
		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("release received unwiped memory")
		}
		return errors.New("release failed")
	}); err != ErrUnavailable {
		t.Fatal("failed release not reported")
	}
	if b.Locked() {
		t.Error("failed close still reports usable locked memory")
	}
	if err := b.With(func([]byte) error { return nil }); err != ErrClosed {
		t.Error("failed close still accepts new key material")
	}
	if err := b.Close(); err != nil {
		t.Fatal("release retry failed")
	}
}

func TestAllocationFailureAndRequiredLockFailClosed(t *testing.T) {
	buffer, err := newBuffer(32, true, func(int) ([]byte, bool, error) { return nil, false, errors.New("allocation denied") }, func([]byte, bool) error { t.Fatal("release after failed allocation"); return nil })
	if buffer != nil || err != ErrUnavailable {
		t.Fatal("allocation failure was not closed")
	}
	released := false
	buffer, err = newBuffer(32, true, func(int) ([]byte, bool, error) { return bytes.Repeat([]byte{0xff}, 32), false, nil }, func(data []byte, locked bool) error {
		released = true
		if locked || !bytes.Equal(data, make([]byte, 32)) {
			t.Fatal("refused pages were not wiped before release")
		}
		return nil
	})
	if buffer != nil || err != ErrUnavailable || !released {
		t.Fatal("required lock silently degraded")
	}
}
