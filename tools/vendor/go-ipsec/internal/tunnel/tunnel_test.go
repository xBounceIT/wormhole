package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	tun2net "github.com/n0madic/go-tun2net"
)

func testSA(t *testing.T) *esp.SA {
	t.Helper()
	encr := bytes.Repeat([]byte{0x01}, 32)
	integ := bytes.Repeat([]byte{0x02}, 32)
	sa, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 0x1111, 0x2222, encr, integ, encr, integ, 64)
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

// TestWriteUnblocksOnClose: a Write blocked inside the transport send must be
// interrupted by Tunnel.Close. Before the fix Write passed
// context.Background() to the send func, so Close (checked only at Write
// entry) could never reach a send already blocked on backpressure and the
// netstack's writer goroutine leaked.
func TestWriteUnblocksOnClose(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	send := func(ctx context.Context, pkt []byte) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	tun := New(testSA(t), send, tun2net.TunConfig{})

	errCh := make(chan error, 1)
	go func() {
		_, err := tun.TunnelConn().Write([]byte{0x45, 0, 0, 20})
		errCh <- err
	}()

	<-entered // Write is now blocked inside send
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not unblock on Close")
	}
}

// TestWriteAfterClose: Write on a closed tunnel conn fails fast with
// net.ErrClosed and never reaches the send func.
func TestWriteAfterClose(t *testing.T) {
	t.Parallel()
	send := func(ctx context.Context, pkt []byte) error {
		t.Error("send func called after Close")
		return nil
	}
	tun := New(testSA(t), send, tun2net.TunConfig{})
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := tun.TunnelConn().Write([]byte{0x45}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
}

// TestWriteSendError: a non-shutdown send failure propagates to the caller.
func TestWriteSendError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("wire broke")
	send := func(ctx context.Context, pkt []byte) error { return sentinel }
	tun := New(testSA(t), send, tun2net.TunConfig{})
	defer tun.Close()
	if _, err := tun.TunnelConn().Write([]byte{0x45}); !errors.Is(err, sentinel) {
		t.Fatalf("Write = %v, want %v", err, sentinel)
	}
}
