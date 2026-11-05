package transport

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// blockingPacketConn is a net.PacketConn whose WriteTo/ReadFrom block until a
// past deadline is installed, emulating a custom PacketDialer transport under
// backpressure (a plain UDP socket write effectively never blocks, so the
// cancellation path cannot be exercised against the real host stack).
type blockingPacketConn struct {
	writeEntered chan struct{} // closed once WriteTo is blocked
	readEntered  chan struct{} // closed once ReadFrom is blocked

	mu          sync.Mutex
	writeExpire chan struct{}
	readExpire  chan struct{}

	enterWriteOnce sync.Once
	enterReadOnce  sync.Once
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{
		writeEntered: make(chan struct{}),
		readEntered:  make(chan struct{}),
		writeExpire:  make(chan struct{}),
		readExpire:   make(chan struct{}),
	}
}

func (c *blockingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.enterWriteOnce.Do(func() { close(c.writeEntered) })
	c.mu.Lock()
	expire := c.writeExpire
	c.mu.Unlock()
	<-expire
	return 0, os.ErrDeadlineExceeded
}

func (c *blockingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.enterReadOnce.Do(func() { close(c.readEntered) })
	c.mu.Lock()
	expire := c.readExpire
	c.mu.Unlock()
	<-expire
	return 0, nil, os.ErrDeadlineExceeded
}

// expireIfPast closes ch when t is a past (non-zero) deadline, mimicking the
// net poller waking a blocked I/O call with ErrDeadlineExceeded.
func expireIfPast(t time.Time, ch chan struct{}) chan struct{} {
	if !t.IsZero() && !t.After(time.Now()) {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	return ch
}

func (c *blockingPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeExpire = expireIfPast(t, c.writeExpire)
	return nil
}

func (c *blockingPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readExpire = expireIfPast(t, c.readExpire)
	return nil
}

func (c *blockingPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *blockingPacketConn) Close() error { return nil }
func (c *blockingPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500}
}

func dialBlocking(t *testing.T) (Conn, *blockingPacketConn) {
	t.Helper()
	pc := newBlockingPacketConn()
	dial := func(ctx context.Context, network, addr string) (net.PacketConn, error) {
		return pc, nil
	}
	conn, err := DialUDP(context.Background(), dial, "udp", "127.0.0.1:500")
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	return conn, pc
}

// TestSendUnblocksOnCancel: a Send blocked inside the transport write must be
// interrupted by plain context cancellation (no deadline on the ctx). Before
// the fix Send only honoured a ctx deadline, so a blocked no-deadline driver
// send could wedge Close() forever (Close waits for the workers before it
// closes the socket).
func TestSendUnblocksOnCancel(t *testing.T) {
	t.Parallel()
	conn, pc := dialBlocking(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- conn.Send(ctx, []byte("payload")) }()

	<-pc.writeEntered // Send is now blocked inside WriteTo
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Send returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not unblock on context cancellation")
	}
}

// TestSendHonorsDeadline: the pre-existing deadline path still works.
func TestSendHonorsDeadline(t *testing.T) {
	t.Parallel()
	conn, _ := dialBlocking(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- conn.Send(ctx, []byte("payload")) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Send succeeded, want deadline error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not unblock on ctx deadline")
	}
}

// TestRecvUnblocksOnCancel pins the same property for Recv (which already had
// the AfterFunc interruption).
func TestRecvUnblocksOnCancel(t *testing.T) {
	t.Parallel()
	conn, pc := dialBlocking(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Recv(ctx)
		errCh <- err
	}()

	<-pc.readEntered // Recv is now blocked inside ReadFrom
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Recv returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Recv did not unblock on context cancellation")
	}
}

// TestSendAfterClose: Send on a closed conn reports ErrClosed.
func TestSendAfterClose(t *testing.T) {
	t.Parallel()
	conn, _ := dialBlocking(t)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Send(context.Background(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Send after Close = %v, want ErrClosed", err)
	}
}
