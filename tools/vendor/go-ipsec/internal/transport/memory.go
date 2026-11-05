package transport

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
)

// MemoryPair returns two Conns wired back-to-back in memory. A datagram sent on
// one side is delivered whole on the other. Used by the offline session tests
// (scripted responder) — no sockets, fully deterministic.
func MemoryPair() (Conn, Conn) {
	a := newMemoryConn("memA", "memB")
	b := newMemoryConn("memB", "memA")
	a.peer, b.peer = b, a
	return a, b
}

type memoryConn struct {
	local, remote string
	peer          *memoryConn
	q             chan []byte
	closeOnce     sync.Once
	closed        atomic.Bool
	done          chan struct{}
}

func newMemoryConn(local, remote string) *memoryConn {
	return &memoryConn{
		local:  local,
		remote: remote,
		q:      make(chan []byte, 256),
		done:   make(chan struct{}),
	}
}

func (m *memoryConn) Send(ctx context.Context, p []byte) error {
	if m.closed.Load() || m.peer.closed.Load() {
		return ErrClosed
	}
	out := append([]byte(nil), p...)
	select {
	case m.peer.q <- out:
		return nil
	case <-m.peer.done:
		return ErrClosed
	case <-m.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *memoryConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case p, ok := <-m.q:
		if !ok {
			return nil, ErrClosed
		}
		return p, nil
	case <-m.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *memoryConn) LocalAddr() net.Addr  { return memAddr(m.local) }
func (m *memoryConn) RemoteAddr() net.Addr { return memAddr(m.remote) }

func (m *memoryConn) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.done)
	})
	return nil
}

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }
