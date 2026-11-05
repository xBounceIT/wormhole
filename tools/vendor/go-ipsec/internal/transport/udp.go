package transport

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

var (
	zeroTime     time.Time
	aLongTimeAgo = time.Unix(1, 0)
)

// maxDatagram bounds a single inbound UDP read. IKE messages and ESP packets
// over NAT-T are well under this; 65535 avoids ever truncating a server frame.
const maxDatagram = 65535

// udpConn is a Conn over a net.PacketConn bound to a single server address.
// The remote address is swappable to support NAT-T port migration (:500→:4500).
type udpConn struct {
	pc     net.PacketConn
	remote atomic.Pointer[net.UDPAddr]
	rbuf   []byte
	closed atomic.Bool
}

// MigrateToPort switches the remote endpoint to the same host on a new port.
// Used to move IKE/ESP onto the NAT-T port 4500 after NAT detection.
func (u *udpConn) MigrateToPort(port int) {
	old := u.remote.Load()
	next := &net.UDPAddr{IP: old.IP, Port: port, Zone: old.Zone}
	u.remote.Store(next)
}

// DialUDP resolves serverAddr and opens a datagram socket to it. When dial is
// nil a host UDP socket is used. network is typically "udp".
func DialUDP(ctx context.Context, dial DialFunc, network, serverAddr string) (Conn, error) {
	remote, err := net.ResolveUDPAddr(network, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve %q: %w", serverAddr, err)
	}
	var pc net.PacketConn
	if dial != nil {
		pc, err = dial(ctx, network, serverAddr)
	} else {
		pc, err = net.ListenUDP(network, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("transport: dial %q: %w", serverAddr, err)
	}
	u := &udpConn{pc: pc, rbuf: make([]byte, maxDatagram)}
	u.remote.Store(remote)
	return u, nil
}

func (u *udpConn) Send(ctx context.Context, p []byte) error {
	if u.closed.Load() {
		return ErrClosed
	}
	// Mirror Recv's discipline: the top-of-Send deadline set is authoritative
	// (it also neutralises a leftover aLongTimeAgo from a prior Send's
	// cancellation AfterFunc), and the AfterFunc interrupts a blocked write on
	// plain cancellation. Without it a no-deadline driver send over a blocking
	// transport (e.g. a custom PacketDialer under backpressure) could never
	// observe shutdown: Close() waits for the workers before it closes the
	// socket, and the worker would be stuck inside WriteTo forever.
	if dl, ok := ctx.Deadline(); ok {
		_ = u.pc.SetWriteDeadline(dl)
	} else {
		_ = u.pc.SetWriteDeadline(zeroTime)
	}
	stop := context.AfterFunc(ctx, func() { _ = u.pc.SetWriteDeadline(aLongTimeAgo) })
	defer func() { _ = u.pc.SetWriteDeadline(zeroTime) }()
	defer stop()
	_, err := u.pc.WriteTo(p, u.remote.Load())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if u.closed.Load() {
			return ErrClosed
		}
	}
	return err
}

func (u *udpConn) Recv(ctx context.Context) ([]byte, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}
	// Set the read deadline at the top of every Recv: the ctx deadline when present,
	// otherwise an explicit clear. This is the authoritative reset — a prior Recv's
	// cancellation AfterFunc may have left the deadline at aLongTimeAgo (stop() does
	// not wait for an already-running AfterFunc, so the deferred clear below can race
	// it), and resetting here makes any such leftover harmless for this Recv.
	if dl, ok := ctx.Deadline(); ok {
		_ = u.pc.SetReadDeadline(dl)
	} else {
		_ = u.pc.SetReadDeadline(zeroTime)
	}
	// AfterFunc interrupts a blocked read on plain cancellation (e.g. a no-deadline
	// data-plane read at shutdown). The deferred clear keeps the common case tidy;
	// the top-of-Recv reset above is what guarantees correctness against the race.
	stop := context.AfterFunc(ctx, func() { _ = u.pc.SetReadDeadline(aLongTimeAgo) })
	defer func() { _ = u.pc.SetReadDeadline(zeroTime) }()
	defer stop()
	for {
		n, src, err := u.pc.ReadFrom(u.rbuf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if u.closed.Load() {
				return nil, ErrClosed
			}
			return nil, err
		}
		// Single-peer channel: ignore stray datagrams from other sources. The
		// host must match; the port may be the pre- or post-migration value so
		// in-flight replies from :500 are still accepted right after migration.
		if !sameHost(src, u.remote.Load()) {
			continue
		}
		return u.rbuf[:n], nil
	}
}

func (u *udpConn) LocalAddr() net.Addr  { return u.pc.LocalAddr() }
func (u *udpConn) RemoteAddr() net.Addr { return u.remote.Load() }

func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	return u.pc.Close()
}

// sameHost reports whether two addresses share the same host. The port is
// intentionally ignored so a server that migrates its source port between 500
// and 4500 during NAT-T is still recognised as the bound peer.
func sameHost(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.IP.Equal(ub.IP)
	}
	ah, _, _ := net.SplitHostPort(a.String())
	bh, _, _ := net.SplitHostPort(b.String())
	return ah == bh
}
