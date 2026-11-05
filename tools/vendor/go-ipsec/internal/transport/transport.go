// Package transport is the wire-level datagram seam beneath the IKE/ESP
// session. A Conn is a single-peer datagram channel: one Send is one datagram
// to the server, one Recv is one datagram from it. The IKE/ESP demux and NAT-T
// framing live above this layer (see internal/natt and the session driver).
package transport

import (
	"context"
	"errors"
	"net"
)

// ErrClosed is returned by Send/Recv after Close.
var ErrClosed = errors.New("transport: closed")

// Conn is a datagram channel bound to one remote peer.
type Conn interface {
	// Send transmits one datagram to the bound peer.
	Send(ctx context.Context, p []byte) error
	// Recv returns the next datagram from the bound peer. The returned slice
	// is owned by the caller until the next Recv on this conn.
	Recv(ctx context.Context) ([]byte, error)
	// LocalAddr / RemoteAddr report the socket endpoints.
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	// Close releases the underlying socket.
	Close() error
}

// DialFunc opens a packet socket for the given network/address. It mirrors the
// public ipsec.PacketDialer.DialPacket so callers can inject a custom socket
// (e.g. a mihomo dialer); a nil DialFunc means "use the host UDP stack".
type DialFunc func(ctx context.Context, network, addr string) (net.PacketConn, error)

// PortMigrator is implemented by Conns that can switch the remote port in place
// (UDP), used to move IKE/ESP onto the NAT-T port 4500.
type PortMigrator interface {
	MigrateToPort(port int)
}
