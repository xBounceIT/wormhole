package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// DialESP opens IP protocol 50, independently of the UDP IKE control socket.
// Operating systems require an elevated token or CAP_NET_RAW for this socket.
// A permission failure is returned; it never changes the selected transport.
func DialESP(ctx context.Context, remote net.Addr) (Conn, error) {
	return dialESP(ctx, remote, func(network string) (rawSocket, error) { return net.ListenIP(network, nil) })
}

type rawSocket interface {
	ReadFromIP([]byte) (int, *net.IPAddr, error)
	WriteToIP([]byte, *net.IPAddr) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

func dialESP(ctx context.Context, remote net.Addr, listen func(string) (rawSocket, error)) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return nil, errors.New("invalid ESP peer")
	}
	peer, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("could not resolve ESP peer")
	}
	network := "ip4:50"
	if peer.IP.To4() == nil {
		network = "ip6:50"
	}
	pc, err := listen(network)
	if err != nil {
		return nil, errors.New("raw ESP requires administrator/root privileges or CAP_NET_RAW")
	}
	return &rawESP{pc: pc, peer: peer, buf: make([]byte, maxDatagram)}, nil
}

type rawESP struct {
	pc     rawSocket
	peer   *net.IPAddr
	buf    []byte
	sendMu sync.Mutex
}

func (r *rawESP) LocalAddr() net.Addr  { return r.pc.LocalAddr() }
func (r *rawESP) RemoteAddr() net.Addr { return r.peer }
func (r *rawESP) Close() error         { return r.pc.Close() }
func (r *rawESP) Send(ctx context.Context, p []byte) error {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	_ = r.pc.SetWriteDeadline(deadline)
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = r.pc.SetWriteDeadline(time.Unix(1, 0)); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	_, err := r.pc.WriteToIP(p, r.peer)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func (r *rawESP) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = r.pc.SetReadDeadline(deadline)
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = r.pc.SetReadDeadline(time.Unix(1, 0)); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	for {
		n, peer, err := r.pc.ReadFromIP(r.buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if peer.IP.Equal(r.peer.IP) {
			return r.buf[:n], nil
		}
	}
}
