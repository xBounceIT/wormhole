package ipsec

import (
	"context"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/tunnel"
	tun2net "github.com/n0madic/go-tun2net"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type failedControlSocket struct{}

func (failedControlSocket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.ErrUnexpectedEOF
}
func (failedControlSocket) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (failedControlSocket) Close() error                              { return nil }
func (failedControlSocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500}
}
func (failedControlSocket) SetDeadline(time.Time) error      { return nil }
func (failedControlSocket) SetReadDeadline(time.Time) error  { return nil }
func (failedControlSocket) SetWriteDeadline(time.Time) error { return nil }

func TestControlReceiveFailureNotifiesOwnerWithoutDPD(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "cancelled"}[cancelled], func(t *testing.T) {
			notified := make(chan struct{})
			var once sync.Once
			reconnect := false
			c := newClient(Config{Logger: discardLogger(), AutoReconnect: &reconnect, OnDead: func() { once.Do(func() { close(notified) }) }})
			defer c.Close()
			s := session.New(session.Config{Server: "127.0.0.1:500", DisableDPD: true, Dialer: func(context.Context, string, string) (net.PacketConn, error) { return failedControlSocket{}, nil }, RetransmitTries: 1})
			if err := s.IKESAInit(t.Context()); err == nil {
				t.Fatal("fixture receive did not fail")
			}
			c.session.Store(s)
			key := make([]byte, 32)
			sa, err := esp.NewSA(0, 1, 2, key, key, key, key, 64)
			if err != nil {
				t.Fatal(err)
			}
			c.tun = tunnel.New(sa, func(context.Context, []byte) error { return nil }, tun2net.TunConfig{MTU: 1400})
			if cancelled {
				c.superCancel()
			}
			c.startWorkers(s)
			if cancelled {
				c.mu.Lock()
				mgr := c.mgr
				c.mu.Unlock()
				mgr.Wait()
				select {
				case <-notified:
					t.Fatal("normal cancellation reported failure")
				default:
				}
				return
			}
			select {
			case <-notified:
			case <-time.After(time.Second):
				t.Fatal("fatal control receive left the VPN owner waiting with DPD disabled")
			}
		})
	}
}
