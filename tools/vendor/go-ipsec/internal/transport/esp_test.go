package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeRaw struct {
	*blockingPacketConn
	reads int
	block bool
	fail  bool
}

func (f *fakeRaw) ReadFromIP(p []byte) (int, *net.IPAddr, error) {
	if f.block {
		_, _, err := f.ReadFrom(p)
		return 0, nil, err
	}
	if f.fail {
		return 0, nil, errors.New("closed")
	}
	f.reads++
	ip := net.IPv4(192, 0, 2, 1)
	if f.reads == 1 {
		ip = net.IPv4(192, 0, 2, 2)
	}
	copy(p, []byte{1, 2, 3})
	return 3, &net.IPAddr{IP: ip}, nil
}
func (f *fakeRaw) WriteToIP(p []byte, a *net.IPAddr) (int, error) {
	if f.block {
		return f.WriteTo(p, a)
	}
	if f.fail {
		return 0, errors.New("closed")
	}
	return len(p), nil
}
func TestRawESPTransport(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
		socket := &fakeRaw{blockingPacketConn: newBlockingPacketConn()}
		c, err := dialESP(context.Background(), &net.UDPAddr{IP: net.ParseIP(host), Port: 500}, func(network string) (rawSocket, error) {
			want := "ip4:50"
			if host == "2001:db8::1" {
				want = "ip6:50"
			}
			if network != want {
				t.Fatal("wrong ESP protocol")
			}
			return socket, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.RemoteAddr().String() != host {
			t.Fatal("wrong peer")
		}
		_ = c.LocalAddr()
		if err = c.Send(context.Background(), []byte{1}); err != nil {
			t.Fatal(err)
		}
		if host == "192.0.2.1" {
			packet, err := c.Recv(context.Background())
			if err != nil || len(packet) != 3 || socket.reads != 2 {
				t.Fatal("source filtering failed", err)
			}
		}
		socket.fail = true
		if c.Send(context.Background(), nil) == nil {
			t.Fatal("write error ignored")
		}
		if _, err = c.Recv(context.Background()); err == nil {
			t.Fatal("read error ignored")
		}
		c.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialESP(ctx, &net.UDPAddr{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := dialESP(context.Background(), &net.IPAddr{}, nil); err == nil {
		t.Fatal("bad peer accepted")
	}
	if _, err := dialESP(context.Background(), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 500}, func(string) (rawSocket, error) { return nil, errors.New("permission denied") }); err == nil {
		t.Fatal("privilege error ignored")
	}
}
func TestRawESPCancellation(t *testing.T) {
	for _, write := range []bool{false, true} {
		socket := &fakeRaw{blockingPacketConn: newBlockingPacketConn(), block: true}
		r := &rawESP{pc: socket, peer: &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}, buf: make([]byte, 100)}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			if write {
				done <- r.Send(ctx, []byte{1})
			} else {
				_, err := r.Recv(ctx)
				done <- err
			}
		}()
		if write {
			<-socket.writeEntered
		} else {
			<-socket.readEntered
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("raw socket blocked shutdown")
		}
		if r.Send(ctx, nil) == nil {
			t.Fatal("cancelled write accepted")
		}
		if _, err := r.Recv(ctx); err == nil {
			t.Fatal("cancelled read accepted")
		}
	}
}
