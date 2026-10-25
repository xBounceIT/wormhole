package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestForcepointCarriesTCPOverNativeFramesWithoutHostSockets(t *testing.T) {
	clientStack, clientEndpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1390)
	if err != nil {
		t.Fatal(err)
	}
	defer clientStack.Close()
	peerStack, peerEndpoint, err := newNetstack(netip.MustParseAddr("10.0.0.1"), 1390)
	if err != nil {
		t.Fatal(err)
	}
	defer peerStack.Close()
	listener, err := gonet.ListenTCP(peerStack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 1}), Port: 2345,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	client, peer := net.Pipe()
	defer peer.Close()
	sess := &forcepointSession{conn: client, cfg: fpTestConfig(), configured: true}
	sess.lastReply.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		runForcepoint(ctx, sess, clientEndpoint, 20*time.Millisecond)
		close(done)
	}()
	var bridge sync.WaitGroup
	var peerWriteMu sync.Mutex
	writePeer := func(op byte, payload []byte) error {
		peerWriteMu.Lock()
		defer peerWriteMu.Unlock()
		_, err := peer.Write(fpTestWire(op, payload))
		return err
	}
	heartbeats := make(chan struct{}, 1)
	bridge.Add(2)
	go func() {
		defer bridge.Done()
		for {
			op, payload, err := readForcepointFrame(peer)
			if err != nil {
				return
			}
			switch op {
			case fpIPv4:
				injectTunnelIPv4(peerEndpoint, payload)
			case fpHeartbeat:
				if err := writePeer(fpHeartbeatReply, payload); err != nil {
					return
				}
				select {
				case heartbeats <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		defer bridge.Done()
		for {
			packet := peerEndpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			err := writePeer(fpIPv4, view.AsSlice())
			view.Release()
			packet.DecRef()
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		cancel()
		_ = peer.Close()
		<-done
		bridge.Wait()
	}()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(conn, conn)
	}()
	dialer := newNetstackDialer(clientStack, netip.MustParseAddr("10.0.0.2"), nil)
	conn, err := dialer.DialContext(ctx, "tcp", "10.0.0.1:2345")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	message := []byte("Forcepoint framed TCP round trip")
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(message))
	if _, err := io.ReadFull(conn, received); err != nil || !bytes.Equal(message, received) {
		t.Fatal("TCP traffic did not cross the Forcepoint tunnel", err)
	}
	select {
	case <-heartbeats:
	case <-ctx.Done():
		t.Fatal("Forcepoint keepalive did not cross the transport")
	}
	if _, err := dialer.DialContext(ctx, "tcp", "internal.example.test:443"); err == nil {
		t.Fatal("missing VPN DNS must not fall back to the host resolver")
	}
}

func TestForcepointDeadPeerAndExpiredAuthenticationCloseTransport(t *testing.T) {
	for _, mode := range []string{"dead-peer", "expired", "auth-timeout", "bad-control", "write-failure"} {
		t.Run(mode, func(t *testing.T) {
			networkStack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1390)
			if err != nil {
				t.Fatal(err)
			}
			defer networkStack.Close()
			client, peer := net.Pipe()
			defer peer.Close()
			sess := &forcepointSession{conn: client, cfg: fpTestConfig(), configured: true}
			sess.lastReply.Store(time.Now().UnixNano())
			switch mode {
			case "expired":
				sess.expires.Store(time.Now().Add(-time.Second).UnixNano())
			case "auth-timeout":
				sess.paused.Store(true)
				sess.pauseSince.Store(time.Now().Add(-2 * fpAuthTimeout).UnixNano())
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				runForcepoint(ctx, sess, endpoint, 10*time.Millisecond)
				close(done)
			}()
			go func() {
				if mode == "bad-control" {
					_, _ = peer.Write(fpTestWire(0xff, nil))
				} else if mode == "write-failure" {
					_, _ = peer.Write(fpTestWire(fpHeartbeat, []byte{1, 2, 3, 4}))
					_ = peer.Close()
				} else {
					_, _ = io.Copy(io.Discard, peer) // silent peer never answers keepalives
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Forcepoint transport did not fail closed")
			}
			if sess.cfg.Password != "" {
				t.Fatal("session retained its credential after transport shutdown")
			}
		})
	}
}
