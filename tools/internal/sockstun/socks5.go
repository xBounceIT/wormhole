// Package sockstun is the SOCKS5 server the Wormhole VPN sidecars (wgproxy, ovpnproxy)
// expose on 127.0.0.1 for parent-process traffic. It implements the minimum RFC 1928
// surface the managed-side Socks5Client speaks: no-auth only, CONNECT command, IPv4 /
// IPv6 / DOMAINNAME address types. Anything else gets a polite error reply.
//
// The Dialer interface abstracts the destination — both sidecars wire it to a TUN-less
// userspace netstack (gVisor for wgproxy, OpenVPN3 + gVisor for ovpnproxy), so the same
// SOCKS5 loop serves traffic via either VPN. A trivial OS-socket Dialer is also exported
// so --mock test paths can exercise the SOCKS5 surface without bringing a VPN up.
package sockstun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Dialer is what the SOCKS5 loop uses to reach the requested target. Implementations
// route through whatever userspace stack the sidecar embeds.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// OSDialer dials via the OS resolver and sockets. Test-only / mock mode.
type OSDialer struct{}

func (OSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Logger is the minimal log surface sockstun needs. Both sidecars satisfy it with a
// fmt.Fprintln-to-stderr wrapper.
type Logger interface {
	Logf(format string, args ...any)
}

// Serve runs the SOCKS5 accept loop on ln until ctx is cancelled or ln is closed. Each
// inbound client is dispatched to a goroutine that handles handshake + CONNECT + bidi
// pump. Serve returns after all in-flight client goroutines exit; close ln to unblock
// the Accept call from another goroutine.
func Serve(ctx context.Context, ln net.Listener, dial Dialer, log Logger) error {
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			log.Logf("accept: %v", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handle(ctx, c, dial, log)
		}(c)
	}
	wg.Wait()
	return nil
}

// handle implements the minimum RFC 1928 surface the .NET Socks5Client speaks: no-auth
// only, CONNECT command, DOMAINNAME / IPv4 / IPv6 address types. Anything else gets a
// polite error reply. Mirrors the logic that used to live inline in wgproxy.
func handle(ctx context.Context, c net.Conn, dial Dialer, log Logger) {
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	n := int(hdr[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil {
		return
	}
	if reqHead[0] != 0x05 {
		return
	}
	if reqHead[1] != 0x01 {
		// only CONNECT supported
		writeReply(c, 0x07)
		return
	}

	var host string
	switch reqHead[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03: // DOMAINNAME
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		writeReply(c, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	// Clear deadline before long-lived stream.
	_ = c.SetDeadline(time.Time{})

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := dial.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	cancelDial()
	if err != nil {
		log.Logf("dial %s:%d failed: %v", host, port, err)
		// 0x04 host unreachable is a reasonable generic reply
		writeReply(c, 0x04)
		return
	}
	defer upstream.Close()

	// Success reply with BND.ADDR = 0.0.0.0:0 (we don't expose the bind address).
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	pump(ctx, c, upstream)
}

// pump bidirectionally copies between client and upstream. When one direction's Copy returns
// (EOF or error), half-close the corresponding peer write so the other Copy unblocks at EOF —
// avoids leaking a goroutine until the OS finally tears down a half-open connection. The
// 2-channel pattern (no WaitGroup, no bridge goroutine) keeps per-connection overhead at
// 2 goroutines instead of 3 — material under RDP-through-tunnel load with many sub-streams.
func pump(ctx context.Context, client, upstream net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	done := make(chan struct{}, 2)
	copy1 := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copy1(upstream, client)
	go copy1(client, upstream)

	select {
	case <-done:
	case <-ctx.Done():
		_ = client.Close()
		_ = upstream.Close()
		<-done
	}
	<-done
}

func writeReply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
