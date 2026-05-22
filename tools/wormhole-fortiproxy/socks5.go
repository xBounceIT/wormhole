package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// handleSocks5 implements the minimum RFC 1928 surface the .NET Socks5Client speaks: no-auth
// only, CONNECT command, DOMAINNAME / IPv4 / IPv6 address types. Lifted from
// tools/wormhole-wgproxy with no behavioral changes — the parent's Socks5Client doesn't care
// which sidecar served the request.
func handleSocks5(ctx context.Context, c net.Conn, dial dialer) {
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

	_ = c.SetDeadline(time.Time{})

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := dial.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	cancelDial()
	if err != nil {
		logf("dial %s:%d failed: %v", host, port, err)
		writeReply(c, 0x04)
		return
	}
	defer upstream.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	pump(ctx, c, upstream)
}

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
