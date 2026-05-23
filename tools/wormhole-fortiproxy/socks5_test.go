package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn implements just enough of net.Conn for handleSocks5 — server reads from `in`,
// server writes to `out`. Read returns EOF after `in` is drained.
type fakeConn struct {
	in       *bytes.Buffer
	out      *bytes.Buffer
	deadline time.Time
}

func (c *fakeConn) Read(b []byte) (int, error)         { return c.in.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)        { return c.out.Write(b) }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// errDialer always errors — handleSocks5 should NEVER reach it on the IPv6 path because we
// reject the ATYP before dial. Test asserts on that.
type errDialer struct{ called bool }

func (d *errDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.called = true
	return nil, errors.New("should not be called for IPv6")
}

func TestHandleSocks5_RejectsIPv6Upfront(t *testing.T) {
	// SOCKS5 greeting: ver=5, nmethods=1, NO_AUTH. CONNECT request with IPv6 target ::1, port 80.
	in := bytes.NewBuffer([]byte{
		0x05, 0x01, 0x00, // greeting
		0x05, 0x01, 0x00, 0x04, // ver, cmd=CONNECT, rsv, atyp=IPv6
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ::1
		0x00, 0x50, // port 80
	})
	out := &bytes.Buffer{}
	c := &fakeConn{in: in, out: out}
	d := &errDialer{}

	handleSocks5(context.Background(), c, d)

	if d.called {
		t.Fatal("dialer should not be called for IPv6 — handler must reject at handshake")
	}
	// Expect: 0x05 0x00 (no-auth method ack), then 0x05 0x08 0x00 0x01 ... (rep=0x08
	// address-type-not-supported, then the canonical 0.0.0.0:0 reply tail).
	got := out.Bytes()
	if len(got) < 2 || got[0] != 0x05 || got[1] != 0x00 {
		t.Fatalf("method-selection reply: got %x", got)
	}
	if len(got) < 12 || got[2] != 0x05 || got[3] != 0x08 {
		t.Fatalf("expected address-type-not-supported (0x08) reply; got %x", got)
	}
}

// Sanity: confirm fakeConn's EOF behavior so the test above doesn't accidentally hang.
func TestFakeConnEOF(t *testing.T) {
	c := &fakeConn{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	_, err := c.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}
