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

type recordingDialer struct {
	connection net.Conn
	err        error
	network    string
	address    string
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.network = network
	d.address = address
	return d.connection, d.err
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

func TestHandleSocks5RejectsUnsupportedNegotiation(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{name: "version", input: []byte{0x04, 0x00}},
		{name: "auth", input: []byte{0x05, 0x01, 0x02}, want: []byte{0x05, 0xff}},
		{name: "command", input: []byte{0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01}, want: append([]byte{0x05, 0x00}, []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}...)},
		{name: "address type", input: []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09}, want: append([]byte{0x05, 0x00}, []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := &fakeConn{in: bytes.NewBuffer(test.input), out: &bytes.Buffer{}}
			handleSocks5(context.Background(), connection, &recordingDialer{})
			if !bytes.Equal(connection.out.Bytes(), test.want) {
				t.Fatalf("reply = %x, want %x", connection.out.Bytes(), test.want)
			}
		})
	}
}

func TestHandleSocks5ParsesIPv4AndDomain(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    string
	}{
		{name: "IPv4", request: []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}, want: "127.0.0.1:443"},
		{name: "domain", request: append([]byte{0x05, 0x01, 0x00, 0x03, 11}, append([]byte("example.com"), 0x00, 0x50)...), want: "example.com:80"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := append([]byte{0x05, 0x01, 0x00}, test.request...)
			connection := &fakeConn{in: bytes.NewBuffer(input), out: &bytes.Buffer{}}
			dial := &recordingDialer{err: errors.New("unreachable")}
			handleSocks5(context.Background(), connection, dial)
			if dial.network != "tcp" || dial.address != test.want {
				t.Fatalf("dial = %q %q", dial.network, dial.address)
			}
			got := connection.out.Bytes()
			if len(got) != 12 || got[3] != 0x04 {
				t.Fatalf("reply = %x", got)
			}
		})
	}
}

func TestHandleSocks5ConnectsAndPumps(t *testing.T) {
	client, server := net.Pipe()
	upstream, peer := net.Pipe()
	dial := &recordingDialer{connection: upstream}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSocks5(ctx, server, dial)
		_ = server.Close()
	}()

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	method := make([]byte, 2)
	_, _ = io.ReadFull(client, method)
	request := append([]byte{0x05, 0x01, 0x00, 0x03, 9}, append([]byte("host.test"), 0x1f, 0x90)...)
	_, _ = client.Write(request)
	reply := make([]byte, 10)
	_, _ = io.ReadFull(client, reply)
	if reply[1] != 0 || dial.address != "host.test:8080" {
		t.Fatalf("reply=%x dial=%q", reply, dial.address)
	}

	readPeer := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(peer, buffer)
		readPeer <- buffer
	}()
	_, _ = client.Write([]byte("ping"))
	if got := <-readPeer; string(got) != "ping" {
		t.Fatalf("peer received %q", got)
	}
	writePeer := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("pong"))
		writePeer <- err
	}()
	buffer := make([]byte, 4)
	_, _ = io.ReadFull(client, buffer)
	if string(buffer) != "pong" || <-writePeer != nil {
		t.Fatalf("client received %q", buffer)
	}

	cancel()
	_ = client.Close()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not stop")
	}
}

func TestHandleSocks5CancellationUnblocksHandshake(t *testing.T) {
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handleSocks5(ctx, server, &recordingDialer{})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled handshake remained blocked")
	}
	_ = client.Close()
	_ = server.Close()
}
