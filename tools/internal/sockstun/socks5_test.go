package sockstun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingLogger struct {
	mu      sync.Mutex
	entries []string
}

func (l *recordingLogger) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, fmt.Sprintf(format, args...))
}

func (l *recordingLogger) contains(value string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(strings.Join(l.entries, "\n"), value)
}

type dialResult struct {
	connection net.Conn
	err        error
	address    string
	dialID     uint64
}

func (d *dialResult) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.address = network + " " + address
	d.dialID, _ = DialIDFromContext(ctx)
	return d.connection, d.err
}

func TestDialIDFromContext(t *testing.T) {
	if _, ok := DialIDFromContext(context.Background()); ok {
		t.Fatal("DialIDFromContext found an absent ID")
	}
	if _, ok := DialIDFromContext(context.WithValue(context.Background(), dialIDContextKey{}, uint64(0))); ok {
		t.Fatal("DialIDFromContext accepted zero")
	}
	if got, ok := DialIDFromContext(context.WithValue(context.Background(), dialIDContextKey{}, uint64(42))); !ok || got != 42 {
		t.Fatalf("DialIDFromContext = %d, %v", got, ok)
	}
}

func TestSanitizeReplyDetail(t *testing.T) {
	if got := sanitizeReplyDetail("  bad\r\nmessage\x7f  "); got != "bad  message" {
		t.Fatalf("sanitizeReplyDetail returned %q", got)
	}
	if got := sanitizeReplyDetail(" \r\n\t "); got != "" {
		t.Fatalf("sanitizeReplyDetail returned %q for whitespace", got)
	}
	long := strings.Repeat("a", 253) + "🔐suffix"
	got := sanitizeReplyDetail(long)
	if got != strings.Repeat("a", 253) {
		t.Fatalf("sanitizeReplyDetail produced invalid truncation of %d bytes", len([]byte(got)))
	}
}

func readExactly(t *testing.T, connection net.Conn, size int) []byte {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, size)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatalf("read %d bytes: %v", size, err)
	}
	return buffer
}

func runFailedRequest(t *testing.T, request []byte, dial Dialer) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handle(context.Background(), server, dial, &recordingLogger{})
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, client, 2); !bytes.Equal(got, []byte{0x05, 0x00}) {
		t.Fatalf("method reply = %v", got)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-done
	return reply
}

func TestHandleRejectsUnsupportedNegotiation(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handle(context.Background(), server, &dialResult{}, &recordingLogger{})
	}()
	if _, err := client.Write([]byte{0x05, 0x02, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, client, 2); !bytes.Equal(got, []byte{0x05, 0xff}) {
		t.Fatalf("method rejection = %v", got)
	}
	_ = client.Close()
	<-done
}

func TestHandleRejectsUnsupportedCommandAndAddressType(t *testing.T) {
	reply := runFailedRequest(t, []byte{0x05, 0x02, 0x00, 0x01}, &dialResult{})
	if len(reply) != 10 || reply[1] != 0x07 {
		t.Fatalf("command rejection = %v", reply)
	}
	reply = runFailedRequest(t, []byte{0x05, 0x01, 0x00, 0x09}, &dialResult{})
	if len(reply) != 10 || reply[1] != 0x08 {
		t.Fatalf("address rejection = %v", reply)
	}
}

func TestHandleParsesTargetsAndReportsDialFailure(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    string
	}{
		{name: "IPv4", request: []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}, want: "tcp 127.0.0.1:443"},
		{name: "domain", request: append([]byte{0x05, 0x01, 0x00, 0x03, 11}, append([]byte("example.com"), 0x00, 0x50)...), want: "tcp example.com:80"},
		{name: "IPv6", request: append([]byte{0x05, 0x01, 0x00, 0x04}, append(net.ParseIP("::1").To16(), 0x20, 0xfb)...), want: "tcp [::1]:8443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dial := &dialResult{err: errors.New("unreachable\r\nreason")}
			reply := runFailedRequest(t, test.request, dial)
			if dial.address != test.want || dial.dialID == 0 {
				t.Fatalf("dial = %q id=%d, want %q", dial.address, dial.dialID, test.want)
			}
			if len(reply) < 7 || reply[1] != 0x04 || reply[3] != 0x03 || bytes.ContainsAny(reply[5:len(reply)-2], "\r\n") {
				t.Fatalf("failure reply = %v", reply)
			}
		})
	}
}

func TestHandleConnectsAndPumpsBothDirections(t *testing.T) {
	client, server := net.Pipe()
	upstream, peer := net.Pipe()
	dial := &dialResult{connection: upstream}
	logger := &recordingLogger{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handle(ctx, server, dial, logger)
	}()

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	readExactly(t, client, 2)
	request := append([]byte{0x05, 0x01, 0x00, 0x03, 9}, append([]byte("host.test"), 0x1f, 0x90)...)
	_, _ = client.Write(request)
	if reply := readExactly(t, client, 10); reply[1] != 0x00 {
		t.Fatalf("success reply = %v", reply)
	}

	clientToPeer := make(chan []byte, 1)
	go func() { clientToPeer <- readExactly(t, peer, 4) }()
	_, _ = client.Write([]byte("ping"))
	if got := <-clientToPeer; string(got) != "ping" {
		t.Fatalf("upstream received %q", got)
	}
	peerToClient := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("pong"))
		peerToClient <- err
	}()
	if got := readExactly(t, client, 4); string(got) != "pong" {
		t.Fatalf("client received %q", got)
	}
	if err := <-peerToClient; err != nil {
		t.Fatal(err)
	}
	if dial.address != "tcp host.test:8080" || dial.dialID == 0 || !logger.contains("connected") {
		t.Fatalf("dial=%q id=%d logs=%v", dial.address, dial.dialID, logger.entries)
	}

	cancel()
	_ = client.Close()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handle did not stop after cancellation")
	}
}

func TestWriteReplyWithDetailFallsBackForEmptyDetail(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		writeReplyWithDetail(server, 0x04, "\r\n")
		_ = server.Close()
	}()
	if got := readExactly(t, client, 10); got[1] != 0x04 || got[3] != 0x01 {
		t.Fatalf("fallback reply = %v", got)
	}
	_ = client.Close()
	<-done
}

func TestServeAcceptsConnectionsUntilListenerCloses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, &dialResult{}, &recordingLogger{}) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write([]byte{0x04, 0x00})
	_ = connection.Close()
	cancel()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestOSDialerConnectsToLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	connection, err := (OSDialer{}).DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("listener did not accept the connection")
	}
	_ = peer.Close()
}
