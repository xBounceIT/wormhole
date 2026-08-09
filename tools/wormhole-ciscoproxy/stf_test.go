package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestBuildSTFFrame_Shape(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	frame, err := buildSTFFrame(acData, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) != stfHeaderSz+len(payload) {
		t.Fatalf("frame length: got %d want %d", len(frame), stfHeaderSz+len(payload))
	}
	if !bytes.Equal(frame[0:4], []byte{'S', 'T', 'F', 0x01}) {
		t.Fatalf("magic: got %v", frame[0:4])
	}
	if binary.BigEndian.Uint16(frame[4:6]) != uint16(len(payload)) {
		t.Fatalf("payload length field: got %d want %d", binary.BigEndian.Uint16(frame[4:6]), len(payload))
	}
	if frame[6] != acData || frame[7] != 0 {
		t.Fatalf("type/reserved bytes: got %d %d", frame[6], frame[7])
	}
	if !bytes.Equal(frame[8:], payload) {
		t.Fatalf("payload not copied verbatim")
	}
}

func TestBuildSTFFrame_EmptyPayloadControl(t *testing.T) {
	frame, err := buildSTFFrame(acDPDResp, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(frame) != stfHeaderSz {
		t.Fatalf("control frame length: got %d want %d", len(frame), stfHeaderSz)
	}
	if binary.BigEndian.Uint16(frame[4:6]) != 0 {
		t.Fatal("control frame should carry zero payload length")
	}
	if frame[6] != acDPDResp {
		t.Fatalf("type: got %d want %d", frame[6], acDPDResp)
	}
}

func TestBuildSTFFrame_RejectsOversized(t *testing.T) {
	if _, err := buildSTFFrame(acData, make([]byte, cstpMaxPayloadLen+1)); err == nil {
		t.Fatal("expected an error for a payload past the framing cap")
	}
}

type fakeNetConn struct {
	in     *bytes.Buffer
	out    *bytes.Buffer
	closed bool
	err    error
}

func (c *fakeNetConn) Read(buffer []byte) (int, error) { return c.in.Read(buffer) }
func (c *fakeNetConn) Write(buffer []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return c.out.Write(buffer)
}
func (c *fakeNetConn) Close() error                     { c.closed = true; return nil }
func (c *fakeNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

func TestReadLoopDispatchesFrameTypes(t *testing.T) {
	stack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	ipv4Packet := make([]byte, 20)
	ipv4Packet[0] = 0x45
	binary.BigEndian.PutUint16(ipv4Packet[2:4], uint16(len(ipv4Packet)))
	input := make([]byte, 0)
	for _, item := range []struct {
		kind    byte
		payload []byte
	}{
		{kind: acData, payload: ipv4Packet},
		{kind: acDPDOut, payload: []byte("nonce")},
		{kind: acDPDResp},
		{kind: acKeepalive},
		{kind: acCompressed, payload: []byte("compressed")},
		{kind: 0xff, payload: []byte("unknown")},
		{kind: acDisconnect},
	} {
		frame, err := buildSTFFrame(item.kind, item.payload)
		if err != nil {
			t.Fatal(err)
		}
		input = append(input, frame...)
	}
	connection := &fakeNetConn{in: bytes.NewBuffer(input), out: &bytes.Buffer{}}
	cancelled := false
	state := &cstpState{
		conn:         connection,
		reader:       bufio.NewReader(connection),
		ch:           endpoint,
		cancel:       func() { cancelled = true },
		controlFrame: make(chan []byte, controlQueueDepth),
		dataFrame:    make(chan []byte, dataQueueDepth),
	}
	state.readLoop(context.Background())
	if !cancelled || len(state.controlFrame) != 1 {
		t.Fatalf("readLoop cancelled=%v control=%d", cancelled, len(state.controlFrame))
	}
	reply := <-state.controlFrame
	if reply[6] != acDPDResp || string(reply[8:]) != "nonce" {
		t.Fatalf("DPD reply = %x", reply)
	}
}

func TestReadLoopHandlesTerminateAndMalformedFrames(t *testing.T) {
	term, _ := buildSTFFrame(acTermServer, nil)
	tests := [][]byte{
		term,
		{0, 0, 0, 0, 0, 0, 0, 0},
		{'S', 'T', 'F', 1, 0x40, 0x01, acData, 0},
		{'S', 'T', 'F', 1, 0, 2, acData, 0, 1},
	}
	for _, input := range tests {
		connection := &fakeNetConn{in: bytes.NewBuffer(input), out: &bytes.Buffer{}}
		state := &cstpState{conn: connection, reader: bufio.NewReader(connection), cancel: func() {}, controlFrame: make(chan []byte, 1)}
		state.readLoop(context.Background())
	}
}

func TestInjectIPv4RejectsMalformedPackets(t *testing.T) {
	state := &cstpState{}
	state.injectIPv4(nil)
	packet := make([]byte, 20)
	packet[0] = 0x60
	state.injectIPv4(packet)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 10)
	state.injectIPv4(packet)
	binary.BigEndian.PutUint16(packet[2:4], 21)
	state.injectIPv4(packet)
}

func TestSendControlHandlesQueueAndOversize(t *testing.T) {
	state := &cstpState{controlFrame: make(chan []byte, 1)}
	state.sendControl(acDPDOut, []byte("probe"))
	state.sendControl(acKeepalive, nil)
	if len(state.controlFrame) != 1 {
		t.Fatalf("control queue length = %d", len(state.controlFrame))
	}
	state.sendControl(acDPDOut, make([]byte, cstpMaxPayloadLen+1))
}

func TestWriteFrameAndWriterLoop(t *testing.T) {
	connection := &fakeNetConn{in: &bytes.Buffer{}, out: &bytes.Buffer{}}
	state := &cstpState{conn: connection, cancel: func() {}, controlFrame: make(chan []byte, 2), dataFrame: make(chan []byte, 2)}
	if err := state.writeFrame(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := state.writeFrame(context.Background(), []byte("direct")); err != nil {
		t.Fatal(err)
	}
	errorState := &cstpState{conn: &fakeNetConn{in: &bytes.Buffer{}, out: &bytes.Buffer{}, err: errors.New("write failed")}}
	if err := errorState.writeFrame(context.Background(), []byte("fail")); err == nil {
		t.Fatal("write error was ignored")
	}
	state.controlFrame <- []byte("control")
	state.dataFrame <- []byte("data")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		state.writerLoop(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writerLoop did not stop")
	}
	if got := connection.out.String(); !strings.Contains(got, "control") || !strings.Contains(got, "data") || !connection.closed {
		t.Fatalf("writer output=%q closed=%v", got, connection.closed)
	}
}

func TestDPDAndDataLoopsStopWithContext(t *testing.T) {
	stack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	state := &cstpState{ch: endpoint, dpdInterval: time.Millisecond, controlFrame: make(chan []byte, 1), dataFrame: make(chan []byte, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	dpdDone := make(chan struct{})
	go func() { state.dpdLoop(ctx); close(dpdDone) }()
	select {
	case frame := <-state.controlFrame:
		if frame[6] != acDPDOut {
			t.Fatalf("DPD frame = %x", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("DPD loop did not emit a probe")
	}
	cancel()
	<-dpdDone
	state.dataLoop(ctx)
}

func TestRunCSTPCancelledLifecycle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	connection, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	stack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		runCSTP(ctx, &session{Conn: connection, Reader: bufio.NewReader(connection), AssignedIP: netip.MustParseAddr("10.0.0.2"), MTU: 1400, DPDSeconds: 1}, endpoint)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCSTP did not stop after cancellation")
	}
}

func TestStartCiscoValidatesBeforeNetwork(t *testing.T) {
	valid := config{Host: "vpn.example.test", Port: 443, Username: "alice", Password: "secret"}
	tests := []struct {
		name   string
		cfg    config
		cancel context.CancelFunc
		want   string
	}{
		{name: "cancel", cfg: valid, want: "outerCancel"},
		{name: "host", cfg: config{Port: 443, Username: "alice", Password: "secret"}, cancel: func() {}, want: "host"},
		{name: "username", cfg: config{Host: "vpn.example.test", Port: 443, Password: "secret"}, cancel: func() {}, want: "username and password"},
		{name: "password", cfg: config{Host: "vpn.example.test", Port: 443, Username: "alice"}, cancel: func() {}, want: "username and password"},
		{name: "low port", cfg: config{Host: "vpn.example.test", Port: -1, Username: "alice", Password: "secret"}, cancel: func() {}, want: "invalid port"},
		{name: "high port", cfg: config{Host: "vpn.example.test", Port: 65536, Username: "alice", Password: "secret"}, cancel: func() {}, want: "invalid port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := startCisco(context.Background(), test.cancel, test.cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startCisco error = %v, want %q", err, test.want)
			}
		})
	}
}
