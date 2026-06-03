package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildEncapFrame_Roundtrip(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	frame, err := buildEncapFrame(pppProtoLCP, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frame) != fortinetEncapHeaderSz+2+len(payload) {
		t.Errorf("len(frame)=%d want %d", len(frame), fortinetEncapHeaderSz+2+len(payload))
	}
	total := binary.BigEndian.Uint16(frame[0:2])
	if int(total) != len(frame) {
		t.Errorf("total len field=%d want %d", total, len(frame))
	}
	magic := binary.BigEndian.Uint16(frame[2:4])
	if magic != fortinetEncapMagic {
		t.Errorf("magic=%#x want %#x", magic, fortinetEncapMagic)
	}
	payloadLen := binary.BigEndian.Uint16(frame[4:6])
	if int(payloadLen) != 2+len(payload) {
		t.Errorf("payload len field=%d want %d", payloadLen, 2+len(payload))
	}
	proto := binary.BigEndian.Uint16(frame[6:8])
	if proto != pppProtoLCP {
		t.Errorf("proto=%#x want %#x", proto, pppProtoLCP)
	}
	if !bytes.Equal(frame[8:], payload) {
		t.Errorf("payload mismatch")
	}
}

func TestBuildEncapFrame_RejectsOversize(t *testing.T) {
	// Payload large enough that header + 2-byte PPP proto field + payload exceeds uint16
	// (0xFFFF). Without the size guard the length fields would silently wrap and corrupt
	// the wire framing — locked here so a future regression is caught.
	const tooBig = 0x10000 // 65536 bytes
	_, err := buildEncapFrame(pppProtoIPv4, make([]byte, tooBig))
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}

func TestBuildEncapFrame_MaxBoundary(t *testing.T) {
	// Exactly at the boundary: payload = 0xFFFF - 6 - 2 = 65527.
	max := 0xFFFF - fortinetEncapHeaderSz - 2
	frame, err := buildEncapFrame(pppProtoIPv4, make([]byte, max))
	if err != nil {
		t.Fatalf("max boundary should succeed; got error: %v", err)
	}
	if len(frame) != 0xFFFF {
		t.Errorf("expected frame len 0xFFFF, got %d", len(frame))
	}
	// One byte over should fail.
	_, err = buildEncapFrame(pppProtoIPv4, make([]byte, max+1))
	if err == nil {
		t.Fatal("max+1 should fail; got nil")
	}
}

func TestExtractIPCPAddress_LegitimateOption(t *testing.T) {
	// Simple IPCP body with just the IP-Address option (type=3, len=6).
	body := []byte{0x03, 0x06, 10, 0, 0, 5}
	addr, ok := extractIPCPAddress(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if addr.String() != "10.0.0.5" {
		t.Errorf("got %v want 10.0.0.5", addr)
	}
}

func TestExtractIPCPAddress_AfterOtherOption(t *testing.T) {
	// RFC 1877 Primary-DNS option (type=129, len=6) followed by IP-Address (type=3, len=6).
	body := []byte{
		0x81, 0x06, 8, 8, 8, 8, // Primary-DNS = 8.8.8.8
		0x03, 0x06, 10, 0, 0, 5, // IP-Address = 10.0.0.5
	}
	addr, ok := extractIPCPAddress(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if addr.String() != "10.0.0.5" {
		t.Errorf("got %v want 10.0.0.5", addr)
	}
}

func TestExtractIPCPAddress_IgnoresFalsePositiveInOtherOptionValue(t *testing.T) {
	// W14: an unrelated option (type=0x81 Primary-DNS, len=6) whose payload happens to
	// contain the byte sequence 0x03, 0x06, 0x01, 0x01 would have been picked up by a
	// sliding-window scan as a fake IP-Address option. Proper option-walking skips past
	// the whole DNS option and never sees its value bytes as a new (type, len) pair, so
	// we correctly return ok=false (no real IP-Address option in this body).
	body := []byte{
		0x81, 0x06, 0x03, 0x06, 0x01, 0x01,
	}
	addr, ok := extractIPCPAddress(body)
	if ok {
		t.Fatalf("expected ok=false (no real IP-Address option); got addr=%v", addr)
	}
}

func TestExtractIPCPAddress_AbortsOnMalformedLength(t *testing.T) {
	// l=1 < 2 is malformed; we abort rather than blindly skipping one byte (which would
	// shift the parser onto value bytes and resurface the same false-positive problem
	// the sliding-window approach had).
	body := []byte{0x01, 0x01, 0x03, 0x06, 10, 0, 0, 5}
	_, ok := extractIPCPAddress(body)
	if ok {
		t.Fatal("expected ok=false on malformed-length prefix")
	}
}

// --- IPCP negotiation (handleIPCP) ---
//
// These lock in the fix for the infinite Configure-Nak loop: the gateway's Configure-Request
// carries the GATEWAY's own address and must be Ack'd (never Nak'd with ours), and the client
// must drive its own half of IPCP by (re)sending its Configure-Request off the gateway's CRs.

func newTestPPPState() (*pppState, *bool) {
	cancelled := false
	s := &pppState{
		assignedIP:   netip.MustParseAddr("10.155.50.19"),
		cancel:       func() { cancelled = true },
		controlFrame: make(chan []byte, controlQueueDepth),
		dataFrame:    make(chan []byte, dataQueueDepth),
	}
	s.nextID.Store(1)
	return s, &cancelled
}

// drainIPCP pops the next frame off the control channel and decodes it as an IPCP control
// frame, returning (code, id, body). Fails the test if the channel is empty or not IPCP.
func drainIPCP(t *testing.T, ch chan []byte) (byte, byte, []byte) {
	t.Helper()
	select {
	case frame := <-ch:
		if len(frame) < 8 {
			t.Fatalf("control frame too short: %d bytes", len(frame))
		}
		if proto := binary.BigEndian.Uint16(frame[6:8]); proto != pppProtoIPCP {
			t.Fatalf("expected IPCP proto %#x, got %#x", pppProtoIPCP, proto)
		}
		code, id, body, ok := parseCPFrame(frame[8:])
		if !ok {
			t.Fatal("parseCPFrame failed on control frame")
		}
		return code, id, body
	default:
		t.Fatal("expected a frame on the control channel, got none")
		return 0, 0, nil
	}
}

// gatewayIPCPRequest builds the payload handleIPCP receives for a gateway IPCP
// Configure-Request announcing addr as the gateway's own address.
func gatewayIPCPRequest(id byte, addr [4]byte) []byte {
	return buildCPFrame(lcpConfigureRequest, id, []byte{ipcpOptIPAddress, 6, addr[0], addr[1], addr[2], addr[3]})
}

func TestHandleIPCP_AcksGatewayAndSendsOwnRequest(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(0x42, [4]byte{80, 76, 65, 33}))

	// First frame: Configure-Ack of the gateway's request, same id, body verbatim.
	code, id, body := drainIPCP(t, s.controlFrame)
	if code != lcpConfigureAck {
		t.Fatalf("first frame code=%d want Ack(%d)", code, lcpConfigureAck)
	}
	if id != 0x42 {
		t.Errorf("ack id=%#x want 0x42", id)
	}
	if !bytes.Equal(body, []byte{ipcpOptIPAddress, 6, 80, 76, 65, 33}) {
		t.Errorf("ack body=%v want verbatim gateway option", body)
	}
	// Second frame: our OWN Configure-Request advertising the assigned address.
	code2, id2, body2 := drainIPCP(t, s.controlFrame)
	if code2 != lcpConfigureRequest {
		t.Fatalf("second frame code=%d want Request(%d)", code2, lcpConfigureRequest)
	}
	if !s.ourIPCPSent || id2 != s.ourIPCPID {
		t.Errorf("our request id=%#x not tracked (ourIPCPID=%#x sent=%v)", id2, s.ourIPCPID, s.ourIPCPSent)
	}
	if want := []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}; !bytes.Equal(body2, want) {
		t.Errorf("our request body=%v want %v (assigned-IP option)", body2, want)
	}
	if !s.peerAckSent {
		t.Error("peerAckSent should be true after acking the gateway request")
	}
}

func TestHandleIPCP_NeverNaksGatewayAddress(t *testing.T) {
	// The whole bug: a gateway address differing from ours must NOT produce a Configure-Nak.
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	for {
		select {
		case frame := <-s.controlFrame:
			if code, _, _, ok := parseCPFrame(frame[8:]); ok && code == lcpConfigureNak {
				t.Fatal("handleIPCP must never Configure-Nak the gateway's announced address")
			}
		default:
			return
		}
	}
}

func TestHandleIPCP_ReusesRequestIdAcrossRetransmits(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)              // ack #1
	_, first, _ := drainIPCP(t, s.controlFrame) // our request #1
	s.handleIPCP(gatewayIPCPRequest(2, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)               // ack #2
	_, second, _ := drainIPCP(t, s.controlFrame) // our request #2 (re-send)
	if first != second {
		t.Errorf("re-sent request id changed: first=%#x second=%#x (must reuse a stable id)", first, second)
	}
}

func TestHandleIPCP_AckOpensOurHalfAndStopsResending(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)               // ack of gateway request (peerAckSent=true)
	_, ourID, _ := drainIPCP(t, s.controlFrame) // our request
	// Gateway acks our request -> our half up; both halves => opened.
	s.handleIPCP(buildCPFrame(lcpConfigureAck, ourID, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}))
	if !s.ourAckReceived {
		t.Fatal("ourAckReceived should be true after the gateway acks our request")
	}
	if !s.ipcpOpened {
		t.Fatal("ipcpOpened should latch once both halves are up")
	}
	// A further gateway CR is still Ack'd, but must NOT trigger another of our requests.
	s.handleIPCP(gatewayIPCPRequest(2, [4]byte{80, 76, 65, 33}))
	if code, _, _ := drainIPCP(t, s.controlFrame); code != lcpConfigureAck {
		t.Fatalf("expected Ack of repeat gateway request, got code=%d", code)
	}
	select {
	case extra := <-s.controlFrame:
		c, _, _, _ := parseCPFrame(extra[8:])
		t.Fatalf("no further client request expected once our half is up; got code=%d", c)
	default:
	}
}

func TestHandleIPCP_StaleAckIgnored(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)
	_, ourID, _ := drainIPCP(t, s.controlFrame)
	s.handleIPCP(buildCPFrame(lcpConfigureAck, ourID+1, nil)) // non-matching id
	if s.ourAckReceived {
		t.Error("a Configure-Ack with a non-matching id must not open our half")
	}
}

func TestHandleIPCP_NakTearsDown(t *testing.T) {
	s, cancelled := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)
	_, ourID, _ := drainIPCP(t, s.controlFrame)
	// Gateway Naks our address, offering a different one we cannot bind.
	s.handleIPCP(buildCPFrame(lcpConfigureNak, ourID, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 99}))
	if !*cancelled {
		t.Error("a Configure-Nak of our address must tear down (cancel), not silently adopt it")
	}
}

func TestHandleIPCP_RejectTearsDown(t *testing.T) {
	s, cancelled := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	drainIPCP(t, s.controlFrame)
	_, ourID, _ := drainIPCP(t, s.controlFrame)
	s.handleIPCP(buildCPFrame(lcpConfigureReject, ourID, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}))
	if !*cancelled {
		t.Error("a Configure-Reject of our IP-Address option must tear down")
	}
}

func TestHandleIPCP_OpenedRequiresBothHalves(t *testing.T) {
	s, _ := newTestPPPState()
	s.peerAckSent = true
	s.maybeIPCPOpened()
	if s.ipcpOpened {
		t.Error("must not open with only the peer half up")
	}
	s.peerAckSent = false
	s.ourAckReceived = true
	s.maybeIPCPOpened()
	if s.ipcpOpened {
		t.Error("must not open with only our half up")
	}
	s.peerAckSent = true
	s.maybeIPCPOpened()
	if !s.ipcpOpened {
		t.Error("must open once both halves are up")
	}
}
