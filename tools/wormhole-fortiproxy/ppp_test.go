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

type ipcpFrame struct {
	code, id byte
	body     []byte
}

// drainAllIPCP non-blockingly pulls every queued control frame, decodes the IPCP ones, and
// returns them. Order-independent so tests don't depend on whether the Ack or our request is
// enqueued first.
func drainAllIPCP(t *testing.T, ch chan []byte) []ipcpFrame {
	t.Helper()
	var out []ipcpFrame
	for {
		select {
		case frame := <-ch:
			if len(frame) >= 8 && binary.BigEndian.Uint16(frame[6:8]) == pppProtoIPCP {
				if code, id, body, ok := parseCPFrame(frame[8:]); ok {
					out = append(out, ipcpFrame{code, id, body})
				}
			}
		default:
			return out
		}
	}
}

// findIPCP returns the first frame with the given code, or nil.
func findIPCP(frames []ipcpFrame, code byte) *ipcpFrame {
	for i := range frames {
		if frames[i].code == code {
			return &frames[i]
		}
	}
	return nil
}

// gatewayIPCPRequest builds the payload handleIPCP receives for a gateway IPCP
// Configure-Request announcing addr as the gateway's own address.
func gatewayIPCPRequest(id byte, addr [4]byte) []byte {
	return buildCPFrame(lcpConfigureRequest, id, []byte{ipcpOptIPAddress, 6, addr[0], addr[1], addr[2], addr[3]})
}

func TestHandleIPCP_AcksGatewayAndSendsOwnRequest(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(0x42, [4]byte{80, 76, 65, 33}))
	frames := drainAllIPCP(t, s.controlFrame)

	// We Ack the gateway's request: same id, body verbatim.
	ack := findIPCP(frames, lcpConfigureAck)
	if ack == nil {
		t.Fatal("no Configure-Ack of the gateway request emitted")
	}
	if ack.id != 0x42 {
		t.Errorf("ack id=%#x want 0x42", ack.id)
	}
	if !bytes.Equal(ack.body, []byte{ipcpOptIPAddress, 6, 80, 76, 65, 33}) {
		t.Errorf("ack body=%v want verbatim gateway option", ack.body)
	}
	// We also originate our OWN Configure-Request advertising the assigned address.
	req := findIPCP(frames, lcpConfigureRequest)
	if req == nil {
		t.Fatal("no client Configure-Request emitted")
	}
	if !s.ourIPCPSent || req.id != s.ourIPCPID {
		t.Errorf("our request id=%#x not tracked (ourIPCPID=%#x sent=%v)", req.id, s.ourIPCPID, s.ourIPCPSent)
	}
	if want := []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}; !bytes.Equal(req.body, want) {
		t.Errorf("our request body=%v want %v (assigned-IP option)", req.body, want)
	}
	if !s.peerAckSent {
		t.Error("peerAckSent should be true after acking the gateway request")
	}
}

func TestHandleIPCP_NeverNaksGatewayAddress(t *testing.T) {
	// The whole bug: a gateway address differing from ours must NOT produce a Configure-Nak.
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	if findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureNak) != nil {
		t.Fatal("handleIPCP must never Configure-Nak the gateway's announced address")
	}
}

func TestHandleIPCP_ReusesRequestIdAcrossRetransmits(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	first := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	s.handleIPCP(gatewayIPCPRequest(2, [4]byte{80, 76, 65, 33}))
	second := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	if first == nil || second == nil {
		t.Fatal("expected a client Configure-Request after each gateway request")
	}
	if first.id != second.id {
		t.Errorf("re-sent request id changed: first=%#x second=%#x (must reuse a stable id)", first.id, second.id)
	}
}

func TestHandleIPCP_AckOpensOurHalfAndStopsResending(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	req := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	if req == nil {
		t.Fatal("expected a client Configure-Request")
	}
	// Gateway acks our request -> our half up; both halves => opened.
	s.handleIPCP(buildCPFrame(lcpConfigureAck, req.id, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}))
	if !s.ourAckReceived {
		t.Fatal("ourAckReceived should be true after the gateway acks our request")
	}
	if !s.ipcpOpened {
		t.Fatal("ipcpOpened should latch once both halves are up")
	}
	// A further gateway CR is still Ack'd, but must NOT trigger another of our requests.
	s.handleIPCP(gatewayIPCPRequest(2, [4]byte{80, 76, 65, 33}))
	frames := drainAllIPCP(t, s.controlFrame)
	if findIPCP(frames, lcpConfigureAck) == nil {
		t.Error("expected an Ack of the repeat gateway request")
	}
	if findIPCP(frames, lcpConfigureRequest) != nil {
		t.Error("no further client request expected once our half is up")
	}
}

func TestHandleIPCP_StaleAckIgnored(t *testing.T) {
	s, _ := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	req := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	if req == nil {
		t.Fatal("expected a client Configure-Request")
	}
	s.handleIPCP(buildCPFrame(lcpConfigureAck, req.id+1, nil)) // non-matching id
	if s.ourAckReceived {
		t.Error("a Configure-Ack with a non-matching id must not open our half")
	}
}

func TestHandleIPCP_NakTearsDown(t *testing.T) {
	s, cancelled := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	req := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	if req == nil {
		t.Fatal("expected a client Configure-Request")
	}
	// Gateway Naks our address, offering a different one we cannot bind.
	s.handleIPCP(buildCPFrame(lcpConfigureNak, req.id, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 99}))
	if !*cancelled {
		t.Error("a Configure-Nak of our address must tear down (cancel), not silently adopt it")
	}
}

func TestHandleIPCP_RejectTearsDown(t *testing.T) {
	s, cancelled := newTestPPPState()
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	req := findIPCP(drainAllIPCP(t, s.controlFrame), lcpConfigureRequest)
	if req == nil {
		t.Fatal("expected a client Configure-Request")
	}
	s.handleIPCP(buildCPFrame(lcpConfigureReject, req.id, []byte{ipcpOptIPAddress, 6, 10, 155, 50, 19}))
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

// fillControl pushes n filler bytes into the control channel to simulate writer backpressure.
// Fillers are 1 byte so drainAllIPCP (which needs >=8 bytes) ignores them.
func fillControl(ch chan []byte, n int) {
	for i := 0; i < n; i++ {
		ch <- []byte{0x00}
	}
}

func TestHandleIPCP_RequestSurvivesOneFreeSlot(t *testing.T) {
	// Codex P2: under control-queue backpressure with a single free slot, the
	// negotiation-critical Configure-Request must win the slot, not the Ack — otherwise a
	// delivered Ack with a dropped request makes the gateway stop retransmitting while our half
	// never opens. Request-before-Ack ordering guarantees the request survives.
	s, _ := newTestPPPState()
	fillControl(s.controlFrame, controlQueueDepth-1) // leave exactly one slot
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	frames := drainAllIPCP(t, s.controlFrame)
	if findIPCP(frames, lcpConfigureRequest) == nil {
		t.Fatal("our Configure-Request must survive the single free slot")
	}
	if findIPCP(frames, lcpConfigureAck) != nil {
		t.Fatal("with one slot the Ack should be the dropped frame, not our request")
	}
	if !s.ourIPCPSent {
		t.Error("ourIPCPSent should latch after the request was enqueued")
	}
	if s.peerAckSent {
		t.Error("peerAckSent must not latch when the Ack was dropped")
	}
}

func TestHandleIPCP_NoFalseLatchWhenQueueFull(t *testing.T) {
	// With a completely full control queue both frames are dropped; ourIPCPSent must NOT latch,
	// so a later gateway request retries the send rather than treating it as done.
	s, _ := newTestPPPState()
	fillControl(s.controlFrame, controlQueueDepth)
	s.handleIPCP(gatewayIPCPRequest(1, [4]byte{80, 76, 65, 33}))
	if s.ourIPCPSent {
		t.Error("ourIPCPSent must not latch when the request enqueue was dropped (queue full)")
	}
	if s.peerAckSent {
		t.Error("peerAckSent must not latch when the Ack enqueue was dropped (queue full)")
	}
}
