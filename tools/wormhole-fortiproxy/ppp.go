package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Fortinet PPP encapsulation: a 6-byte header in front of every PPP frame.
//
//   bytes 0-1: total length (big-endian) = payload_len + 6
//   bytes 2-3: magic 0x5050 (constant)
//   bytes 4-5: payload length (big-endian) = PPP header + payload, NOT including these 6 bytes
//   bytes 6+ : PPP frame (starts with 2-byte PPP protocol field, e.g. 0xC021 LCP, 0x8021 IPCP,
//              0x0021 IPv4)
//
// Per openconnect/ppp.c the validator asserts total_len == payload_len + 6 and magic == 0x5050.
const (
	fortinetEncapMagic    = 0x5050
	fortinetEncapHeaderSz = 6

	// Sanity cap for a single PPP frame's payload length. FortiGate negotiates MRU around
	// 1500; pin a generous upper bound so a corrupt / malicious header can't lead us to
	// allocate an absurd buffer or block ReadFull on bytes that will never arrive. Anything
	// above this is treated as a framing error.
	fortinetMaxPayloadLen = 16 * 1024

	pppProtoLCP  = 0xC021
	pppProtoIPCP = 0x8021
	pppProtoIPv4 = 0x0021

	lcpConfigureRequest = 1
	lcpConfigureAck     = 2
	lcpConfigureNak     = 3
	lcpConfigureReject  = 4
	lcpTerminateRequest = 5
	lcpTerminateAck     = 6
	lcpCodeReject       = 7
	lcpEchoRequest      = 9
	lcpEchoReply        = 10

	// LCP option types we care about. Types are 1 byte; values are length-prefixed.
	lcpOptMRU          = 1
	lcpOptMagicNumber  = 5
	ipcpOptIPAddress   = 3

	// Control-plane queue depth. A handful of pending control frames (Configure-Request /
	// Echo-Reply / Terminate-Ack) is plenty; if the queue fills we drop and log rather than
	// block the read loop and stall the link.
	controlQueueDepth = 16
	// Data-plane queue depth: large enough to absorb a typical TCP burst, small enough that
	// we surface drops promptly if the gateway link is the bottleneck.
	dataQueueDepth = 256
)

// runPPP drives the PPP state machine for the lifetime of the session: reads frames off the
// TLS stream, dispatches LCP/IPCP control plane to a small ack-everything implementation, and
// forwards IPv4 packets to the netstack channel endpoint. Outbound IPv4 packets pulled from
// the channel are wrapped in PPP+Fortinet-encap and written back to the TLS stream.
//
// Returns when both read- and write-loops have exited. The shutdown signal can come from any
// of: (a) ctx cancelled by parent, (b) gateway sent LCP Terminate-Request, (c) read error on
// the underlying TLS conn (e.g. session.Conn.Close from cleanup).
func runPPP(ctx context.Context, sess *session, ch *channel.Endpoint) {
	pppCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	state := &pppState{
		conn:         sess.Conn,
		ch:           ch,
		assignedIP:   sess.AssignedIP,
		cancel:       cancel,
		controlFrame: make(chan []byte, controlQueueDepth),
		dataFrame:    make(chan []byte, dataQueueDepth),
	}
	state.nextID.Store(1)

	// Pick a random 4-byte MagicNumber so we can detect loopback (peer echoing our frames
	// back at us) per RFC 1661 §6.4. A zero magic means "no magic," which both disables
	// loopback detection AND is treated as "no option" by some FortiGate firmwares — neither
	// is what we want.
	var magic [4]byte
	if _, err := rand.Read(magic[:]); err != nil {
		// crypto/rand on Windows almost never fails, but if it does, fall back to a fixed
		// non-zero value rather than letting magic stay all-zero (which is the worst case).
		copy(magic[:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	}
	state.ourMagic.Store(binary.BigEndian.Uint32(magic[:]))

	// Initial LCP Configure-Request advertises our MagicNumber and a conservative MRU. Some
	// FortiGate firmwares wait for the client to send a meaningful Configure-Request before
	// progressing IPCP; an empty one is silently Nak'd and the link stalls.
	initialOpts := buildLCPInitialOptions(magic, sess.MTU)
	state.sendLCP(lcpConfigureRequest, state.allocID(), initialOpts)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		state.writerLoop(pppCtx)
	}()
	go func() {
		defer wg.Done()
		state.readLoop(pppCtx)
	}()
	go func() {
		defer wg.Done()
		state.dataLoop(pppCtx)
	}()

	wg.Wait()
}

type pppState struct {
	conn       net.Conn
	ch         *channel.Endpoint
	assignedIP netip.Addr
	cancel     context.CancelFunc
	nextID     atomic.Uint32

	// Our LCP MagicNumber (set once at startup). Peer Configure-Requests that echo this value
	// back to us indicate a loopback per RFC 1661 §6.4 and are rejected.
	ourMagic atomic.Uint32

	// Separate channels for control- vs data-plane frames so a stalled bulk IPv4 write
	// can't delay an LCP Echo-Reply past the gateway's dead-peer-detection window. The
	// single writerLoop is the only goroutine that touches s.conn for writes — no mutex
	// needed.
	controlFrame chan []byte
	dataFrame    chan []byte
}

func (s *pppState) allocID() byte {
	return byte(s.nextID.Add(1) & 0xff)
}

// readLoop reads encap-framed PPP frames off s.conn synchronously. INVARIANT: this loop
// only unblocks when s.conn is closed (or returns a read error). Context cancellation alone
// does NOT interrupt io.ReadFull — writerLoop's defer must close s.conn on exit so the
// teardown chain (handleLCP Terminate-Request, gateway RST, cleanup) can actually unblock
// this goroutine. cleanup() in main.go also closes s.conn explicitly as a belt-and-braces.
func (s *pppState) readLoop(ctx context.Context) {
	defer s.cancel()
	var hdr [fortinetEncapHeaderSz]byte
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				logf("ppp read header: %v", err)
			}
			return
		}
		// Compare in uint32 so a malicious payloadLen of 0xFFFF doesn't wrap when we add the
		// 6-byte header overhead. The uint16-vs-untyped-constant arithmetic that used to live
		// here let a frame with totalLen=5, payloadLen=0xFFFF slip past validation and stall
		// the reader on 65535 bytes that never arrived. payloadLen < 2 is also rejected
		// upfront — every legitimate PPP frame carries at least a 2-byte protocol field, so
		// shorter payloads are malformed and used to busy-loop the reader (read header,
		// read zero/one bytes, skip via `len(buf) < 2`, repeat).
		totalLen := uint32(binary.BigEndian.Uint16(hdr[0:2]))
		magic := binary.BigEndian.Uint16(hdr[2:4])
		payloadLen := uint32(binary.BigEndian.Uint16(hdr[4:6]))
		if magic != fortinetEncapMagic ||
			totalLen != payloadLen+fortinetEncapHeaderSz ||
			payloadLen < 2 ||
			payloadLen > fortinetMaxPayloadLen {
			logf("ppp frame header invalid: total=%d magic=%#x payload=%d (max=%d)",
				totalLen, magic, payloadLen, fortinetMaxPayloadLen)
			return
		}
		buf := make([]byte, payloadLen)
		if _, err := io.ReadFull(s.conn, buf); err != nil {
			logf("ppp read payload: %v", err)
			return
		}
		proto := binary.BigEndian.Uint16(buf[0:2])
		payload := buf[2:]
		switch proto {
		case pppProtoLCP:
			s.handleLCP(payload)
		case pppProtoIPCP:
			s.handleIPCP(payload)
		case pppProtoIPv4:
			s.injectIPv4(payload)
		default:
			// Unknown / unsupported (IPv6CP, CCP, etc.) — drop silently. A real impl would
			// send Protocol-Reject; openconnect just logs and drops.
		}
	}
}

// dataLoop pulls outbound IPv4 packets from the netstack channel endpoint and enqueues them
// onto the data-plane frame channel. It does NOT write to the TLS conn directly — only the
// writerLoop does, so the control plane never contends with a stalled bulk write. The
// enqueue blocks rather than drops: writerLoop's strict-priority drain always preempts
// data with pending control frames, so blocking here is safe and lets the gVisor TCP stack
// see proper backpressure (filling the channel.Endpoint queue, then send-buffer, then
// stalling the SOCKS5 reader) instead of TCP-style retransmits triggered by silent drops.
func (s *pppState) dataLoop(ctx context.Context) {
	for {
		pkt := s.ch.ReadContext(ctx)
		if pkt == nil {
			return
		}
		buf := pkt.ToBuffer()
		pkt.DecRef()
		raw := buf.Flatten()
		frame := buildEncapFrame(pppProtoIPv4, raw)
		select {
		case s.dataFrame <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// writerLoop is the sole writer of s.conn. It STRICTLY prefers control-plane frames: every
// iteration first drains every pending control frame, and even on cancellation it performs
// one last drain so a Terminate-Ack queued immediately before s.cancel() (handleLCP's
// shutdown handshake) reaches the wire before we close the conn. Returns only after the
// final drain — the close-conn defer then unblocks readLoop's synchronous io.ReadFull.
func (s *pppState) writerLoop(ctx context.Context) {
	defer s.cancel()
	defer func() { _ = s.conn.Close() }()
	for {
		// Always drain pending control frames first — BEFORE checking ctx — so a control
		// frame enqueued immediately before cancellation (the canonical case: handleLCP's
		// Terminate-Ack → s.cancel() sequence) still reaches the wire. Previously this
		// check was at the top of the iteration alongside ctx.Err(), opening a window
		// where a just-enqueued Ack could be skipped if cancellation was observed first.
		drainedControl := false
		for {
			select {
			case frame := <-s.controlFrame:
				if err := s.writeFrame(ctx, frame); err != nil {
					return
				}
				drainedControl = true
				continue
			default:
			}
			break
		}
		if drainedControl {
			// Loop back; the next iteration's drain will pick up anything that arrived
			// while we were writing, and the bottom-select will exit cleanly if ctx is done.
			continue
		}
		// Control plane is empty — block on a new control frame (which preempts data), a
		// data frame, or cancellation. NOTE: Go's select picks pseudo-randomly when
		// multiple cases are ready; the data arm re-checks controlFrame before writing,
		// and the ctx.Done arm performs ONE FINAL drain so any control frame that landed
		// in the same scheduling tick as cancellation still reaches the wire.
		select {
		case frame := <-s.controlFrame:
			if err := s.writeFrame(ctx, frame); err != nil {
				return
			}
		case frame := <-s.dataFrame:
			// Re-check control non-blockingly. If we just lost the random tiebreak
			// against a concurrently-ready control frame, write it before the data.
			select {
			case cframe := <-s.controlFrame:
				if err := s.writeFrame(ctx, cframe); err != nil {
					return
				}
			default:
			}
			if err := s.writeFrame(ctx, frame); err != nil {
				return
			}
		case <-ctx.Done():
			// Final drain: the canonical shutdown path is handleLCP → sendLCP(TermAck)
			// (enqueue) → s.cancel() (ctx fires). If the two events land in the same
			// scheduling tick, Go's select may pick ctx.Done() first; without this drain
			// the queued Terminate-Ack would be dropped on the floor and the gateway
			// would see an abrupt close instead of a graceful shutdown. Bounded by
			// controlQueueDepth, so it can't loop forever.
			for {
				select {
				case frame := <-s.controlFrame:
					// Pass a fresh background context to writeFrame so it doesn't suppress
					// the log on a real write error during the drain; the write itself is
					// still bounded by s.conn's own write deadline (none today, but a TLS
					// conn under sustained back-pressure would surface here).
					if _, werr := s.conn.Write(frame); werr != nil {
						// Conn likely closed by the other side; nothing more to flush.
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *pppState) writeFrame(ctx context.Context, frame []byte) error {
	if frame == nil {
		return nil
	}
	if _, err := s.conn.Write(frame); err != nil {
		if ctx.Err() == nil {
			logf("ppp write: %v", err)
		}
		return err
	}
	return nil
}

func (s *pppState) injectIPv4(packet []byte) {
	// Sanity-check the IPv4 header before handing to gVisor. The Fortinet encap validator
	// already bounds the frame length, but the inner IPv4 fields are still gateway-supplied
	// — pre-filtering here matches the defense-in-depth posture established for the encap
	// header and avoids forcing gVisor to alloc/parse/drop garbage at line rate.
	const minIPv4Header = 20
	if len(packet) < minIPv4Header {
		return
	}
	// IP version must be 4 (top nibble of byte 0).
	if packet[0]>>4 != 4 {
		return
	}
	// Total length field (bytes 2-3) must equal what we have, per RFC 791. We don't try to
	// handle IP fragmentation reassembly here — gVisor does that downstream.
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < minIPv4Header || totalLen > len(packet) {
		return
	}
	// Hand the raw IPv4 packet to netstack. The channel endpoint's stack will route it to
	// the appropriate transport listener (e.g. the dialer-side TCP socket).
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet[:totalLen]),
	})
	s.ch.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (s *pppState) sendPPP(proto uint16, payload []byte, control bool) {
	frame := buildEncapFrame(proto, payload)
	ch := s.dataFrame
	if control {
		ch = s.controlFrame
	}
	// Non-blocking enqueue: if the channel is full, drop and log rather than stall the
	// caller (which is usually the read loop dispatching a control reply).
	select {
	case ch <- frame:
	default:
		logf("ppp frame queue full (control=%v); dropping", control)
	}
}

// buildEncapFrame produces a single Fortinet-encapsulated PPP frame for the given protocol
// and payload. Pure function — no IO, no state.
func buildEncapFrame(proto uint16, payload []byte) []byte {
	frame := make([]byte, fortinetEncapHeaderSz+2+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(fortinetEncapHeaderSz+2+len(payload)))
	binary.BigEndian.PutUint16(frame[2:4], fortinetEncapMagic)
	binary.BigEndian.PutUint16(frame[4:6], uint16(2+len(payload)))
	binary.BigEndian.PutUint16(frame[6:8], proto)
	copy(frame[8:], payload)
	return frame
}

// handleLCP implements just enough of the LCP state machine to bring the link up and respond
// to gateway-initiated maintenance: Ack Configure-Request, reply to Echo-Request, Ack and
// tear down on Terminate-Request, and reject any frame that mirrors our MagicNumber.
func (s *pppState) handleLCP(payload []byte) {
	code, id, body, ok := parseCPFrame(payload)
	if !ok {
		return
	}
	switch code {
	case lcpConfigureRequest:
		if s.peerEchoedOurMagic(body) {
			// Loopback detected — the peer is bouncing our own MagicNumber back at us per
			// RFC 1661 §6.4. Don't Ack; respond Code-Reject and let the link die.
			logf("ppp LCP loopback detected (peer echoed our MagicNumber); rejecting")
			s.sendLCP(lcpCodeReject, id, payload)
			s.cancel()
			return
		}
		s.sendLCP(lcpConfigureAck, id, body)
	case lcpEchoRequest:
		s.sendLCP(lcpEchoReply, id, body)
	case lcpTerminateRequest:
		// Per RFC 1661 §6.6: respond with Terminate-Ack and transition to the Stopped state.
		// We signal teardown to the rest of the sidecar by cancelling the PPP context, which
		// the cleanup function in main.go's startFortinet observes via wg.Wait().
		logf("ppp peer sent LCP Terminate-Request; sending Terminate-Ack and tearing down")
		s.sendLCP(lcpTerminateAck, id, body)
		s.cancel()
	case lcpConfigureAck, lcpConfigureNak, lcpConfigureReject, lcpEchoReply, lcpTerminateAck, lcpCodeReject:
		// no-op
	}
}

// handleIPCP brings up the network layer. The gateway's Configure-Request announces the IP
// address it wants the client to use; we compare to the address we already bound at the
// channel.Endpoint (from the XML config). A mismatch means the gateway changed its mind
// after the XML — Ack'ing would leave the netstack bound to the XML IP while the gateway
// thinks we accepted a different one, and every outbound packet would carry the wrong
// source. Per RFC 1332 §3.3 the correct response is Configure-Nak with our preferred
// address; the gateway will then either re-issue with our value or Reject and we tear down.
func (s *pppState) handleIPCP(payload []byte) {
	code, id, body, ok := parseCPFrame(payload)
	if !ok {
		return
	}
	switch code {
	case lcpConfigureRequest:
		if announced, ok := extractIPCPAddress(body); ok && announced.IsValid() && announced != s.assignedIP {
			// Log the mismatch BEFORE attempting to build the Nak, so operators see the
			// peer/netstack disagreement context regardless of whether the build path
			// errors. (Previously this log only fired on the success path, so a defensive
			// fallback would have hidden the cause.)
			logf("ppp IPCP peer announced IP-Address=%s but netstack is bound to %s (XML)",
				announced, s.assignedIP)
			// Build a Nak body containing the IP-Address option with OUR address. Per RFC 1332
			// §3.3 a Nak preserves option order; we only carry the one option we disagree on.
			nak, err := buildIPCPAddressOption(s.assignedIP)
			if err != nil {
				// Should be unreachable because parseTunnelConfigXML rejects non-v4 addresses,
				// but if it ever IS reached, Ack'ing into a known-broken state (gateway thinks
				// we accepted its IP; our netstack stays bound to ours; outbound source IP
				// wrong; replies silently dropped) is worse than tearing down. Hard-fail.
				logf("ppp IPCP cannot build Nak for assignedIP=%s (%v); tearing down rather than Ack'ing into a broken state",
					s.assignedIP, err)
				s.cancel()
				return
			}
			logf("ppp IPCP replying Configure-Nak with our address")
			s.sendIPCP(lcpConfigureNak, id, nak)
			return
		}
		s.sendIPCP(lcpConfigureAck, id, body)
	case lcpConfigureAck, lcpConfigureNak, lcpConfigureReject:
		// no-op
	}
}

// buildIPCPAddressOption returns the bytes of an IPCP IP-Address option (type=3, len=6,
// value=4 bytes of IPv4). Returns an error for non-v4 addresses rather than silently
// emitting a 0.0.0.0 option, which the gateway would reject in a confusing way.
func buildIPCPAddressOption(addr netip.Addr) ([]byte, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("expected IPv4 address, got %v", addr)
	}
	v := addr.As4()
	out := []byte{ipcpOptIPAddress, 6, v[0], v[1], v[2], v[3]}
	return out, nil
}

func (s *pppState) sendLCP(code byte, id byte, body []byte) {
	frame := buildCPFrame(code, id, body)
	s.sendPPP(pppProtoLCP, frame, true)
}

func (s *pppState) sendIPCP(code byte, id byte, body []byte) {
	frame := buildCPFrame(code, id, body)
	s.sendPPP(pppProtoIPCP, frame, true)
}

func buildCPFrame(code, id byte, body []byte) []byte {
	frame := make([]byte, 4+len(body))
	frame[0] = code
	frame[1] = id
	binary.BigEndian.PutUint16(frame[2:4], uint16(4+len(body)))
	copy(frame[4:], body)
	return frame
}

// parseCPFrame decodes the common LCP/IPCP control-frame header (code, id, length) and
// returns the option body. Returns ok=false for any frame too short to contain a header or
// whose self-reported length is inconsistent with the buffer — guards against the slice-OOB
// panic that would otherwise fire when a peer sends length<4 or length>len(payload).
func parseCPFrame(payload []byte) (code, id byte, body []byte, ok bool) {
	if len(payload) < 4 {
		return 0, 0, nil, false
	}
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	// Lower bound: length includes the 4-byte header, so anything < 4 means a malformed
	// frame and slicing payload[4:length] would panic with low > high. Upper bound: a
	// length past the available bytes means a truncated frame.
	if length < 4 || length > len(payload) {
		return 0, 0, nil, false
	}
	return payload[0], payload[1], payload[4:length], true
}

// buildLCPInitialOptions emits an LCP option list containing our MagicNumber and a
// conservative MRU. Option encoding per RFC 1661 §6: type (1B), length (1B), value.
func buildLCPInitialOptions(magic [4]byte, mtu int) []byte {
	// Use the discovered MTU from the XML config (or 1500 default) as the announced MRU. The
	// gateway may Nak to something else, which handleLCP currently no-ops on — improving
	// that is a follow-up.
	if mtu <= 0 || mtu > 0xFFFF {
		mtu = 1500
	}
	out := make([]byte, 0, 10)
	// MRU
	out = append(out, lcpOptMRU, 4, byte(mtu>>8), byte(mtu&0xff))
	// MagicNumber
	out = append(out, lcpOptMagicNumber, 6, magic[0], magic[1], magic[2], magic[3])
	return out
}

// peerEchoedOurMagic looks for an LCP MagicNumber option (type=5, len=6) whose 4-byte
// value matches ourMagic anywhere in the body. Per RFC 1661 §6.4, that mirror is the
// loopback-detection signal.
//
// We deliberately scan byte-by-byte for the 6-byte signature {0x05, 0x06, magic[0..3]}
// rather than walking the option list with its attacker-supplied length fields. An option-
// walk can be mis-aligned by a single malformed prefix (e.g., {0x01,0x01,0x05,0x06,M...})
// such that the parser's "i += l" step hops OVER the real mirror — a fail-open hole no
// matter whether we abort or skip-one-byte on malformed entries. A sliding-window pattern
// match is the only correct posture for this defense.
func (s *pppState) peerEchoedOurMagic(body []byte) bool {
	ourMagic := s.ourMagic.Load()
	// ourMagic is initialized in runPPP from crypto/rand with a non-zero fallback, so a
	// zero value here means runPPP was bypassed (a test, a future refactor). Treat it as
	// "loopback detection unavailable" — return false rather than emitting our magic on the
	// wire as zero (which RFC 1661 says means "no magic" and disables peer detection too).
	if ourMagic == 0 {
		return false
	}
	var want [6]byte
	want[0] = lcpOptMagicNumber
	want[1] = 6
	binary.BigEndian.PutUint32(want[2:6], ourMagic)
	for i := 0; i+6 <= len(body); i++ {
		if body[i] == want[0] && body[i+1] == want[1] &&
			body[i+2] == want[2] && body[i+3] == want[3] &&
			body[i+4] == want[4] && body[i+5] == want[5] {
			return true
		}
	}
	return false
}

// extractIPCPAddress walks an IPCP option list looking for the IP-Address option (type=3,
// len=6) and returns its 4-byte value as a netip.Addr.
//
// Like peerEchoedOurMagic this uses a sliding-window byte scan for the 6-byte signature
// {0x03, 0x06, b0, b1, b2, b3} rather than an option-walk with attacker-supplied length
// fields. A malformed-length prefix would otherwise let the parser's i += l step hop OVER
// the real IP-Address option, suppressing the mismatch detection in handleIPCP and letting
// a hostile gateway tell us "I accept your IP" while routing its return traffic to a
// different address — silent dead tunnel with no log line.
func extractIPCPAddress(body []byte) (netip.Addr, bool) {
	for i := 0; i+6 <= len(body); i++ {
		if body[i] == ipcpOptIPAddress && body[i+1] == 6 {
			var buf [4]byte
			copy(buf[:], body[i+2:i+6])
			return netip.AddrFrom4(buf), true
		}
	}
	return netip.Addr{}, false
}
