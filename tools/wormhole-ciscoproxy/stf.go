package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Cisco AnyConnect CSTP data framing ("STF" packets): an 8-byte header in front of every
// payload, per openconnect/cstp.c.
//
//	bytes 0-2: magic 'S' 'T' 'F'  (0x53 0x54 0x46)
//	byte  3  : 0x01 (version)
//	bytes 4-5: payload length (big-endian, NOT including these 8 header bytes)
//	byte  6  : packet type (see below)
//	byte  7  : 0x00
//
// For AC_PKT_DATA the payload is a raw IPv4 packet.
const (
	stfHeaderSz = 8

	// Sanity cap for a single CSTP frame payload. AnyConnect MTUs are ~1400; pin a generous
	// upper bound so a corrupt / malicious header can't lead us to allocate an absurd buffer or
	// block ReadFull on bytes that will never arrive. Also bounds the netstack MTU clamp.
	cstpMaxPayloadLen = 16 * 1024

	// AC_PKT_* packet types.
	acData       = 0
	acDPDOut     = 3
	acDPDResp    = 4
	acDisconnect = 5
	acKeepalive  = 7
	acCompressed = 8
	acTermServer = 9

	// Control-plane queue depth (DPD responses, keepalives). A handful is plenty.
	controlQueueDepth = 16
	// Data-plane queue depth: large enough to absorb a typical TCP burst.
	dataQueueDepth = 256

	// Floor/ceiling for the DPD keepalive cadence we send to the gateway, regardless of the
	// advertised X-CSTP-DPD value, so a hostile/absent value can't busy-spin or let the session
	// idle out.
	minDPDInterval     = 5 * time.Second
	defaultDPDInterval = 30 * time.Second
)

var stfMagic = [4]byte{'S', 'T', 'F', 0x01}

// startCisco performs the AnyConnect login + CSTP upgrade, brings up a gVisor netstack endpoint,
// and returns a SOCKS5 dialer that routes through the virtual network plus an arm/cleanup pair.
// The data loop runs in a background goroutine for the lifetime of the returned cleanup; cleanup
// waits for it before tearing down the gVisor stack so the read/write loops never touch a closed
// stack. Mirrors the Fortinet sidecar's startFortinet contract (arm-after-READY, watcher fires
// outerCancel on gateway-initiated teardown).
func startCisco(ctx context.Context, outerCancel context.CancelFunc, cfg config) (sockstun.Dialer, func(), func(), error) {
	if outerCancel == nil {
		return nil, nil, nil, errors.New("outerCancel is required")
	}
	if cfg.Host == "" {
		return nil, nil, nil, errors.New("host is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, nil, nil, errors.New("username and password are required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, nil, nil, fmt.Errorf("invalid port %d", cfg.Port)
	}

	sess, err := ciscoLogin(ctx, cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("login: %w", err)
	}
	logf("anyconnect login ok: assigned %s mtu=%d dns=%v dpd=%ds", sess.AssignedIP, sess.MTU, sess.DNS, sess.DPDSeconds)

	netStack, ch, err := newNetstack(sess.AssignedIP, sess.MTU)
	if err != nil {
		_ = sess.Conn.Close()
		return nil, nil, nil, fmt.Errorf("netstack: %w", err)
	}

	loopCtx, loopCancel := context.WithCancel(ctx)
	loopDone := make(chan struct{})
	ready := make(chan struct{})

	var readyClosed bool
	closeReadyOnce := func() {
		if readyClosed {
			return
		}
		readyClosed = true
		close(ready)
	}

	started := false
	defer func() {
		if started {
			return
		}
		closeReadyOnce()
		loopCancel()
		_ = sess.Conn.Close()
		<-loopDone
		netStack.Close()
	}()

	go func() {
		defer close(loopDone)
		runCSTP(loopCtx, sess, ch)
	}()

	// Propagate gateway-initiated teardown back to the OUTER ctx (gateway DISCONNECT/TERMINATE
	// or a read error). Without this, the data loop would exit but the SOCKS5 accept loop in
	// run() would keep accepting connections that can never carry traffic. Gated on `ready` so
	// the watcher can't fire outerCancel before run() prints READY (the phantom-READY race).
	go func() {
		<-ready
		<-loopDone
		logf("cstp loop exited; cancelling outer ctx so run() can shut down")
		outerCancel()
	}()

	cleanup := func() {
		closeReadyOnce()
		loopCancel()
		_ = sess.Conn.Close()
		<-loopDone
		netStack.Close()
	}
	arm := closeReadyOnce

	started = true
	return newNetstackDialer(netStack, sess.AssignedIP, sess.DNS), arm, cleanup, nil
}

type cstpState struct {
	conn   net.Conn
	reader *bufio.Reader
	ch     *channel.Endpoint
	cancel context.CancelFunc

	dpdInterval time.Duration

	// Separate channels for control- vs data-plane frames so a stalled bulk IPv4 write can't
	// delay a DPD response past the gateway's dead-peer-detection window. The single writerLoop
	// is the only goroutine that touches conn for writes — no mutex needed.
	controlFrame chan []byte
	dataFrame    chan []byte
}

// runCSTP drives the CSTP data plane for the lifetime of the session: reads STF frames off the
// TLS stream, responds to DPD/keepalive control packets, and forwards IPv4 payloads to the
// netstack. Outbound IPv4 packets pulled from the channel are STF-framed and written back.
func runCSTP(ctx context.Context, sess *session, ch *channel.Endpoint) {
	cstpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	interval := defaultDPDInterval
	if sess.DPDSeconds > 0 {
		interval = time.Duration(sess.DPDSeconds) * time.Second
	}
	if interval < minDPDInterval {
		interval = minDPDInterval
	}

	s := &cstpState{
		conn:         sess.Conn,
		reader:       sess.Reader,
		ch:           ch,
		cancel:       cancel,
		dpdInterval:  interval,
		controlFrame: make(chan []byte, controlQueueDepth),
		dataFrame:    make(chan []byte, dataQueueDepth),
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); s.writerLoop(cstpCtx) }()
	go func() { defer wg.Done(); s.readLoop(cstpCtx) }()
	go func() { defer wg.Done(); s.dataLoop(cstpCtx) }()
	go func() { defer wg.Done(); s.dpdLoop(cstpCtx) }()
	wg.Wait()
}

// readLoop reads STF frames off s.reader synchronously. INVARIANT: this loop only unblocks when
// the underlying conn is closed (or returns a read error). Context cancellation alone does NOT
// interrupt io.ReadFull — writerLoop's defer closes s.conn on exit so the teardown chain can
// unblock this goroutine; cleanup() in startCisco also closes s.conn as belt-and-braces.
func (s *cstpState) readLoop(ctx context.Context) {
	defer s.cancel()
	var hdr [stfHeaderSz]byte
	for {
		if _, err := io.ReadFull(s.reader, hdr[:]); err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				logf("cstp read header: %v", err)
			}
			return
		}
		if hdr[0] != stfMagic[0] || hdr[1] != stfMagic[1] || hdr[2] != stfMagic[2] || hdr[3] != stfMagic[3] {
			logf("cstp frame header invalid: %#x %#x %#x %#x (want STF\\x01)", hdr[0], hdr[1], hdr[2], hdr[3])
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(hdr[4:6]))
		ptype := hdr[6]
		if payloadLen > cstpMaxPayloadLen {
			logf("cstp frame payload %d exceeds max %d; tearing down", payloadLen, cstpMaxPayloadLen)
			return
		}
		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(s.reader, payload); err != nil {
				logf("cstp read payload: %v", err)
				return
			}
		}
		switch ptype {
		case acData:
			s.injectIPv4(payload)
		case acDPDOut:
			// Gateway dead-peer-detection probe — reply so it knows we're alive.
			s.sendControl(acDPDResp, nil)
		case acDPDResp, acKeepalive:
			// Replies to our own probes / idle keepalives — nothing to do.
		case acDisconnect:
			logf("cstp gateway sent DISCONNECT; tearing down")
			return
		case acTermServer:
			logf("cstp gateway sent TERMINATE; tearing down")
			return
		case acCompressed:
			// We never advertise X-CSTP-Accept-Encoding, so the gateway shouldn't compress.
			// If it does anyway, we can't decode it — drop and log rather than corrupt the stack.
			logf("cstp received a compressed frame but compression was not negotiated; dropping")
		default:
			logf("cstp unknown frame type %d (len %d); dropping", ptype, payloadLen)
		}
	}
}

// dataLoop pulls outbound IPv4 packets from the netstack channel endpoint and enqueues them
// onto the data-plane frame channel. It does NOT write to the TLS conn directly — only the
// writerLoop does, so the control plane never contends with a stalled bulk write. The enqueue
// blocks rather than drops so the gVisor TCP stack sees proper backpressure.
func (s *cstpState) dataLoop(ctx context.Context) {
	for {
		pkt := s.ch.ReadContext(ctx)
		if pkt == nil {
			return
		}
		buf := pkt.ToBuffer()
		pkt.DecRef()
		raw := buf.Flatten()
		frame, err := buildSTFFrame(acData, raw)
		if err != nil {
			logf("cstp dataLoop: dropping oversized IPv4 packet: %v", err)
			continue
		}
		select {
		case s.dataFrame <- frame:
		case <-ctx.Done():
			return
		}
	}
}

// dpdLoop periodically sends a DPD probe so the gateway keeps the session alive across idle
// periods (and NAT mappings don't expire). The gateway answers with AC_PKT_DPD_RESP, which
// readLoop ignores.
func (s *cstpState) dpdLoop(ctx context.Context) {
	t := time.NewTicker(s.dpdInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sendControl(acDPDOut, nil)
		}
	}
}

// writerLoop is the sole writer of s.conn. It STRICTLY prefers control-plane frames: every
// iteration first drains every pending control frame, and even on cancellation it performs one
// last drain so a DPD response queued immediately before teardown reaches the wire. Returns only
// after the final drain — the close-conn defer then unblocks readLoop's synchronous io.ReadFull.
func (s *cstpState) writerLoop(ctx context.Context) {
	defer s.cancel()
	defer func() { _ = s.conn.Close() }()
	for {
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
			continue
		}
		select {
		case frame := <-s.controlFrame:
			if err := s.writeFrame(ctx, frame); err != nil {
				return
			}
		case frame := <-s.dataFrame:
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
			for {
				select {
				case frame := <-s.controlFrame:
					if _, werr := s.conn.Write(frame); werr != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *cstpState) writeFrame(ctx context.Context, frame []byte) error {
	if frame == nil {
		return nil
	}
	if _, err := s.conn.Write(frame); err != nil {
		if ctx.Err() == nil {
			logf("cstp write: %v", err)
		}
		return err
	}
	return nil
}

// sendControl enqueues a control frame (DPD/keepalive). Non-blocking: if the control queue is
// full, drop and log rather than stall the read loop that usually calls this.
func (s *cstpState) sendControl(ptype byte, payload []byte) {
	frame, err := buildSTFFrame(ptype, payload)
	if err != nil {
		logf("cstp sendControl: dropping oversized frame (type=%d): %v", ptype, err)
		return
	}
	select {
	case s.controlFrame <- frame:
	default:
		logf("cstp control queue full; dropping type=%d frame", ptype)
	}
}

func (s *cstpState) injectIPv4(packet []byte) {
	const minIPv4Header = 20
	if len(packet) < minIPv4Header {
		return
	}
	if packet[0]>>4 != 4 {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < minIPv4Header || totalLen > len(packet) {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet[:totalLen]),
	})
	s.ch.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// buildSTFFrame produces a single STF-framed CSTP packet. Pure function — no IO, no state.
// Returns an error if the payload would overflow the 16-bit length field; callers log+drop.
func buildSTFFrame(ptype byte, payload []byte) ([]byte, error) {
	if len(payload) > cstpMaxPayloadLen {
		return nil, fmt.Errorf("cstp frame payload too large: %d (max %d)", len(payload), cstpMaxPayloadLen)
	}
	frame := make([]byte, stfHeaderSz+len(payload))
	frame[0] = stfMagic[0]
	frame[1] = stfMagic[1]
	frame[2] = stfMagic[2]
	frame[3] = stfMagic[3]
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	frame[6] = ptype
	frame[7] = 0x00
	copy(frame[8:], payload)
	return frame, nil
}
