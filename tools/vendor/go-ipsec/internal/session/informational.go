package session

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// driverTick is the driver's housekeeping granularity (retransmit, rekey and
// DPD deadline checks).
const driverTick = time.Second

// rekeyRetryInterval is how long to wait before retrying a rekey that was
// abandoned (peer unresponsive to the CREATE_CHILD_SA).
const rekeyRetryInterval = time.Minute

// Suspend/wake detection. The driver ticks every driverTick, so a wall-clock gap
// between ticks far larger than that means the host was suspended (laptop sleep).
// The monotonic clock is frozen across a suspend, so lastInbound looks recent and
// ordinary DPD would not probe for another dpdInterval; on a NAT'd UDP tunnel the
// mapping has very likely expired meanwhile, so a wake triggers an immediate DPD
// probe on a tightened schedule (fastDPDBase/fastDPDTries) that declares the peer
// dead within a few seconds instead of the ~90s the default schedule takes.
const (
	suspendThreshold = 5 * time.Second
	fastDPDBase      = 1 * time.Second
	fastDPDTries     = 2
)

// encodeSKEmpty builds an SK{} message with no inner payloads under the current
// IKE SA (DPD probe / generic ack).
func (s *Session) encodeSKEmpty(exchangeType ikemsg.ExchangeType, flags ikemsg.Flags, msgID uint32) ([]byte, error) {
	return encodeSKEmptyWith(&ikeCtx{s.ikeSA, s.initiatorSPI, s.responderSPI}, exchangeType, flags, msgID)
}

func encodeSKEmptyWith(c *ikeCtx, exchangeType ikemsg.ExchangeType, flags ikemsg.Flags, msgID uint32) ([]byte, error) {
	skData, err := c.sa.EncryptToSK(nil)
	if err != nil {
		return nil, err
	}
	m := &ikemsg.Message{
		InitiatorSPI: c.spii,
		ResponderSPI: c.spir,
		Exchange:     exchangeType,
		Flags:        flags,
		MessageID:    msgID,
		Payloads:     ikemsg.Payloads{&ikemsg.EncryptedPayload{InnerFirst: ikemsg.PayloadNone, Data: skData}},
	}
	raw, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	if err := c.sa.FinalizeSK(raw, len(skData)); err != nil {
		return nil, err
	}
	return raw, nil
}

// Driver runs the post-handshake IKE control loop on a single goroutine — the
// sole writer of IKE state after the handshake. It answers server-initiated
// requests (DPD, DELETE, CREATE_CHILD_SA rekey), initiates Child/IKE SA rekey
// before the soft lifetime, sends periodic DPD probes when idle, retransmits the
// single outstanding request (IKEv2 window size 1), and sends a graceful DELETE
// on shutdown. ikeInbox carries inbound IKE datagrams from the rx demux; onDead
// fires once if the peer is declared dead or tears the IKE SA down.
func (s *Session) Driver(ctx context.Context, ikeInbox <-chan []byte, onDead func()) {
	now := time.Now()
	s.lastInbound = now
	s.lastTickWall = now.Round(0) // wall-clock baseline for suspend/wake detection
	if s.childInstalledAt.IsZero() {
		s.childInstalledAt = now
	}
	if s.ikeInstalledAt.IsZero() {
		s.ikeInstalledAt = now
	}
	s.nextChildRekey = jitteredDeadline(s.childInstalledAt, s.cfg.RekeyLifetime)
	s.nextIKERekey = jitteredDeadline(s.ikeInstalledAt, s.ikeRekeyLifetime())

	tick := time.NewTicker(driverTick)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			s.sendGracefulDelete()
			return
		case raw := <-ikeInbox:
			if s.handleInbound(ctx, raw, onDead) {
				return
			}
		case <-tick.C:
			if s.housekeeping(ctx, onDead) {
				return
			}
		}
	}
}

// handleInbound dispatches one decoded inbound IKE datagram. It returns true if
// the session should tear down (server DELETE of the current IKE SA).
func (s *Session) handleInbound(ctx context.Context, raw []byte, onDead func()) (exit bool) {
	hdr, inner, dec, err := s.decodeIKE(raw)
	if err != nil {
		s.log.Debug("driver: undecodable IKE datagram", "err", err)
		return false
	}
	// Liveness clock: refresh ONLY on a datagram whose ICV decodeIKE has verified.
	// Counting unauthenticated traffic here would let any stray/spoofed UDP to our
	// :4500 keep the clock fresh and suppress DPD, masking a dead tunnel (the ESP
	// data-plane clock is likewise gated on a successful Decrypt).
	s.lastInbound = time.Now()
	isResponse := hdr.Flags.IsResponse()
	viaOld := s.oldIKE != nil && dec.sa == s.oldIKE.sa

	switch hdr.Exchange {
	case ikemsg.ExchangeInformational:
		if isResponse {
			// An old-SA response acks our superseded-SA DELETE; a current-SA
			// response acks our current pending exchange. Keep them separate so a
			// numeric Message-ID coincidence across SAs can't cross-clear.
			if viaOld {
				s.clearOldIKEDelete(hdr.MessageID)
			} else {
				s.clearPending(hdr.MessageID)
			}
			return false
		}
		if s.dedupPeerRequest(ctx, hdr.MessageID, viaOld) {
			return false
		}
		teardown := s.handleInformationalRequest(ctx, hdr, inner, dec, viaOld)
		if teardown {
			onDead()
		}
		return teardown
	case ikemsg.ExchangeCreateChildSA:
		if isResponse {
			s.completeMatchingRekey(ctx, hdr.MessageID, inner, viaOld)
			return false
		}
		if s.dedupPeerRequest(ctx, hdr.MessageID, viaOld) {
			return false
		}
		// Simultaneous rekey: if our own rekey is in flight, reject the peer's
		// with TEMPORARY_FAILURE (RFC 7296 §2.25) rather than installing a second
		// redundant SA and DELETEing the one the other half just installed.
		if s.pending != nil && (s.pending.kind == exChildRekey || s.pending.kind == exIKERekey) {
			s.sendTemporaryFailure(ctx, dec, hdr.MessageID, viaOld)
			return false
		}
		ikeRekey := isIKERekey(inner)
		// A server IKE rekey arriving under the superseded SA during the grace
		// window would force a SECOND cutover keyed from a dying SA, and its
		// swapIKE (s.oldPeer = s.peer) would clobber the response cached for it —
		// leaving a retransmit unanswerable. Decline with TEMPORARY_FAILURE
		// (cached in the oldPeer slot; no swap follows); the peer retries (RFC
		// 7296 §2.25) once the request arrives under the current SA.
		if ikeRekey && viaOld {
			s.sendTemporaryFailure(ctx, dec, hdr.MessageID, viaOld)
			s.log.Debug("declined server IKE rekey arriving under the superseded SA during grace")
			return false
		}
		var rerr error
		if ikeRekey {
			rerr = s.handleIKERekeyRequest(ctx, hdr, inner, dec)
		} else {
			rerr = s.handleChildRekeyRequest(ctx, hdr, inner, dec, viaOld)
		}
		if rerr != nil {
			s.log.Warn("driver: server rekey handling failed", "err", rerr)
		}
		return false
	default:
		s.log.Debug("driver: ignoring exchange", "type", hdr.Exchange)
		return false
	}
}

// dedupPeerRequest enforces responder-side retransmit semantics: a server
// request whose Message ID we have already answered is not reprocessed (which
// would re-derive keys and re-swap SAs); the cached response is resent. It
// returns true when the request was a duplicate and has been handled.
func (s *Session) dedupPeerRequest(ctx context.Context, msgID uint32, viaOld bool) bool {
	dd := &s.peer
	if viaOld {
		dd = &s.oldPeer
	}
	if dd.set && msgID <= dd.msgID {
		if msgID == dd.msgID && dd.resp != nil {
			_ = s.sendDatagram(ctx, dd.resp)
		}
		return true
	}
	return false
}

// recordPeerResponse caches the response sent to a server request so a later
// retransmit of that Message ID is answered without reprocessing.
func (s *Session) recordPeerResponse(viaOld bool, msgID uint32, raw []byte) {
	dd := &s.peer
	if viaOld {
		dd = &s.oldPeer
	}
	dd.msgID = msgID
	dd.set = true
	dd.resp = raw
}

// clearOldIKEDelete clears the tracked superseded-SA DELETE when its ack arrives.
func (s *Session) clearOldIKEDelete(msgID uint32) {
	if s.oldIKEDelete != nil && s.oldIKEDelete.msgID == msgID {
		s.oldIKEDelete = nil
	}
}

// sendNotifyResponse answers a server CREATE_CHILD_SA request with a single
// notify payload and caches it so a retransmit of that Message ID resends the
// exact bytes (responder dedup) instead of being reprocessed as a fresh request.
// what labels the notify in debug logs.
func (s *Session) sendNotifyResponse(ctx context.Context, dec *ikeCtx, msgID uint32, viaOld bool, protocol ikemsg.ProtocolID, notifyType ikemsg.NotifyType, data []byte, what string) {
	resp := ikemsg.Payloads{&ikemsg.NotifyPayload{Protocol: protocol, Type: notifyType, Data: data}}
	raw, err := encodeSKWith(dec.sa, dec.spii, dec.spir,
		ikemsg.ExchangeCreateChildSA, ikeRoleBit(dec.sa.Role)|ikemsg.FlagResponse, msgID, resp)
	if err != nil {
		s.log.Debug("encode "+what+" failed", "err", err)
		return
	}
	s.recordPeerResponse(viaOld, msgID, raw)
	if err := s.sendDatagram(ctx, raw); err != nil {
		s.log.Debug("send "+what+" failed", "err", err)
	}
}

// sendTemporaryFailure answers a server CREATE_CHILD_SA request with a
// TEMPORARY_FAILURE notify (used to decline a colliding simultaneous rekey).
func (s *Session) sendTemporaryFailure(ctx context.Context, dec *ikeCtx, msgID uint32, viaOld bool) {
	s.sendNotifyResponse(ctx, dec, msgID, viaOld, ikemsg.ProtocolNone, ikemsg.NotifyTemporaryFailure, nil, "TEMPORARY_FAILURE")
}

// completeMatchingRekey finishes a rekey we initiated when its response arrives.
// viaOld reports whether the response was decoded under the superseded IKE SA
// (rekey grace window); a rekey we initiated is answered under the current SA, so
// an old-SA response is stale and must not be matched on Message-ID alone — this
// mirrors the INFORMATIONAL response path's old/current discriminator.
func (s *Session) completeMatchingRekey(ctx context.Context, msgID uint32, inner ikemsg.Payloads, viaOld bool) {
	if viaOld {
		return // stale old-SA response; our pending rekey runs under the current SA
	}
	p := s.pending
	if p == nil || p.msgID != msgID {
		return // stale or unsolicited response
	}
	// Only a rekey exchange is completed here. A Message-ID coincidence with an
	// in-flight DPD or DELETE must not clear that pending exchange (the switch below
	// has no case for it, so it would be silently lost).
	if p.kind != exChildRekey && p.kind != exIKERekey {
		return
	}
	s.pending = nil
	var err error
	switch p.kind {
	case exChildRekey:
		if err = s.completeChildRekey(ctx, inner, p); err == nil {
			// Re-arm only on success: on error childInstalledAt is stale (no install
			// happened), and nextChildRekey already holds the retry backoff the
			// initiation set, so leaving it drives a timely retry.
			s.nextChildRekey = jitteredDeadline(s.childInstalledAt, s.cfg.RekeyLifetime)
		}
	case exIKERekey:
		err = s.completeIKERekey(ctx, inner, p)
		// swapIKE (reached via completeIKERekey) is the single arming point for the
		// IKE-rekey deadline; no re-arm here.
	}
	if err != nil {
		s.log.Warn("driver: rekey completion failed", "kind", p.kind, "err", err)
	}
}

// handleInformationalRequest answers a server INFORMATIONAL request and reports
// whether it requested teardown of the current IKE SA. ESP Deletes and old-SA
// (post-rekey) IKE Deletes are acked but do not tear the session down.
func (s *Session) handleInformationalRequest(ctx context.Context, hdr *ikemsg.Message, inner ikemsg.Payloads, dec *ikeCtx, viaOld bool) bool {
	teardown := false
	for _, p := range inner {
		d, ok := p.(*ikemsg.DeletePayload)
		if !ok {
			continue
		}
		switch d.Protocol {
		case ikemsg.ProtocolIKE:
			// A current-SA IKE DELETE tears the session down; an old-SA DELETE is
			// just the post-rekey cleanup of the superseded SA (acked, not fatal).
			if !viaOld {
				teardown = true
			}
		case ikemsg.ProtocolESP:
			s.handleInboundChildDelete(ctx, d)
		}
	}
	// Ack under the SA that carried the request. The I bit follows our role on
	// that SA (set when we initiated it, cleared after a server-initiated rekey
	// left us its responder); R marks the response — RFC 7296 §3.1.
	if ack, err := encodeSKEmptyWith(dec, ikemsg.ExchangeInformational, ikeRoleBit(dec.sa.Role)|ikemsg.FlagResponse, hdr.MessageID); err == nil {
		s.recordPeerResponse(viaOld, hdr.MessageID, ack)
		if err := s.sendDatagram(ctx, ack); err != nil {
			s.log.Debug("driver: failed to ack INFORMATIONAL", "err", err)
		}
	}
	return teardown
}

// deleteRefsChild reports whether an ESP DELETE references the live Child SA. It
// scans every SPI in the batched DELETE (RFC 7296 §3.11 allows multiple) and
// matches our outbound SPI (the one the peer sends on, s.child.ResponderSPI) or
// our inbound SPI defensively.
func deleteRefsChild(d *ikemsg.DeletePayload, child *ChildSA) bool {
	for _, raw := range d.SPIs {
		if len(raw) != 4 {
			continue
		}
		spi := binary.BigEndian.Uint32(raw)
		if spi == child.ResponderSPI || spi == child.InitiatorSPI {
			return true
		}
	}
	return false
}

// handleInboundChildDelete processes a server DELETE of the live Child SA by
// re-establishing a fresh Child SA (a new CREATE_CHILD_SA without N(REKEY_SA) —
// RFC 7296 §1.3.1) so the data plane keeps flowing. The old inbound SA is left
// installed; completeChildRekey hands its SPI to the data plane as OldInSPI so
// it is grace-removed after childSAGrace rather than dropped eagerly. The DELETE
// is still acked by the caller.
func (s *Session) handleInboundChildDelete(ctx context.Context, d *ikemsg.DeletePayload) {
	if s.child == nil || s.dataPlane == nil || d.SPISize() != 4 {
		return
	}
	if !deleteRefsChild(d, s.child) {
		return
	}
	// Re-establish a fresh Child SA. Do NOT nil s.child — initiateChildRekey
	// needs it for the new SA's old-inbound-SPI grace removal. If an exchange is
	// already in flight (window size 1), queue it for housekeeping when the
	// window frees.
	if s.pending == nil {
		if err := s.initiateChildRekey(ctx, true); err != nil {
			s.log.Warn("driver: Child SA re-establishment failed", "err", err)
			s.childReestablish = true // retry from housekeeping
		} else {
			// A fresh re-establishment is in flight; clear any stale queued flag and
			// backoff so a prior cycle's state cannot trigger a redundant retry.
			s.childReestablish = false
			s.nextChildReestablish = time.Time{}
		}
	} else {
		s.childReestablish = true
	}
}

// housekeeping runs the periodic timers: retransmit the outstanding request,
// initiate rekey before the soft lifetime, and probe with DPD when idle.
func (s *Session) housekeeping(ctx context.Context, onDead func()) (exit bool) {
	now := time.Now()
	s.detectSuspend(ctx, now)
	if s.oldIKE != nil && now.After(s.oldIKEUntil) {
		s.oldIKE = nil
		s.oldPeer = peerDedup{}
		s.oldIKEDelete = nil // grace expired; stop retransmitting the old-SA DELETE
	}

	// Retransmit the superseded-IKE-SA DELETE under the old SA during the grace
	// window. It rides its own slot (the old SA's window), independent of the
	// current-SA pending exchange below.
	if s.oldIKEDelete != nil {
		if s.oldIKE == nil {
			s.oldIKEDelete = nil
		} else if now.After(s.oldIKEDelete.nextRetransmit) {
			s.oldIKEDelete.attempts++
			if s.oldIKEDelete.attempts > s.retransmitTries() {
				s.oldIKEDelete = nil
			} else {
				s.oldIKEDelete.nextRetransmit = now.Add(s.retransBackoff(s.oldIKEDelete.attempts))
				_ = s.sendDatagram(ctx, s.oldIKEDelete.raw)
			}
		}
	}

	if s.pending != nil {
		if now.After(s.pending.nextRetransmit) {
			s.pending.attempts++
			if s.pending.attempts > s.pendingTries() {
				kind := s.pending.kind
				// A re-establishment (peer DELETEd the live Child SA) that goes
				// unanswered must keep being retried — otherwise the data plane is
				// left dead. Re-queue it for housekeeping with a backoff.
				reestablish := s.pending.child != nil && s.pending.child.reestablish
				s.pending = nil
				if kind == exDPD {
					s.log.Warn("DPD: peer unresponsive, declaring dead")
					onDead()
					return true
				}
				s.log.Warn("driver: exchange unanswered, abandoning", "kind", kind)
				if reestablish {
					s.childReestablish = true
					s.nextChildReestablish = now.Add(rekeyRetryInterval)
				}
			} else {
				s.pending.nextRetransmit = now.Add(s.pendingBackoff(s.pending.attempts))
				_ = s.sendDatagram(ctx, s.pending.raw)
			}
		}
		return false // window size 1: no new exchange while one is outstanding
	}

	// A fast DPD armed by a suspend/wake whose window was busy at the time: fire it
	// now that the window is free, ahead of any rekey, so liveness is verified
	// quickly instead of waiting out the idle DPD timer.
	if s.fastDPDDue {
		s.fastDPDDue = false
		if err := s.initiateDPD(ctx, true); err != nil {
			s.log.Debug("post-suspend DPD probe send failed", "err", err)
		}
		return false
	}

	// A peer DELETE of the live Child SA queued a re-establishment (or its
	// immediate attempt failed); run it now that the window is free. Throttled by
	// nextChildReestablish so a peer that keeps rejecting the CREATE_CHILD_SA does
	// not spin every tick. The flag is cleared only on a successful initiation.
	if s.childReestablish && s.dataPlane != nil && now.After(s.nextChildReestablish) {
		if err := s.initiateChildRekey(ctx, true); err != nil {
			s.log.Warn("driver: queued Child SA re-establishment failed", "err", err)
			s.nextChildReestablish = now.Add(rekeyRetryInterval)
		} else {
			s.childReestablish = false
			s.nextChildReestablish = time.Time{} // reset backoff so a later cycle is not throttled by stale state
		}
		return false
	}

	// Volume-based Child SA rekey, independent of RekeyLifetime: rekey once the
	// outbound sequence number crosses the threshold so a heavy-traffic tunnel
	// rekeys before the 32-bit counter nears exhaustion. nextVolumeRekey throttles
	// re-initiation after an abandoned attempt (its zero value lets the first
	// over-threshold tick through). Suppressed while a re-establishment is pending:
	// s.child then references a peer-DELETEd SA, so a normal rekey would carry
	// N(REKEY_SA) for a gone SPI and draw CHILD_SA_NOT_FOUND.
	if s.dataPlane != nil && !s.childReestablish && now.After(s.nextVolumeRekey) &&
		s.dataPlane.ChildSAVolume() >= s.rekeyMaxPackets() {
		s.nextVolumeRekey = now.Add(rekeyRetryInterval)
		if err := s.initiateChildRekey(ctx, false); err != nil {
			s.log.Warn("driver: volume-based Child rekey failed", "err", err)
		}
		return false
	}

	// Initiate rekey (IKE rekey takes priority over Child rekey).
	if s.dataPlane != nil && s.cfg.RekeyLifetime > 0 {
		if !s.nextIKERekey.IsZero() && now.After(s.nextIKERekey) {
			s.nextIKERekey = now.Add(rekeyRetryInterval)
			if err := s.initiateIKERekey(ctx); err != nil {
				s.log.Warn("driver: IKE rekey initiation failed", "err", err)
			}
			return false
		}
		// Suppressed while a re-establishment is pending (s.child references a
		// peer-DELETEd SA — a normal REKEY_SA of it would draw CHILD_SA_NOT_FOUND).
		if !s.childReestablish && !s.nextChildRekey.IsZero() && now.After(s.nextChildRekey) {
			s.nextChildRekey = now.Add(rekeyRetryInterval)
			if err := s.initiateChildRekey(ctx, false); err != nil {
				s.log.Warn("driver: Child rekey initiation failed", "err", err)
			}
			return false
		}
	}

	// Treat inbound ESP as liveness too: a tunnel busy on the data plane but
	// quiet on IKE must not be probed (and torn down) as if it were dead.
	idle := now.Sub(s.lastInbound)
	if s.dataPlane != nil {
		if last := s.dataPlane.LastDataInbound(); !last.IsZero() {
			if d := now.Sub(last); d < idle {
				idle = d
			}
		}
	}
	if idle > s.dpdInterval() {
		if err := s.initiateDPD(ctx, false); err != nil {
			s.log.Debug("DPD probe send failed", "err", err)
		}
	}
	return false
}

// detectSuspend notices a host suspend/wake by the wall-clock gap since the
// previous housekeeping tick (the monotonic clock is frozen across a suspend, so
// this gap, measured on wall-clock, reveals it). On a wake it triggers a DPD
// probe on the tightened fast schedule so a tunnel whose NAT mapping expired
// during sleep is declared dead in seconds. If the request window is busy it
// accelerates the in-flight exchange and arms a fast DPD for once it frees.
func (s *Session) detectSuspend(ctx context.Context, now time.Time) {
	prev := s.lastTickWall
	s.lastTickWall = now.Round(0)
	if prev.IsZero() || s.lastTickWall.Sub(prev) <= suspendThreshold {
		return
	}
	s.log.Info("suspend/wake detected, fast-probing tunnel liveness", "gap", s.lastTickWall.Sub(prev))
	switch {
	case s.pending == nil:
		if err := s.initiateDPD(ctx, true); err != nil {
			s.log.Debug("post-suspend DPD probe send failed", "err", err)
		}
	case s.pending.kind == exDPD:
		s.pending.fast = true
		s.pending.nextRetransmit = now
	default:
		// A rekey or DELETE is in flight; fast-fail it and arm a fast DPD for once
		// the window frees (housekeeping fires it before re-occupying the window
		// with a rekey). Fast-failing a DELETE ack is safe: the old Child SA is
		// cleaned up by the grace timer regardless of how its ack times out.
		s.pending.fast = true
		s.pending.nextRetransmit = now
		s.fastDPDDue = true
	}
}

// initiateDPD sends an empty INFORMATIONAL request and records it as the pending
// exchange so a missing ack eventually declares the peer dead. A fast probe uses
// the tightened post-suspend schedule (fastDPDBase/fastDPDTries).
func (s *Session) initiateDPD(ctx context.Context, fast bool) error {
	msgID := s.messageID
	raw, err := s.encodeSKEmpty(ikemsg.ExchangeInformational, ikeRoleBit(s.ikeSA.Role), msgID)
	if err != nil {
		return err
	}
	s.messageID++
	base := s.retransmitBase()
	if fast {
		base = fastDPDBase
	}
	s.pending = &pendingExchange{
		kind: exDPD, msgID: msgID, raw: raw, attempts: 1, fast: fast,
		nextRetransmit: time.Now().Add(base),
	}
	return s.sendDatagram(ctx, raw)
}

// pendingTries returns the retransmit attempt budget for the outstanding
// exchange, tightened for a post-suspend fast DPD probe.
func (s *Session) pendingTries() int {
	if s.pending != nil && s.pending.fast {
		return fastDPDTries
	}
	return s.retransmitTries()
}

// pendingBackoff returns the retransmit delay for the nth attempt of the
// outstanding exchange, fixed-short for a post-suspend fast DPD probe.
func (s *Session) pendingBackoff(attempt int) time.Duration {
	if s.pending != nil && s.pending.fast {
		return fastDPDBase
	}
	return s.retransBackoff(attempt)
}

// clearPending clears the outstanding exchange when its INFORMATIONAL response
// arrives. It only clears an INFORMATIONAL-initiated exchange (DPD or DELETE): a
// rekey is a CREATE_CHILD_SA exchange cleared by completeMatchingRekey, so a
// numeric Message-ID coincidence on an INFORMATIONAL response must not silently
// cancel an in-flight rekey (mirrors completeMatchingRekey's kind guard).
func (s *Session) clearPending(msgID uint32) {
	if s.pending != nil && s.pending.msgID == msgID &&
		(s.pending.kind == exDPD || s.pending.kind == exDelete) {
		s.pending = nil
	}
}

// sendGracefulDelete sends INFORMATIONAL{ Delete(IKE SA) } on shutdown with a
// short bounded timeout, best-effort.
func (s *Session) sendGracefulDelete() {
	if s.ikeSA == nil || s.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	inner := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolIKE}}
	raw, err := s.encodeSK(ikemsg.ExchangeInformational, ikeRoleBit(s.ikeSA.Role), s.messageID, inner)
	if err != nil {
		return
	}
	s.messageID++
	if err := s.sendDatagram(ctx, raw); err != nil {
		s.log.Debug("graceful DELETE send failed", "err", err)
	}
}

// --- timing helpers ---

func (s *Session) dpdInterval() time.Duration {
	if s.cfg.DPDTimeout > 0 {
		return s.cfg.DPDTimeout
	}
	return 30 * time.Second
}

func (s *Session) ikeRekeyLifetime() time.Duration {
	if s.cfg.IKERekeyLifetime > 0 {
		return s.cfg.IKERekeyLifetime
	}
	if s.cfg.RekeyLifetime > 0 {
		return 4 * s.cfg.RekeyLifetime
	}
	return 0
}

// defaultRekeyMaxPackets is the volume-based Child SA rekey threshold used when
// Config.RekeyMaxPackets is zero: rekey after 2^31 outbound packets, well below
// the 2^32 sequence-number space so the cutover lands with ample margin.
const defaultRekeyMaxPackets = uint32(1) << 31

// rekeyMaxPackets resolves the configured volume-based rekey threshold,
// substituting the built-in default for a zero value.
func (s *Session) rekeyMaxPackets() uint32 {
	if s.cfg.RekeyMaxPackets > 0 {
		return s.cfg.RekeyMaxPackets
	}
	return defaultRekeyMaxPackets
}

// retransBackoff returns the retransmit delay for the nth attempt (exponential,
// capped).
func (s *Session) retransBackoff(attempt int) time.Duration {
	d := s.retransmitBase()
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= s.retransmitMax() {
			return s.retransmitMax()
		}
	}
	return d
}

// jitteredDeadline returns base+lifetime scaled by a random 0.85–1.0 factor to
// avoid both peers rekeying at the same instant. A zero lifetime disables it.
func jitteredDeadline(base time.Time, lifetime time.Duration) time.Time {
	if lifetime <= 0 {
		return time.Time{}
	}
	scaled := time.Duration(float64(lifetime) * (0.85 + 0.15*randFraction()))
	return base.Add(scaled)
}

// randFraction returns a value in [0,1) from crypto/rand (Math/rand-free).
func randFraction() float64 {
	b, err := randBytes(2)
	if err != nil {
		return 0.5
	}
	return float64(uint16(b[0])<<8|uint16(b[1])) / 65536.0
}
