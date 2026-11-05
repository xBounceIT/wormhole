package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"github.com/n0madic/go-ipsec/internal/transport"
)

// mirrorSessions builds an initiator and responder session sharing derived IKE
// SA keys over a memory transport pair. The envelope runs the default AES-GCM
// suite, so the whole post-handshake test suite (DPD, ack, dedup, grace,
// rekey) exercises the RFC 5282 AEAD SK{} framing; mirrorSessionsSuite selects
// another suite explicitly.
func mirrorSessions(t *testing.T) (initS, respS *Session, respConn transport.Conn) {
	t.Helper()
	return mirrorSessionsSuite(t, ikesa.SuiteAESGCM256)
}

// mirrorSessionsSuite is mirrorSessions with an explicit IKE envelope suite.
func mirrorSessionsSuite(t *testing.T, suite ikesa.Suite) (initS, respS *Session, respConn transport.Conn) {
	t.Helper()
	ni := bytes.Repeat([]byte{0x11}, 32)
	nr := bytes.Repeat([]byte{0x22}, 32)
	shared := bytes.Repeat([]byte{0x33}, 256)
	const spii, spir = 0xAAAA, 0xBBBB

	initSA := &ikesa.IKESA{}
	if err := initSA.Derive(suite, ikesa.Initiator, spii, spir, ni, nr, shared); err != nil {
		t.Fatal(err)
	}
	respSA := &ikesa.IKESA{}
	if err := respSA.Derive(suite, ikesa.Responder, spii, spir, ni, nr, shared); err != nil {
		t.Fatal(err)
	}

	ic, rc := transport.MemoryPair()
	initS = New(Config{Logger: slog.New(slog.DiscardHandler), DPDTimeout: 50 * time.Millisecond})
	initS.ikeSA = initSA
	initS.initiatorSPI = spii
	initS.responderSPI = spir
	initS.messageID = 2
	initS.conn = ic
	// The harness bypasses IKE_SA_INIT, so seed the negotiated DH group it would
	// have set. The stub shared secret above is 256 bytes (MODP-2048), so default
	// the group to 14; x25519 tests override ikeDHGroup/childPFSGroup explicitly.
	initS.ikeDHGroup = ikemsg.DH_MODP2048

	respS = New(Config{Logger: slog.New(slog.DiscardHandler)})
	respS.ikeSA = respSA
	respS.initiatorSPI = spii
	respS.responderSPI = spir
	respS.conn = rc
	respS.ikeDHGroup = ikemsg.DH_MODP2048
	return initS, respS, rc
}

func TestDriverDPDAck(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	inbox := make(chan []byte, 4)
	ctx := t.Context()
	go initS.Driver(ctx, inbox, func() {})

	// Server sends an empty INFORMATIONAL request (DPD probe). Flags=0: the
	// server is the original responder, so the I bit is clear.
	probe, err := respS.encodeSKEmpty(ikemsg.ExchangeInformational, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	inbox <- probe

	// The driver must reply with an INFORMATIONAL response.
	rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
	defer rcancel()
	ack, err := respConn.Recv(rctx)
	if err != nil {
		t.Fatalf("no DPD ack: %v", err)
	}
	m, err := ikemsg.Parse(ack)
	if err != nil {
		t.Fatal(err)
	}
	if m.Exchange != ikemsg.ExchangeInformational || !m.Flags.IsResponse() {
		t.Fatalf("ack not an INFORMATIONAL response: type=%d flags=%x", m.Exchange, m.Flags)
	}
	if !m.Flags.IsInitiator() {
		t.Fatal("initiator response must keep the I bit set")
	}
}

// TestLivenessClockOnlyOnAuthenticated is finding #2: the DPD liveness clock
// (lastInbound) must be refreshed only by a datagram whose ICV verifies, so stray
// or spoofed unauthenticated UDP to :4500 cannot suppress DPD and mask a dead peer.
func TestLivenessClockOnlyOnAuthenticated(t *testing.T) {
	initS, respS, _ := mirrorSessions(t)
	initS.SetDataPlane(&fakeDataPlane{})
	ctx := t.Context()

	// An authenticated INFORMATIONAL probe refreshes the clock.
	stale := time.Now().Add(-time.Hour)
	initS.lastInbound = stale
	probe, err := respS.encodeSKEmpty(ikemsg.ExchangeInformational, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, probe, func() {}); exit {
		t.Fatal("unexpected teardown on DPD probe")
	}
	if !initS.lastInbound.After(stale) {
		t.Fatal("authenticated datagram did not refresh the liveness clock")
	}

	// Unauthenticated garbage (corrupted ICV) must NOT refresh it.
	initS.lastInbound = stale
	garbage := append([]byte(nil), probe...)
	garbage[len(garbage)-1] ^= 0xFF
	if exit := initS.handleInbound(ctx, garbage, func() {}); exit {
		t.Fatal("unexpected teardown on garbage")
	}
	if !initS.lastInbound.Equal(stale) {
		t.Fatal("unauthenticated datagram refreshed the liveness clock (DPD suppression)")
	}
}

// TestClearPendingKindGuard is finding #7: an INFORMATIONAL response must only
// clear an INFORMATIONAL-initiated exchange (DPD/DELETE); a numeric Message-ID
// coincidence must not cancel an in-flight CREATE_CHILD_SA rekey.
func TestClearPendingKindGuard(t *testing.T) {
	s := New(Config{Logger: slog.New(slog.DiscardHandler)})

	s.pending = &pendingExchange{kind: exChildRekey, msgID: 42}
	s.clearPending(42)
	if s.pending == nil {
		t.Fatal("clearPending cancelled an in-flight rekey on a colliding Message ID")
	}

	s.pending = &pendingExchange{kind: exDPD, msgID: 42}
	s.clearPending(42)
	if s.pending != nil {
		t.Fatal("clearPending did not clear a DPD exchange")
	}
}

func TestDriverServerDelete(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	inbox := make(chan []byte, 4)
	dead := make(chan struct{})
	ctx := t.Context()
	go initS.Driver(ctx, inbox, func() { close(dead) })

	d := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolIKE}}
	del, err := respS.encodeSK(ikemsg.ExchangeInformational, 0, 0, d)
	if err != nil {
		t.Fatal(err)
	}
	inbox <- del

	// The server DELETE must be acked and the peer declared dead.
	rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
	defer rcancel()
	if _, err := respConn.Recv(rctx); err != nil {
		t.Fatalf("no DELETE ack: %v", err)
	}
	select {
	case <-dead:
	case <-time.After(2 * time.Second):
		t.Fatal("onDead not invoked after server DELETE")
	}
}

// TestSuspendWakeFastDPD verifies a detected suspend/wake (a large wall-clock gap
// since the previous tick) arms and sends a fast DPD probe, even though the
// monotonic-based idle timer still looks fresh.
func TestSuspendWakeFastDPD(t *testing.T) {
	initS, _, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	now := time.Now()
	initS.lastInbound = now                             // monotonic-recent: ordinary DPD would not fire
	initS.lastTickWall = now.Round(0).Add(-time.Minute) // simulate a suspend gap

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exit := initS.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit from housekeeping")
	}
	if initS.pending == nil || initS.pending.kind != exDPD || !initS.pending.fast {
		t.Fatal("suspend/wake did not arm a fast DPD probe")
	}
	raw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatalf("no DPD probe reached the peer after wake: %v", err)
	}
	m, err := ikemsg.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Exchange != ikemsg.ExchangeInformational || m.Flags.IsResponse() {
		t.Fatalf("probe is not an INFORMATIONAL request: type=%d flags=%x", m.Exchange, m.Flags)
	}
}

// TestFastDPDDeclaresDeadQuickly checks the post-suspend fast schedule declares
// the peer dead within fastDPDTries retransmits — far fewer than the default
// RetransmitTries the ordinary DPD path uses (~90s).
func TestFastDPDDeclaresDeadQuickly(t *testing.T) {
	initS, _, _ := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	dead := false
	onDead := func() { dead = true }
	ctx := context.Background()

	now := time.Now()
	initS.lastInbound = now
	initS.lastTickWall = now.Round(0).Add(-time.Minute)
	// Pass 1: detect the wake, arm and send the fast DPD (attempts = 1).
	if exit := initS.housekeeping(ctx, onDead); exit {
		t.Fatal("unexpected exit on the wake pass")
	}
	if initS.pending == nil || !initS.pending.fast {
		t.Fatal("fast DPD was not armed on wake")
	}

	// Drive retransmit passes the peer never answers, forcing each to be due. It
	// must converge to "dead" within fastDPDTries passes.
	passes := 0
	for !dead {
		passes++
		if passes > fastDPDTries+2 {
			t.Fatalf("fast DPD did not declare the peer dead within %d passes", passes)
		}
		initS.pending.nextRetransmit = time.Now().Add(-time.Second)
		initS.lastTickWall = time.Now().Round(0) // keep the gap small so suspend isn't re-detected
		initS.housekeeping(ctx, onDead)
	}
	if passes > fastDPDTries+1 {
		t.Fatalf("fast DPD took %d retransmit passes, want <= %d", passes, fastDPDTries+1)
	}
}

// TestNoSuspendOnNormalTick guards against false positives: an ordinary ~1s tick
// gap must not be mistaken for a suspend and must start no exchange.
func TestNoSuspendOnNormalTick(t *testing.T) {
	initS, _, _ := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	now := time.Now()
	initS.lastInbound = now
	initS.lastTickWall = now.Round(0).Add(-time.Second) // a normal tick gap

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if exit := initS.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit from housekeeping")
	}
	if initS.pending != nil {
		t.Fatalf("a normal tick spuriously started an exchange (kind=%v)", initS.pending.kind)
	}
}

// TestVolumeBasedChildRekey is finding #6: housekeeping initiates a Child rekey
// once the outbound ESP volume reaches the threshold, independent of the
// time-based rekey schedule (RekeyLifetime here is 0).
func TestVolumeBasedChildRekey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// At/over threshold → a Child rekey is initiated.
	atThreshold, _, _ := mirrorSessions(t)
	atThreshold.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	atThreshold.cfg.RekeyMaxPackets = 1000
	atThreshold.cfg.RekeyLifetime = 0 // time-based rekey disabled
	atThreshold.lastInbound = time.Now()
	atThreshold.SetDataPlane(&fakeDataPlane{volume: 1000})
	if exit := atThreshold.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit from housekeeping")
	}
	if atThreshold.pending == nil || atThreshold.pending.kind != exChildRekey {
		t.Fatal("volume threshold did not trigger a Child rekey")
	}

	// F5 backoff: with the first attempt abandoned (pending cleared) and the
	// volume still over threshold, a second housekeeping pass must NOT immediately
	// re-initiate — nextVolumeRekey throttles it until rekeyRetryInterval elapses.
	atThreshold.pending = nil
	atThreshold.lastInbound = time.Now()
	if exit := atThreshold.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit from housekeeping")
	}
	if atThreshold.pending != nil {
		t.Fatalf("volume rekey re-initiated without backoff (kind=%v)", atThreshold.pending.kind)
	}

	// Below threshold → no rekey (and no DPD, since we just had inbound).
	below, _, _ := mirrorSessions(t)
	below.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	below.cfg.RekeyMaxPackets = 1000
	below.cfg.RekeyLifetime = 0
	below.lastInbound = time.Now()
	below.SetDataPlane(&fakeDataPlane{volume: 999})
	if exit := below.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit from housekeeping")
	}
	if below.pending != nil {
		t.Fatalf("rekey triggered below the volume threshold (kind=%v)", below.pending.kind)
	}
}

// TestInboundChildDeleteReestablishes covers findings #1–#3: a server DELETE of
// the live Child SA re-establishes a fresh Child SA via a CREATE_CHILD_SA that
// carries NO N(REKEY_SA) (a strict responder would answer CHILD_SA_NOT_FOUND to
// a REKEY of the just-deleted SPI). The old inbound SA is not dropped eagerly,
// the DELETE is still acked, and the session is not torn down.
func TestInboundChildDeleteReestablishes(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)

	// Server DELETEs the Child SA, referencing the SPI it sends on (our outbound
	// = ResponderSPI 0x2222). I bit clear (server is the original responder).
	inner := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolESP, SPIs: [][]byte{{0, 0, 0x22, 0x22}}}}
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeInformational, 0, 9, inner)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("an ESP DELETE must not tear the session down")
	}

	// The re-establishment must NOT eagerly drop the old inbound SA: it is kept
	// installed until completeChildRekey hands its SPI to the data plane for grace
	// removal, so no install/removal has happened yet.
	if len(initDP.updates) != 0 {
		t.Fatalf("re-establishment must not touch the data plane before completion, got %d updates", len(initDP.updates))
	}
	// A fresh Child SA rekey is initiated (s.child is kept for the grace removal).
	if initS.pending == nil || initS.pending.kind != exChildRekey {
		t.Fatal("ESP DELETE did not trigger Child SA re-establishment")
	}
	if !initS.pending.child.reestablish {
		t.Fatal("re-establishment exchange not marked reestablish")
	}
	if initS.child == nil {
		t.Fatal("s.child must not be nilled (initiateChildRekey needs it)")
	}

	// Two datagrams reach the peer: the re-establishment CREATE_CHILD_SA and the
	// DELETE ack.
	var sawRekey, sawAck bool
	for i := range 2 {
		raw, err := respConn.Recv(ctx)
		if err != nil {
			t.Fatalf("expected 2 datagrams, got %d: %v", i, err)
		}
		hdr, inner, _, err := respS.decodeIKE(raw)
		if err != nil {
			t.Fatal(err)
		}
		switch hdr.Exchange {
		case ikemsg.ExchangeCreateChildSA:
			sawRekey = true
			// F1: the re-establishment must be a fresh CREATE_CHILD_SA, NOT a REKEY
			// of the deleted SPI. A strict responder answers CHILD_SA_NOT_FOUND to a
			// N(REKEY_SA) referencing an SA it just deleted.
			for _, p := range inner {
				if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyRekeySA {
					t.Fatal("re-establishment CREATE_CHILD_SA must not carry N(REKEY_SA)")
				}
			}
		case ikemsg.ExchangeInformational:
			if hdr.Flags.IsResponse() {
				sawAck = true
			}
		}
	}
	if !sawRekey {
		t.Fatal("no CREATE_CHILD_SA re-establishment was sent")
	}
	if !sawAck {
		t.Fatal("the ESP DELETE was not acked")
	}
}

// errSendAlwaysFails is returned by failSendConn.Send.
var errSendAlwaysFails = errors.New("send always fails")

// failSendConn wraps a transport.Conn but makes every Send fail, to exercise the
// install-before-send ordering of handleChildRekeyRequest.
type failSendConn struct {
	transport.Conn
}

func (failSendConn) Send(context.Context, []byte) error { return errSendAlwaysFails }

// TestChildRekeyResponderInstallsBeforeSend pins finding #5: a server Child rekey
// whose response send fails must still have installed our inbound SA and updated
// s.child, so the peer (which can complete via a cached retransmit) is not
// black-holed on the new SPI.
func TestChildRekeyResponderInstallsBeforeSend(t *testing.T) {
	initS, respS, _ := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	initS.conn = failSendConn{initS.conn} // every response send now fails

	var inner ikemsg.Payloads
	inner = append(inner, &ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}})
	inner = append(inner, &ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalCBC(1, []byte{0xAB, 0xCD, 0xEF, 0x40})}})
	inner = append(inner, &ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xD4}, nonceLen)})
	appendTrafficSelectors(&inner, false)
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, 5, inner)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// handleInbound logs the rekey error (the failed send) but does not tear down.
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if len(initDP.updates) != 1 {
		t.Fatal("inbound SA was not installed before the (failed) response send")
	}
	if initS.child == nil || initS.child.ResponderSPI != 0xABCDEF40 {
		t.Fatal("s.child not updated to the new SA despite a send failure")
	}
}

// TestReestablishRetriedAfterAbandon pins finding #1: a re-establishment that
// exhausts its retransmits must be re-queued (childReestablish set, backoff armed)
// so the data plane is not left dead.
func TestReestablishRetriedAfterAbandon(t *testing.T) {
	initS, _, _ := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.SetDataPlane(&fakeDataPlane{})
	initS.lastInbound = time.Now()
	initS.pending = &pendingExchange{
		kind:           exChildRekey,
		child:          &childRekeyCtx{reestablish: true},
		attempts:       initS.retransmitTries(),
		nextRetransmit: time.Now().Add(-time.Second),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exit := initS.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit")
	}
	if initS.pending != nil {
		t.Fatal("abandoned exchange not cleared")
	}
	if !initS.childReestablish {
		t.Fatal("abandoned re-establishment was not re-queued for retry")
	}
	if initS.nextChildReestablish.IsZero() {
		t.Fatal("re-establishment retry backoff not armed")
	}
}

// TestNoNormalRekeyWhileReestablishPending pins finding #2: while a re-establishment
// is queued (s.child references a peer-DELETEd SA), a due time-based Child rekey must
// NOT fire — it would carry N(REKEY_SA) for a gone SPI and draw CHILD_SA_NOT_FOUND.
func TestNoNormalRekeyWhileReestablishPending(t *testing.T) {
	initS, _, _ := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.cfg.RekeyLifetime = time.Hour
	initS.SetDataPlane(&fakeDataPlane{})
	initS.lastInbound = time.Now()
	now := time.Now()
	initS.childReestablish = true
	initS.nextChildReestablish = now.Add(time.Hour) // throttled: re-establishment won't fire this tick
	initS.nextChildRekey = now.Add(-time.Second)    // normal Child rekey is due

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exit := initS.housekeeping(ctx, func() {}); exit {
		t.Fatal("unexpected exit")
	}
	if initS.pending != nil {
		t.Fatalf("a normal rekey fired while a re-establishment was pending (kind=%v)", initS.pending.kind)
	}
}

// TestReestablishClearsStaleFlagOnImmediateSuccess pins findings #6/#8: when a peer
// DELETE re-establishes immediately (window free) and succeeds, any stale queued
// childReestablish flag and backoff from a prior cycle are cleared, so housekeeping
// does not fire a redundant duplicate re-establishment nor throttle a future one.
func TestReestablishClearsStaleFlagOnImmediateSuccess(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initS.SetDataPlane(&fakeDataPlane{})
	initS.childReestablish = true                          // stale flag from an earlier cycle
	initS.nextChildReestablish = time.Now().Add(time.Hour) // stale backoff

	del := ikemsg.Payloads{&ikemsg.DeletePayload{Protocol: ikemsg.ProtocolESP, SPIs: [][]byte{{0, 0, 0x22, 0x22}}}}
	delRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeInformational, 0, 9, del)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exit := initS.handleInbound(ctx, delRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	for range 2 { // drain re-establishment + ack
		if _, err := respConn.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if initS.pending == nil || initS.pending.kind != exChildRekey {
		t.Fatal("immediate re-establishment not initiated")
	}
	if initS.childReestablish {
		t.Fatal("stale childReestablish flag not cleared on immediate success")
	}
	if !initS.nextChildReestablish.IsZero() {
		t.Fatal("stale re-establishment backoff not reset on immediate success")
	}
}

func TestDriverGracefulDelete(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	inbox := make(chan []byte, 4)
	ctx, cancel := context.WithCancel(context.Background())
	go initS.Driver(ctx, inbox, func() {})

	// Cancelling the driver context triggers a graceful DELETE.
	cancel()
	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rcancel()
	raw, err := respConn.Recv(rctx)
	if err != nil {
		t.Fatalf("no graceful DELETE: %v", err)
	}
	_, inner, err := respS.decodeSK(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sawDelete bool
	for _, p := range inner {
		if dp, ok := p.(*ikemsg.DeletePayload); ok && dp.Protocol == ikemsg.ProtocolIKE {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatal("graceful shutdown did not send a Delete payload")
	}
}

// TestCompleteMatchingRekeyGuards covers findings #3 and #13: a CREATE_CHILD_SA
// response must not consume s.pending when it arrives under the superseded SA
// (viaOld) or when the outstanding exchange is not a rekey (a Message-ID
// coincidence with an in-flight DPD or DELETE).
func TestCompleteMatchingRekeyGuards(t *testing.T) {
	s, _, _ := mirrorSessions(t)
	ctx, cancel := recvCtx(t)
	defer cancel()

	// #13: a non-rekey pending (DPD) with a matching Message-ID is left intact
	// (the kind switch has no case for it, so it would otherwise be silently lost).
	s.pending = &pendingExchange{kind: exDPD, msgID: 5}
	s.completeMatchingRekey(ctx, 5, ikemsg.Payloads{}, false)
	if s.pending == nil || s.pending.kind != exDPD {
		t.Fatal("DPD pending cleared by a CREATE_CHILD_SA response Message-ID coincidence")
	}

	// #3: a stale old-SA (viaOld) response must not consume a live rekey pending
	// that runs under the current SA.
	s.pending = &pendingExchange{kind: exChildRekey, msgID: 7}
	s.completeMatchingRekey(ctx, 7, ikemsg.Payloads{}, true)
	if s.pending == nil || s.pending.kind != exChildRekey {
		t.Fatal("live rekey pending consumed by a stale old-SA response")
	}
}

// TestCloseWipesCredentialCopies: the session owns its PSK/EAP-password byte
// copies (toSessionConfig allocates them fresh per dial), and Close zeroes
// them so the credentials do not outlive the session in the default
// (no-runtime/secret) build.
func TestCloseWipesCredentialCopies(t *testing.T) {
	s, _, _ := mirrorSessions(t)
	s.cfg.PSK = []byte("preshared-secret")
	s.cfg.EAPPass = []byte("eap-password")
	psk, pass := s.cfg.PSK, s.cfg.EAPPass

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{psk, pass} {
		for _, v := range b {
			if v != 0 {
				t.Fatal("Close did not wipe the credential copy")
			}
		}
	}
}
