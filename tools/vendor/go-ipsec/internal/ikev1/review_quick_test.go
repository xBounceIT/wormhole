package ikev1

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func establishedReviewPair(t *testing.T, inspect ...func(*pair)) *pair {
	t.Helper()
	cfg := Config{Mode: ModeAggressive, Phase2: Phase2RemoteAccess, PSK: []byte("review-fixture"), ManualIP: net.IPv4(10, 0, 0, 1), Groups: []uint16{14}, LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(192, 0, 2, 2)}
	other := cfg
	other.ManualIP = net.IPv4(10, 0, 0, 2)
	p := newPair(t, cfg, other)
	t.Cleanup(p.initiator.Close)
	t.Cleanup(p.responder.Close)
	if len(inspect) > 0 {
		inspect[0](p)
	}
	p.run(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.initErr != nil || p.respErr != nil || p.initRes == nil || p.respRes == nil {
		t.Fatal("fixture did not establish", p.initErr, p.respErr)
	}
	return p
}
func TestForgedQuickModeDoesNotDestroyEstablishedSA(t *testing.T) {
	for _, state := range []sessionState{stDone, stWaitQM2, stWaitQM3} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			p := establishedReviewPair(t)
			s := p.responder
			s.mu.Lock()
			s.state = state
			s.qmMsgID = 77
			beforeIV := append([]byte(nil), s.qmIV...)
			forged := assemble(s.mmHeader(exchangeQuick, flagEncryption, 77), payloadHash, []byte{1})
			s.mu.Unlock()
			if s.HandleInbound(forged) {
				t.Fatal("forgery authenticated")
			}
			s.mu.Lock()
			got := s.state
			iv := append([]byte(nil), s.qmIV...)
			s.mu.Unlock()
			if got != state || !bytes.Equal(iv, beforeIV) {
				t.Fatal("forged Quick Mode changed active SA/retransmission state", got)
			}
			p.mu.Lock()
			err := p.respErr
			p.mu.Unlock()
			if err != nil {
				t.Fatal("forged rekey killed tunnel", err)
			}
		})
	}
}
func TestCompletedQuickModeCannotBeReplayedAsFreshRekey(t *testing.T) {
	var original []byte
	p := establishedReviewPair(t, func(p *pair) {
		tap := func(wire []byte) {
			h, _, _, err := parseHeader(wire)
			if err == nil && h.exchange == exchangeQuick && original == nil {
				original = append([]byte(nil), wire...)
			}
		}
		p.tap.Store(&tap)
	})
	if len(original) == 0 {
		t.Fatal("fixture did not capture an authenticated QM1")
	}
	p.mu.Lock()
	before := p.respRes.InSPI
	p.mu.Unlock()
	if err := p.initiator.Rekey(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		fresh := p.respRes.InSPI != before && p.initErr == nil && p.respErr == nil
		p.mu.Unlock()
		if fresh {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new rekey did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	s := p.responder
	s.mu.Lock()
	before = s.inSPI
	messageID := s.qmMsgID
	s.mu.Unlock()
	s.HandleInbound(original)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stDone || s.inSPI != before || s.qmMsgID != messageID {
		t.Fatal("old authenticated QM1 was replayed as a fresh exchange")
	}
}
func TestLostFinalQuickModeMessageIsRetransmitted(t *testing.T) {
	var request []byte
	p := establishedReviewPair(t, func(p *pair) {
		send := p.responder.cfg.Send
		p.responder.cfg.Send = func(wire []byte, natt bool) error {
			h, _, _, err := parseHeader(wire)
			if err == nil && h.exchange == exchangeQuick {
				request = append([]byte(nil), wire...)
			}
			return send(wire, natt)
		}
	})
	s := p.initiator
	s.mu.Lock()
	reply := append([]byte(nil), s.lastSent...)
	s.mu.Unlock()
	if len(request) == 0 || len(reply) == 0 {
		t.Fatal("fixture did not capture QM2 and QM3")
	}
	sent := make(chan []byte, 1)
	s.mu.Lock()
	s.cfg.Send = func(wire []byte, _ bool) error { sent <- append([]byte(nil), wire...); return nil }
	s.mu.Unlock()
	s.HandleInbound(request)
	select {
	case got := <-sent:
		if !bytes.Equal(got, reply) {
			t.Fatal("duplicate QM2 changed its QM3 response")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("lost final Quick Mode packet cannot recover")
	}
}

func TestRetypedInformationalCannotChangeQuickModeState(t *testing.T) {
	p := establishedReviewPair(t)
	var wire []byte
	s := p.initiator
	s.mu.Lock()
	s.cfg.Send = func(packet []byte, _ bool) error { wire = append([]byte(nil), packet...); return nil }
	err := s.sendInformational([]payload{{typ: payloadNotify, body: s.buildDPDNotify(notifyRUThere, 1)}})
	s.mu.Unlock()
	if err != nil || len(wire) < isakmpHeaderLen {
		t.Fatal("invalid informational fixture", err)
	}
	wire[18] = exchangeQuick
	peer := p.responder
	peer.mu.Lock()
	iv := append([]byte(nil), peer.qmIV...)
	peer.mu.Unlock()
	if peer.HandleInbound(wire) {
		t.Fatal("informational packet authenticated as Quick Mode")
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.state != stDone || !bytes.Equal(iv, peer.qmIV) {
		t.Fatal("retyped informational corrupted established Quick Mode")
	}
}

func TestQuickModeHistoryExhaustionRequiresReauthentication(t *testing.T) {
	p := establishedReviewPair(t)
	s := p.initiator
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quickCompleted = make(map[uint32]struct{}, maxQuickExchanges)
	for id := uint32(1); id <= maxQuickExchanges; id++ {
		s.quickCompleted[id] = struct{}{}
	}
	if err := s.startQuickMode(); err == nil {
		t.Fatal("unbounded Quick Mode history accepted")
	}
	s.state = stWaitQM3
	s.qmMsgID = maxQuickExchanges + 1
	s.finish()
	if s.state != stFailed || len(s.quickCompleted) != maxQuickExchanges {
		t.Fatal("history exhaustion did not fail closed within the memory bound")
	}
}
