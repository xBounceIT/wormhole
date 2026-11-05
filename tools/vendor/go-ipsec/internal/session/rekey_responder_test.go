package session

import (
	"bytes"
	"testing"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// TestServerIKERekeySwapsDespiteSendFailure: a server IKE rekey whose response
// send fails must still cut over to the new IKE SA (the response is cached, so
// the peer can complete the rekey from a retransmit), adopt the rekey's DH
// group, and answer that retransmit — now arriving under the superseded SA —
// from cache without deriving another SA.
func TestServerIKERekeySwapsDespiteSendFailure(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	realConn := initS.conn
	initS.conn = failSendConn{realConn}
	initS.ikeDHGroup = ikemsg.DH_X25519
	oldSA := initS.ikeSA

	dh, err := ikesa.NewDH(ikemsg.DH_MODP2048)
	if err != nil {
		t.Fatal(err)
	}
	reqRaw := serverIKERekey(t, respS, 0, 0x7171, ikemsg.DH_MODP2048, dh.Public, bytes.Repeat([]byte{0xE1}, nonceLen))

	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if initS.ikeSA == oldSA || initS.oldIKE == nil || initS.oldIKE.sa != oldSA {
		t.Fatal("did not cut over to the new IKE SA after a failed response send")
	}
	newSA := initS.ikeSA
	if initS.ikeDHGroup != ikemsg.DH_MODP2048 {
		t.Fatalf("ikeDHGroup = %d, want the rekey's group 14", initS.ikeDHGroup)
	}
	if !initS.oldPeer.set {
		t.Fatal("rekey response was not cached for retransmits")
	}

	// The retransmit is answered from cache under the old SA; no second cutover.
	initS.conn = realConn
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown on retransmit")
	}
	if initS.ikeSA != newSA {
		t.Fatal("retransmit was reprocessed into another IKE SA")
	}
	respRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(respRaw, initS.oldPeer.resp) {
		t.Fatal("retransmit was not answered with the cached response")
	}
}

// TestServerIKERekeyMalformedKEAnswered: a server IKE rekey whose KE value has
// the wrong length for its (supported) group draws a cached INVALID_SYNTAX, so
// retransmits are answered from cache instead of being reprocessed into silence.
func TestServerIKERekeyMalformedKEAnswered(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	oldSA := initS.ikeSA
	reqRaw := serverIKERekey(t, respS, 0, 0x7272, ikemsg.DH_MODP2048, bytes.Repeat([]byte{0x01}, 17), bytes.Repeat([]byte{0xE2}, nonceLen))

	ctx, cancel := recvCtx(t)
	defer cancel()
	for i := range 2 {
		if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
			t.Fatal("unexpected teardown")
		}
		respRaw, err := respConn.Recv(ctx)
		if err != nil {
			t.Fatalf("attempt %d: no response: %v", i, err)
		}
		_, inner, _, err := respS.decodeIKE(respRaw)
		if err != nil {
			t.Fatal(err)
		}
		var got ikemsg.NotifyType
		for _, p := range inner {
			if n, ok := p.(*ikemsg.NotifyPayload); ok {
				got = n.Type
			}
		}
		if got != ikemsg.NotifyInvalidSyntax {
			t.Fatalf("attempt %d: notify = %d, want INVALID_SYNTAX", i, got)
		}
	}
	if initS.ikeSA != oldSA {
		t.Fatal("malformed IKE rekey must not cut over")
	}
}

// TestIsSelectionForRejectsAmbiguousESNAndDH: a responder "selection" that
// echoes several ESN or DH alternatives is not a narrowed selection.
func TestIsSelectionForRejectsAmbiguousESNAndDH(t *testing.T) {
	gcmESP, _ := suiteByID(esp.SuiteAESGCM256, espSuites)
	spi := []byte{1, 2, 3, 4}

	if p := buildProposalForSuite(1, gcmESP, spi); !isSelectionFor(gcmESP, p) {
		t.Fatal("clean ESP selection rejected")
	}
	twoESN := buildProposalForSuite(1, gcmESP, spi)
	twoESN.Transforms = append(twoESN.Transforms, ikemsg.Transform{Type: ikemsg.TransformESN, ID: 1}) // 1 = ESN
	if isSelectionFor(gcmESP, twoESN) {
		t.Fatal("ESP selection with both ESN_NONE and ESN accepted")
	}
	noESN := buildProposalForSuite(1, gcmESP, spi)
	noESN.Transforms = noESN.Transforms[:len(noESN.Transforms)-1]
	if isSelectionFor(gcmESP, noESN) {
		t.Fatal("ESP selection without ESN accepted")
	}

	gcmIKE := gcmIKESuite()
	if p := buildProposalForSuite(1, gcmIKE, nil, ikemsg.DH_X25519); !isSelectionFor(gcmIKE, p) {
		t.Fatal("clean IKE selection rejected")
	}
	if p := buildProposalForSuite(1, gcmIKE, nil, ikemsg.DH_X25519, ikemsg.DH_MODP2048); isSelectionFor(gcmIKE, p) {
		t.Fatal("IKE selection with two DH groups accepted")
	}
}

// TestSuiteProtocolFromIDType: the protocol is derived from the row's id type.
func TestSuiteProtocolFromIDType(t *testing.T) {
	for _, s := range espSuites {
		if s.protocol() != ikemsg.ProtocolESP || s.spiLen() != 4 {
			t.Fatalf("%s: protocol=%d spiLen=%d", s.name(), s.protocol(), s.spiLen())
		}
	}
	for _, s := range ikeSuites {
		if s.protocol() != ikemsg.ProtocolIKE || s.spiLen() != 8 {
			t.Fatalf("%s: protocol=%d spiLen=%d", s.name(), s.protocol(), s.spiLen())
		}
	}
}

// TestCheckConfiguredSuitesRejectsUnknown: an id with no table row fails loudly
// instead of being dropped from (or emptying) the offer.
func TestCheckConfiguredSuitesRejectsUnknown(t *testing.T) {
	s := New(Config{})
	if err := s.checkConfiguredSuites(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	s = New(Config{IKESuites: []ikesa.Suite{0xEE}})
	if err := s.checkConfiguredSuites(); err == nil {
		t.Fatal("unknown IKE suite accepted")
	}
	s = New(Config{ESPSuites: []esp.Suite{esp.SuiteAESGCM256, 0xEE}})
	if err := s.checkConfiguredSuites(); err == nil {
		t.Fatal("unknown ESP suite accepted")
	}
}
