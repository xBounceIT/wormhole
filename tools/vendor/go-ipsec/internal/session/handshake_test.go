package session

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	iauth "github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/eap"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"github.com/n0madic/go-ipsec/internal/transport"
	"layeh.com/radius/rfc2759"
)

// TestOfflineHandshake drives the full initiator state machine
// (IKE_SA_INIT + IKE_AUTH + EAP-MSCHAPv2 + Child SA) against a cooperating
// in-memory responder built from the same primitives — once per negotiable ESP
// suite (under the default GCM IKE envelope) and once per negotiable IKE suite
// (with the ESP suite pinned to GCM), the responder narrowing the client's
// multi-proposal offers accordingly. It proves the state machine reaches
// "established", records the selected suites, and that both ends derive
// identical Child SA keys of the ESP suite's lengths — the offline gate, with
// zero live dials. The EAP conversation running inside the SK{} envelope also
// exercises multiple AEAD IVs per IKE SA for the AEAD IKE suites.
func TestOfflineHandshake(t *testing.T) {
	for _, id := range []esp.Suite{esp.SuiteAESGCM256, esp.SuiteChaCha20Poly1305, esp.SuiteAESCBC256SHA256} {
		suite := mustSuite(t, id)
		t.Run("esp-"+suite.name(), func(t *testing.T) {
			testOfflineHandshake(t, suite, mustIKESuite(t, ikesa.SuiteAESGCM256))
		})
	}
	for _, id := range []ikesa.Suite{ikesa.SuiteAESGCM256, ikesa.SuiteChaCha20Poly1305, ikesa.SuiteAESCBC256SHA256} {
		ike := mustIKESuite(t, id)
		t.Run("ike-"+ike.name(), func(t *testing.T) {
			testOfflineHandshake(t, mustSuite(t, esp.SuiteAESGCM256), ike)
		})
	}
}

func testOfflineHandshake(t *testing.T, suite espSuite, ike ikeSuite) {
	const username, password = "User", "clientPass"
	initConn, respConn := transport.MemoryPair()

	// CA + leaf certificate trusted by the initiator, SAN "vpn.test".
	leaf, leafKey, roots := makeTestCert(t, "vpn.test")

	initCfg := Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		RemoteID:        WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")},
		EAPUser:         username,
		EAPPass:         []byte(password),
		RootCAs:         roots,
		Logger:          slog.New(slog.DiscardHandler),
		RequestIPv6:     true,
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	}
	initSess := New(initCfg)
	initSess.conn = initConn

	respDone := make(chan *responderResult, 1)
	go func() {
		res := runResponder(t, respConn, username, password, leaf, leafKey, suite, ike)
		respDone <- res
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	if initSess.ikeSA.Suite != ike.id {
		t.Fatalf("negotiated IKE suite = %v, want %v", initSess.ikeSA.Suite, ike.id)
	}
	if err := initSess.IKEAuth(ctx); err != nil {
		t.Fatalf("IKEAuth: %v", err)
	}
	if !initSess.Established() {
		t.Fatal("session not established")
	}

	res := <-respDone
	if res.err != nil {
		t.Fatalf("responder: %v", res.err)
	}

	// Assigned config from CP.
	if initSess.Assigned().IP != netip.MustParseAddr("10.10.0.42") {
		t.Fatalf("assigned IP = %v, want 10.10.0.42", initSess.Assigned().IP)
	}
	// Inner IPv6 from the CFG_REPLY INTERNAL_IP6_ADDRESS (end-to-end v6 parse).
	wantIP6 := netip.MustParsePrefix("fd00:10::42/64")
	if got := initSess.Assigned().IP6; got != wantIP6 {
		t.Fatalf("assigned IP6 = %v, want %v", got, wantIP6)
	}
	// Child SA suite, SPIs, key lengths and keys must agree across both ends.
	child := initSess.Child()
	if child == nil {
		t.Fatal("no child SA installed")
	}
	if child.Suite != suite.id {
		t.Fatalf("negotiated suite = %v, want %v", child.Suite, suite.id)
	}
	if len(child.Keys.EncrIR) != suite.encrKeyLen || len(child.Keys.IntegIR) != suite.integKeyLen {
		t.Fatalf("key lengths %d/%d, want %d/%d",
			len(child.Keys.EncrIR), len(child.Keys.IntegIR), suite.encrKeyLen, suite.integKeyLen)
	}
	if child.ResponderSPI != res.childResponderSPI {
		t.Fatalf("responder SPI mismatch: %08x vs %08x", child.ResponderSPI, res.childResponderSPI)
	}
	if !bytes.Equal(child.Keys.EncrIR, res.childKeys.EncrIR) ||
		!bytes.Equal(child.Keys.IntegRI, res.childKeys.IntegRI) {
		t.Fatal("child SA key material disagrees across initiator/responder")
	}
}

type responderResult struct {
	err               error
	childResponderSPI uint32
	childKeys         ikesa.ChildKeys
}

// runResponder implements the responder half of the handshake, narrowing the
// client's multi-suite ESP offer to the given ESP suite and its multi-suite
// IKE offer to the given IKE suite. It uses a Responder-role Session purely
// for its encodeSK/decodeSK helpers.
func runResponder(t *testing.T, conn transport.Conn, username, password string, leaf *x509.Certificate, leafKey *rsa.PrivateKey, suite espSuite, ike ikeSuite) *responderResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := &responderResult{}
	fail := func(err error) *responderResult { res.err = err; return res }

	rs := New(Config{Logger: slog.New(slog.DiscardHandler)})

	// --- IKE_SA_INIT ---
	nr := bytes.Repeat([]byte{0x42}, 32)
	raw1, realMessage2, ni, err := respondSAInit(ctx, conn, rs, nr, ike)
	if err != nil {
		return fail(err)
	}

	// --- IKE_AUTH message 3 ---
	raw3, err := conn.Recv(ctx)
	if err != nil {
		return fail(err)
	}
	hdr3, inner3, err := rs.decodeSK(raw3)
	if err != nil {
		return fail(err)
	}
	var idi *ikemsg.IDiPayload
	for _, p := range inner3 {
		if v, ok := p.(*ikemsg.IDiPayload); ok {
			idi = v
		}
	}
	if idi == nil {
		return fail(errFail("missing IDi"))
	}

	// --- message 4: IDr, CERT, AUTH(cert), EAP-Challenge ---
	idr := WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")}
	respSigned := iauth.SignedOctets(rs.ikeSA.PRF, realMessage2, ni, ikemsg.MarshalIDBody(ikemsg.IDType(idr.Type), idr.Data), rs.ikeSA.SKpr)
	certAuth, err := signRFC7427(leafKey, respSigned)
	if err != nil {
		return fail(err)
	}
	authChallenge := bytes.Repeat([]byte{0x11}, 16)

	m4 := ikemsg.Payloads{
		&ikemsg.IDrPayload{IDType: ikemsg.IDType(idr.Type), Data: idr.Data},
		&ikemsg.CertPayload{Encoding: ikemsg.CertX509Signature, Data: leaf.Raw},
		&ikemsg.AuthPayload{Method: iauth.MethodDigitalSignature, Data: certAuth},
		&ikemsg.EAPPayload{Data: mschapChallenge(1, authChallenge).Marshal()},
	}
	out4, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr3.MessageID, m4)
	if err != nil {
		return fail(err)
	}
	if err := conn.Send(ctx, out4); err != nil {
		return fail(err)
	}

	// --- message 5: EAP-Response/Response ---
	raw5, err := conn.Recv(ctx)
	if err != nil {
		return fail(err)
	}
	hdr5, inner5, err := rs.decodeSK(raw5)
	if err != nil {
		return fail(err)
	}
	eapResp, ok, err := firstEAP(inner5)
	if err != nil || !ok || eapResp.Type != eap.TypeMSCHAPv2 {
		return fail(errFail("missing MSCHAPv2 response"))
	}
	value := eapResp.Data[5 : 5+49]
	peerChallenge := value[0:16]
	ntResponse := value[24:48]
	authResp, err := rfc2759.GenerateAuthenticatorResponse(authChallenge, peerChallenge, ntResponse, []byte(username), []byte(password))
	if err != nil {
		return fail(err)
	}

	// --- message 6: EAP-Request/Success ---
	m6 := ikemsg.Payloads{&ikemsg.EAPPayload{Data: mschapSuccessRequest(2, authResp).Marshal()}}
	out6, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr5.MessageID, m6)
	if err != nil {
		return fail(err)
	}
	if err := conn.Send(ctx, out6); err != nil {
		return fail(err)
	}

	// --- message 7: EAP-Response/Success → reply EAP-Success ---
	raw7, err := conn.Recv(ctx)
	if err != nil {
		return fail(err)
	}
	hdr7, _, err := rs.decodeSK(raw7)
	if err != nil {
		return fail(err)
	}
	m8 := ikemsg.Payloads{&ikemsg.EAPPayload{Data: eap.Packet{Code: eap.CodeSuccess, Identifier: 3}.Marshal()}}
	out8, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr7.MessageID, m8)
	if err != nil {
		return fail(err)
	}
	if err := conn.Send(ctx, out8); err != nil {
		return fail(err)
	}

	// --- message 9: initiator AUTH → verify, reply with AUTH + SAr2 + TS + CP ---
	raw9, err := conn.Recv(ctx)
	if err != nil {
		return fail(err)
	}
	hdr9, inner9, err := rs.decodeSK(raw9)
	if err != nil {
		return fail(err)
	}
	var initAuth *ikemsg.AuthPayload
	for _, p := range inner9 {
		if v, ok := p.(*ikemsg.AuthPayload); ok {
			initAuth = v
		}
	}
	if initAuth == nil {
		return fail(errFail("missing initiator AUTH"))
	}
	// Verify the initiator's MSK AUTH.
	ucs2, _ := rfc2759.ToUTF16([]byte(password))
	phh := rfc2759.NTPasswordHash(rfc2759.NTPasswordHash(ucs2))
	msk, err := eap.DeriveMSK(phh, ntResponse)
	if err != nil {
		return fail(err)
	}
	initSigned := iauth.SignedOctets(rs.ikeSA.PRF, raw1, nr, ikemsg.MarshalIDBody(idi.IDType, idi.Data), rs.ikeSA.SKpi)
	wantInitAuth := iauth.SharedSecretAuth(rs.ikeSA.PRF, msk, initSigned)
	if !bytes.Equal(initAuth.Data, wantInitAuth) {
		return fail(errFail("initiator MSK AUTH mismatch"))
	}

	// Build final response, narrowed to the requested suite.
	var childSPIBuf [4]byte
	rand.Read(childSPIBuf[:])
	res.childResponderSPI = binary.BigEndian.Uint32(childSPIBuf[:])
	res.childKeys = rs.ikeSA.DeriveChildKeys(ni, nr, suite.encrKeyLen, suite.integKeyLen)

	respAuth := iauth.SharedSecretAuth(rs.ikeSA.PRF, msk, respSigned)
	m10 := ikemsg.Payloads{
		&ikemsg.AuthPayload{Method: iauth.MethodSharedKeyMIC, Data: respAuth},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, suite, childSPIBuf[:])}},
	}
	appendTrafficSelectors(&m10, true)
	ip := netip.MustParseAddr("10.10.0.42").As4()
	mask := netip.MustParseAddr("255.255.255.0").As4()
	ip6 := netip.MustParseAddr("fd00:10::42").As16()
	m10 = append(m10, &ikemsg.ConfigPayload{
		CfgType: ikemsg.ConfigReply,
		Attributes: []ikemsg.ConfigAttr{
			{Type: ikemsg.ConfigAttrInternalIP4Address, Value: ip[:]},
			{Type: ikemsg.ConfigAttrInternalIP4Netmask, Value: mask[:]},
			// INTERNAL_IP6_ADDRESS: 16-byte address + 1-byte prefix length (/64).
			{Type: ikemsg.ConfigAttrInternalIP6Address, Value: append(append([]byte(nil), ip6[:]...), 64)},
		},
	})

	out10, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr9.MessageID, m10)
	if err != nil {
		return fail(err)
	}
	if err := conn.Send(ctx, out10); err != nil {
		return fail(err)
	}
	return res
}

// TestOfflineHandshakePSK drives the initiator state machine through the PSK
// IKE_AUTH path (IKE_SA_INIT + a single-round PSK IKE_AUTH + Child SA) against a
// cooperating in-memory PSK responder. It proves both ends reach "established"
// and derive identical Child SA keys with no EAP conversation and no certificate.
func TestOfflineHandshakePSK(t *testing.T) {
	psk := []byte("a-strong-preshared-key")
	initConn, respConn := transport.MemoryPair()

	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("client.test")},
		RemoteID:        WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")},
		PSK:             psk,
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	respDone := make(chan *responderResult, 1)
	go func() { respDone <- runResponderPSK(respConn, psk, cbcSuite(), nil) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	if err := initSess.IKEAuth(ctx); err != nil {
		t.Fatalf("IKEAuth (PSK): %v", err)
	}
	if !initSess.Established() {
		t.Fatal("session not established")
	}

	res := <-respDone
	if res.err != nil {
		t.Fatalf("responder: %v", res.err)
	}
	if initSess.Assigned().IP != netip.MustParseAddr("10.10.0.77") {
		t.Fatalf("assigned IP = %v, want 10.10.0.77", initSess.Assigned().IP)
	}
	// The responder's IDr (carried in the single PSK response) must be recorded.
	if got := string(initSess.remoteIDr.Data); got != "vpn.test" {
		t.Fatalf("remote IDr = %q, want vpn.test", got)
	}
	child := initSess.Child()
	if child == nil {
		t.Fatal("no child SA installed")
	}
	if child.ResponderSPI != res.childResponderSPI {
		t.Fatalf("responder SPI mismatch: %08x vs %08x", child.ResponderSPI, res.childResponderSPI)
	}
	if !bytes.Equal(child.Keys.EncrIR, res.childKeys.EncrIR) ||
		!bytes.Equal(child.Keys.IntegRI, res.childKeys.IntegRI) {
		t.Fatal("child SA key material disagrees across initiator/responder")
	}
}

// TestOfflineHandshakePSKWrongKey proves a mismatched PSK is rejected at AUTH
// verification: the initiator holds a different key than the responder, so the
// responder's AUTH fails to verify and the session is not established.
func TestOfflineHandshakePSKWrongKey(t *testing.T) {
	initConn, respConn := transport.MemoryPair()

	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("client.test")},
		PSK:             []byte("client-key"),
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	respDone := make(chan *responderResult, 1)
	go func() { respDone <- runResponderPSK(respConn, []byte("server-key"), cbcSuite(), nil) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	if err := initSess.IKEAuth(ctx); err == nil {
		t.Fatal("IKEAuth accepted a mismatched PSK")
	}
	if initSess.Established() {
		t.Fatal("session must not be established with a wrong PSK")
	}
	<-respDone // drain the responder goroutine (it fails on the initiator AUTH)
}

// respondSAInit performs the responder half of IKE_SA_INIT on conn: it reads the
// initiator's request, derives the IKE SA into rs (Responder role, the given
// IKE suite), sends the response narrowed to that suite, and returns the
// verbatim request/response datagrams and the initiator nonce — the inputs the
// IKE_AUTH signed octets need. nr is the fixed responder nonce the caller
// supplies so it can recompute the same octets.
func respondSAInit(ctx context.Context, conn transport.Conn, rs *Session, nr []byte, ike ikeSuite) (raw1, realMessage2, ni []byte, err error) {
	raw1, err = conn.Recv(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	m1, err := ikemsg.Parse(raw1)
	if err != nil {
		return nil, nil, nil, err
	}
	var keiData []byte
	var keiGroup uint16
	for _, p := range m1.Payloads {
		switch v := p.(type) {
		case *ikemsg.KEPayload:
			keiData = v.Data
			keiGroup = v.Group
		case *ikemsg.NoncePayload:
			ni = v.Data
		}
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return nil, nil, nil, err
	}
	shared, err := respDH.Shared(keiData)
	if err != nil {
		return nil, nil, nil, err
	}
	var respSPIBuf [8]byte
	rand.Read(respSPIBuf[:])
	respSPI := binary.BigEndian.Uint64(respSPIBuf[:])

	rs.initiatorSPI = m1.InitiatorSPI
	rs.responderSPI = respSPI
	rs.ikeSA = &ikesa.IKESA{}
	if err := rs.ikeSA.Derive(ike.id, ikesa.Responder, m1.InitiatorSPI, respSPI, ni, nr, shared); err != nil {
		return nil, nil, nil, err
	}

	resp1 := &ikemsg.Message{
		InitiatorSPI: m1.InitiatorSPI,
		ResponderSPI: respSPI,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, ike, nil, keiGroup)}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: nr},
		},
	}
	realMessage2, err = resp1.Marshal()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := conn.Send(ctx, realMessage2); err != nil {
		return nil, nil, nil, err
	}
	return raw1, realMessage2, ni, nil
}

// cbcSuite returns the AES-CBC-256+HMAC ESP suite row for scripted responders
// that run outside a *testing.T context (goroutines).
func cbcSuite() espSuite {
	s, _ := suiteByID(esp.SuiteAESCBC256SHA256, espSuites)
	return s
}

// gcmIKESuite returns the AES-GCM-256 IKE suite row (the default preference)
// for scripted responders that run outside a *testing.T context (goroutines).
func gcmIKESuite() ikeSuite {
	s, _ := suiteByID(ikesa.SuiteAESGCM256, ikeSuites)
	return s
}

// runResponderPSK implements the PSK responder half: IKE_SA_INIT followed by a
// single IKE_AUTH round-trip that verifies the initiator's shared-key AUTH and
// replies with IDr, the responder's shared-key AUTH, SAr2 (narrowed to suite,
// optionally corrupted by mangle for negative tests), traffic selectors and
// the CFG reply. A PSK mismatch is surfaced as an error in the returned result.
func runResponderPSK(conn transport.Conn, psk []byte, suite espSuite, mangle func(*ikemsg.Proposal)) *responderResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := &responderResult{}
	fail := func(err error) *responderResult { res.err = err; return res }

	rs := New(Config{Logger: slog.New(slog.DiscardHandler)})
	nr := bytes.Repeat([]byte{0x42}, 32)

	raw1, realMessage2, ni, err := respondSAInit(ctx, conn, rs, nr, gcmIKESuite())
	if err != nil {
		return fail(err)
	}

	// --- IKE_AUTH message 3: IDi, AUTH(PSK), SA2, TSi, TSr, CP ---
	raw3, err := conn.Recv(ctx)
	if err != nil {
		return fail(err)
	}
	hdr3, inner3, err := rs.decodeSK(raw3)
	if err != nil {
		return fail(err)
	}
	var (
		idi      *ikemsg.IDiPayload
		initAuth *ikemsg.AuthPayload
	)
	for _, p := range inner3 {
		switch v := p.(type) {
		case *ikemsg.IDiPayload:
			idi = v
		case *ikemsg.AuthPayload:
			initAuth = v
		}
	}
	if idi == nil || initAuth == nil {
		return fail(errFail("PSK message 3 missing IDi or AUTH"))
	}
	if initAuth.Method != iauth.MethodSharedKeyMIC {
		return fail(errFail("initiator AUTH method is not SharedKeyMIC"))
	}
	// Verify the initiator's shared-key AUTH (a wrong PSK fails here).
	initSigned := iauth.SignedOctets(rs.ikeSA.PRF, raw1, nr, ikemsg.MarshalIDBody(idi.IDType, idi.Data), rs.ikeSA.SKpi)
	if want := iauth.SharedSecretAuth(rs.ikeSA.PRF, psk, initSigned); !bytes.Equal(initAuth.Data, want) {
		return fail(errFail("initiator PSK AUTH mismatch"))
	}

	// --- message 4: IDr, AUTH(PSK), SAr2, TSi, TSr, CP(reply) ---
	idr := WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")}
	respSigned := iauth.SignedOctets(rs.ikeSA.PRF, realMessage2, ni, ikemsg.MarshalIDBody(ikemsg.IDType(idr.Type), idr.Data), rs.ikeSA.SKpr)
	respAuth := iauth.SharedSecretAuth(rs.ikeSA.PRF, psk, respSigned)

	var childSPIBuf [4]byte
	rand.Read(childSPIBuf[:])
	res.childResponderSPI = binary.BigEndian.Uint32(childSPIBuf[:])
	res.childKeys = rs.ikeSA.DeriveChildKeys(ni, nr, suite.encrKeyLen, suite.integKeyLen)

	prop := buildProposalForSuite(1, suite, childSPIBuf[:])
	if mangle != nil {
		mangle(&prop)
	}
	m4 := ikemsg.Payloads{
		&ikemsg.IDrPayload{IDType: ikemsg.IDType(idr.Type), Data: idr.Data},
		&ikemsg.AuthPayload{Method: iauth.MethodSharedKeyMIC, Data: respAuth},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{prop}},
	}
	appendTrafficSelectors(&m4, false)
	ip := netip.MustParseAddr("10.10.0.77").As4()
	mask := netip.MustParseAddr("255.255.255.0").As4()
	m4 = append(m4, &ikemsg.ConfigPayload{
		CfgType: ikemsg.ConfigReply,
		Attributes: []ikemsg.ConfigAttr{
			{Type: ikemsg.ConfigAttrInternalIP4Address, Value: ip[:]},
			{Type: ikemsg.ConfigAttrInternalIP4Netmask, Value: mask[:]},
		},
	})
	out4, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr3.MessageID, m4)
	if err != nil {
		return fail(err)
	}
	if err := conn.Send(ctx, out4); err != nil {
		return fail(err)
	}
	return res
}

// newPSKInitSession builds the standard PSK initiator session over a fresh
// memory pair, optionally restricting the enabled ESP suites.
func newPSKInitSession(psk []byte, suites []esp.Suite) (*Session, transport.Conn) {
	initConn, respConn := transport.MemoryPair()
	s := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("client.test")},
		RemoteID:        WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")},
		PSK:             psk,
		ESPSuites:       suites,
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	})
	s.conn = initConn
	return s, respConn
}

// TestOfflineHandshakePSKDisabledSuiteRejected pins the enabled-suite gate: the
// client restricts the offer to CBC via Config.ESPSuites, but the responder
// answers with a GCM selection. IKE_AUTH must fail — a suite the operator
// disabled must never be installed, even if the server picked it.
func TestOfflineHandshakePSKDisabledSuiteRejected(t *testing.T) {
	psk := []byte("a-strong-preshared-key")
	initSess, respConn := newPSKInitSession(psk, []esp.Suite{esp.SuiteAESCBC256SHA256})

	gcm := mustSuite(t, esp.SuiteAESGCM256)
	respDone := make(chan *responderResult, 1)
	go func() { respDone <- runResponderPSK(respConn, psk, gcm, nil) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	err := initSess.IKEAuth(ctx)
	if err == nil {
		t.Fatal("IKE_AUTH accepted a suite the config disabled")
	}
	if !strings.Contains(err.Error(), "unsupported or ambiguous ESP proposal") {
		t.Fatalf("unexpected error: %v", err)
	}
	if initSess.Established() {
		t.Fatal("session must not be established")
	}
	<-respDone
}

// TestOfflineHandshakePSKAmbiguousSelectionRejected: the responder echoes a
// "selection" that still carries two ENCR alternatives — with several suites
// offered such a reply leaves the KEYMAT lengths undefined, so IKE_AUTH must
// reject it instead of guessing.
func TestOfflineHandshakePSKAmbiguousSelectionRejected(t *testing.T) {
	psk := []byte("a-strong-preshared-key")
	initSess, respConn := newPSKInitSession(psk, nil)

	gcm := mustSuite(t, esp.SuiteAESGCM256)
	ambiguous := func(p *ikemsg.Proposal) {
		p.Transforms = append(p.Transforms,
			ikemsg.Transform{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_CHACHA20_POLY1305})
	}
	respDone := make(chan *responderResult, 1)
	go func() { respDone <- runResponderPSK(respConn, psk, gcm, ambiguous) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	err := initSess.IKEAuth(ctx)
	if err == nil {
		t.Fatal("IKE_AUTH accepted an ambiguous two-ENCR selection")
	}
	if !strings.Contains(err.Error(), "unsupported or ambiguous ESP proposal") {
		t.Fatalf("unexpected error: %v", err)
	}
	if initSess.Established() {
		t.Fatal("session must not be established")
	}
	<-respDone
}

// TestOfflineHandshakePSKShortResponderSPIRejected pins that the final
// IKE_AUTH response validates the responder Child-SA SPI length before reading
// it: a malformed 3-byte SPI must be rejected cleanly, not panic.
func TestOfflineHandshakePSKShortResponderSPIRejected(t *testing.T) {
	psk := []byte("a-strong-preshared-key")
	initSess, respConn := newPSKInitSession(psk, nil)

	respDone := make(chan *responderResult, 1)
	go func() {
		respDone <- runResponderPSK(respConn, psk, cbcSuite(), func(p *ikemsg.Proposal) {
			p.SPI = p.SPI[:3]
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	err := initSess.IKEAuth(ctx)
	if err == nil {
		t.Fatal("IKE_AUTH accepted a responder ESP proposal with a short SPI")
	}
	if !strings.Contains(err.Error(), "invalid SPI length 3") {
		t.Fatalf("unexpected error: %v", err)
	}
	if initSess.Established() {
		t.Fatal("session must not be established")
	}
	<-respDone
}

// TestEAPSuccessWithoutMSCHAPVerifyRejected is the session-level finding #12: a
// server that runs the MSCHAPv2 challenge and then jumps straight to an outer
// EAP-Success — skipping the MSCHAPv2-Success step that proves it knows the
// password — must be rejected, not accepted with a derived MSK.
func TestEAPSuccessWithoutMSCHAPVerifyRejected(t *testing.T) {
	const username, password = "User", "clientPass"
	initConn, respConn := transport.MemoryPair()
	leaf, leafKey, roots := makeTestCert(t, "vpn.test")

	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		RemoteID:        WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")},
		EAPUser:         username,
		EAPPass:         []byte(password),
		RootCAs:         roots,
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	go eapSuccessSkipResponder(respConn, leaf, leafKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit: %v", err)
	}
	err := initSess.IKEAuth(ctx)
	if err == nil {
		t.Fatal("IKE_AUTH accepted an EAP-Success that skipped MSCHAPv2 verification")
	}
	if !strings.Contains(err.Error(), "without verifying MSCHAPv2") {
		t.Fatalf("unexpected error: %v", err)
	}
	if initSess.Established() {
		t.Fatal("session must not be established")
	}
}

// eapSuccessSkipResponder performs IKE_SA_INIT and IKE_AUTH up to the EAP
// challenge, then sends an outer EAP-Success WITHOUT the MSCHAPv2-Success step.
func eapSuccessSkipResponder(conn transport.Conn, leaf *x509.Certificate, leafKey *rsa.PrivateKey) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rs := New(Config{Logger: slog.New(slog.DiscardHandler)})

	nr := bytes.Repeat([]byte{0x42}, 32)
	_, realMessage2, ni, err := respondSAInit(ctx, conn, rs, nr, gcmIKESuite())
	if err != nil {
		return
	}

	// IKE_AUTH message 3.
	raw3, err := conn.Recv(ctx)
	if err != nil {
		return
	}
	hdr3, _, err := rs.decodeSK(raw3)
	if err != nil {
		return
	}

	// message 4: IDr, CERT, AUTH(cert), EAP-Challenge.
	idr := WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")}
	respSigned := iauth.SignedOctets(rs.ikeSA.PRF, realMessage2, ni, ikemsg.MarshalIDBody(ikemsg.IDType(idr.Type), idr.Data), rs.ikeSA.SKpr)
	certAuth, err := signRFC7427(leafKey, respSigned)
	if err != nil {
		return
	}
	authChallenge := bytes.Repeat([]byte{0x11}, 16)
	m4 := ikemsg.Payloads{
		&ikemsg.IDrPayload{IDType: ikemsg.IDType(idr.Type), Data: idr.Data},
		&ikemsg.CertPayload{Encoding: ikemsg.CertX509Signature, Data: leaf.Raw},
		&ikemsg.AuthPayload{Method: iauth.MethodDigitalSignature, Data: certAuth},
		&ikemsg.EAPPayload{Data: mschapChallenge(1, authChallenge).Marshal()},
	}
	out4, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr3.MessageID, m4)
	if err != nil {
		return
	}
	if err := conn.Send(ctx, out4); err != nil {
		return
	}

	// message 5: the client's EAP-Response (consumed, not validated here).
	raw5, err := conn.Recv(ctx)
	if err != nil {
		return
	}
	hdr5, _, err := rs.decodeSK(raw5)
	if err != nil {
		return
	}

	// message 6: jump straight to an OUTER EAP-Success, skipping MSCHAPv2-Success.
	m6 := ikemsg.Payloads{&ikemsg.EAPPayload{Data: eap.Packet{Code: eap.CodeSuccess, Identifier: 2}.Marshal()}}
	out6, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr5.MessageID, m6)
	if err != nil {
		return
	}
	_ = conn.Send(ctx, out6)
}

// TestIKESAInitCookieRetry drives IKE_SA_INIT against a responder that issues a
// COOKIE challenge, checking the client retries with the cookie echoed as the
// first payload (RFC 7296 §2.6) and then completes key derivation.
func TestIKESAInitCookieRetry(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		EAPUser:         "u",
		EAPPass:         []byte("p"),
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  time.Second,
		RetransmitMax:   2 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	cookie := []byte("test-cookie-blob-1234")
	done := make(chan error, 1)
	go func() { done <- cookieResponder(respConn, cookie) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit with cookie retry: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("responder: %v", err)
	}
	if initSess.ikeSA == nil {
		t.Fatal("IKE SA not derived after cookie retry")
	}
}

// cookieResponder answers the first IKE_SA_INIT with a COOKIE notify, then
// expects the retry to carry that cookie first and replies with a normal
// IKE_SA_INIT response.
func cookieResponder(conn transport.Conn, cookie []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw1, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m1, err := ikemsg.Parse(raw1)
	if err != nil {
		return err
	}
	ck := &ikemsg.Message{
		InitiatorSPI: m1.InitiatorSPI,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads:     ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyCookie, Data: cookie}},
	}
	out, err := ck.Marshal()
	if err != nil {
		return err
	}
	if err := conn.Send(ctx, out); err != nil {
		return err
	}

	raw2, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m2, err := ikemsg.Parse(raw2)
	if err != nil {
		return err
	}
	if len(m2.Payloads) == 0 {
		return errFail("retry IKE_SA_INIT had no payloads")
	}
	n, ok := m2.Payloads[0].(*ikemsg.NotifyPayload)
	if !ok || n.Type != ikemsg.NotifyCookie || !bytes.Equal(n.Data, cookie) {
		return errFail("retry did not echo the cookie as the first payload")
	}

	var keiData []byte
	var keiGroup uint16
	for _, p := range m2.Payloads {
		if v, ok := p.(*ikemsg.KEPayload); ok {
			keiData = v.Data
			keiGroup = v.Group
		}
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return err
	}
	if _, err := respDH.Shared(keiData); err != nil {
		return err
	}
	var spiBuf [8]byte
	rand.Read(spiBuf[:])
	resp := &ikemsg.Message{
		InitiatorSPI: m2.InitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint64(spiBuf[:]),
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, gcmIKESuite(), nil, keiGroup)}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0x42}, 32)},
		},
	}
	out2, err := resp.Marshal()
	if err != nil {
		return err
	}
	return conn.Send(ctx, out2)
}

// TestIKESAInitRetransmit proves IKE_SA_INIT recovers from a lost first request
// the same way later exchanges do: the responder drops the initial datagram and
// answers only the retransmit, yet the handshake still derives keys instead of
// failing the Dial on a single UDP drop.
func TestIKESAInitRetransmit(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		EAPUser:         "u",
		EAPPass:         []byte("p"),
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  100 * time.Millisecond,
		RetransmitMax:   200 * time.Millisecond,
		RetransmitTries: 5,
	})
	initSess.conn = initConn

	done := make(chan error, 1)
	go func() { done <- dropFirstSAInitResponder(respConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit did not recover from a dropped first request: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("responder: %v", err)
	}
	if initSess.ikeSA == nil {
		t.Fatal("IKE SA not derived after retransmit")
	}
}

// dropFirstSAInitResponder discards the first IKE_SA_INIT request and answers the
// retransmit with a normal IKE_SA_INIT response.
func dropFirstSAInitResponder(conn transport.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := conn.Recv(ctx); err != nil { // drop the first request
		return err
	}
	raw, err := conn.Recv(ctx) // answer the retransmit
	if err != nil {
		return err
	}
	m, err := ikemsg.Parse(raw)
	if err != nil {
		return err
	}
	var keiData []byte
	var keiGroup uint16
	for _, p := range m.Payloads {
		if v, ok := p.(*ikemsg.KEPayload); ok {
			keiData = v.Data
			keiGroup = v.Group
		}
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return err
	}
	if _, err := respDH.Shared(keiData); err != nil {
		return err
	}
	var spiBuf [8]byte
	rand.Read(spiBuf[:])
	resp := &ikemsg.Message{
		InitiatorSPI: m.InitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint64(spiBuf[:]),
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, gcmIKESuite(), nil, keiGroup)}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0x42}, 32)},
		},
	}
	out, err := resp.Marshal()
	if err != nil {
		return err
	}
	return conn.Send(ctx, out)
}

// TestIKESAInitInvalidKERetry drives IKE_SA_INIT against a responder that rejects
// our preferred x25519 KE with N(INVALID_KE_PAYLOAD) demanding MODP-2048, and
// checks the client retries with group 14 and completes key derivation (the
// modp-only-server fallback path).
func TestIKESAInitInvalidKERetry(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		EAPUser:         "u",
		EAPPass:         []byte("p"),
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  time.Second,
		RetransmitMax:   2 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	done := make(chan error, 1)
	go func() { done <- invalidKEResponder(respConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit with INVALID_KE retry: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("responder: %v", err)
	}
	if initSess.ikeSA == nil {
		t.Fatal("IKE SA not derived after INVALID_KE retry")
	}
	if initSess.dh.Group != ikemsg.DH_MODP2048 || initSess.ikeDHGroup != ikemsg.DH_MODP2048 {
		t.Fatalf("client did not fall back to group 14: dh=%d ikeDHGroup=%d", initSess.dh.Group, initSess.ikeDHGroup)
	}
}

// invalidKEResponder answers the first IKE_SA_INIT (x25519 KEi) with an
// INVALID_KE_PAYLOAD demanding group 14, then completes the retried exchange.
func invalidKEResponder(conn transport.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw1, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m1, err := ikemsg.Parse(raw1)
	if err != nil {
		return err
	}
	// The first offer's KEi must be x25519 (the client's preference).
	for _, p := range m1.Payloads {
		if ke, ok := p.(*ikemsg.KEPayload); ok && ke.Group != ikemsg.DH_X25519 {
			return errFail("first KEi was not group 31")
		}
	}
	var grp [2]byte
	binary.BigEndian.PutUint16(grp[:], ikemsg.DH_MODP2048)
	rej := &ikemsg.Message{
		InitiatorSPI: m1.InitiatorSPI,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads:     ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyInvalidKEPayload, Data: grp[:]}},
	}
	out, err := rej.Marshal()
	if err != nil {
		return err
	}
	if err := conn.Send(ctx, out); err != nil {
		return err
	}

	raw2, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m2, err := ikemsg.Parse(raw2)
	if err != nil {
		return err
	}
	var keiData []byte
	var keiGroup uint16
	for _, p := range m2.Payloads {
		if v, ok := p.(*ikemsg.KEPayload); ok {
			keiData = v.Data
			keiGroup = v.Group
		}
	}
	if keiGroup != ikemsg.DH_MODP2048 {
		return errFail("retry KEi was not group 14")
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return err
	}
	if _, err := respDH.Shared(keiData); err != nil {
		return err
	}
	var spiBuf [8]byte
	rand.Read(spiBuf[:])
	resp := &ikemsg.Message{
		InitiatorSPI: m2.InitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint64(spiBuf[:]),
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, gcmIKESuite(), nil, keiGroup)}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0x42}, 32)},
		},
	}
	out2, err := resp.Marshal()
	if err != nil {
		return err
	}
	return conn.Send(ctx, out2)
}

// TestMalformedSAInitNoPanic is the finding #1 regression. A spoofed or
// corrupted IKE_SA_INIT whose SA proposal claims ProposalLength=9 but SPISize=200
// would index out of range in a naive decoder. ikemsg.Parse is bounds-safe, so it
// returns an error; handleSAInitResponse and saInitCookie surface that as an
// ordinary decode failure rather than crashing the process.
func TestMalformedSAInitNoPanic(t *testing.T) {
	raw := malformedSAInit()

	// The codec must reject the crafted length, not panic on it.
	if _, err := ikemsg.Parse(raw); err == nil {
		t.Fatal("ikemsg.Parse accepted a malformed SA proposal")
	}

	s := New(Config{Logger: slog.New(slog.DiscardHandler)})
	if err := s.handleSAInitResponse(raw); err == nil {
		t.Fatal("handleSAInitResponse accepted a malformed IKE_SA_INIT")
	}
	if _, ok := saInitCookie(raw); ok {
		t.Fatal("saInitCookie reported a cookie in a malformed message")
	}
}

// malformedSAInit builds an otherwise well-formed IKE_SA_INIT datagram whose
// single SA proposal sets ProposalLength=9 and SPISize=200, so a naive decoder
// evaluates rawData[8+200:9] (low > high).
func malformedSAInit() []byte {
	const total = 240
	raw := make([]byte, total)
	binary.BigEndian.PutUint64(raw[0:8], 0x1122334455667788)  // initiator SPI
	binary.BigEndian.PutUint64(raw[8:16], 0x99AABBCCDDEEFF00) // responder SPI
	raw[16] = byte(ikemsg.PayloadSA)                          // first payload
	raw[17] = 0x20                                            // version
	raw[18] = byte(ikemsg.ExchangeIKESAInit)                  // exchange type
	raw[19] = byte(ikemsg.FlagResponse)                       // flags
	binary.BigEndian.PutUint32(raw[24:28], uint32(total))     // header length

	// SA generic payload header at offset 28.
	raw[28] = 0                                              // next payload (none)
	raw[29] = 0                                              // critical/reserved
	binary.BigEndian.PutUint16(raw[30:32], uint16(total-28)) // SA payload length = 212

	// Proposal substructure at offset 32 (SA body, 208 bytes).
	body := raw[32:]
	body[0] = 0                              // last proposal
	binary.BigEndian.PutUint16(body[2:4], 9) // proposal length = 9
	body[4] = 1                              // proposal number
	body[5] = byte(ikemsg.ProtocolIKE)       // protocol ID
	body[6] = 200                            // SPI size (overruns the proposal)
	body[7] = 0                              // num transforms
	return raw
}

// TestBuildEAPResponseNotification is finding #4: an EAP Request/Notification
// (RFC 3748 §5.2) must be acknowledged with an empty EAP-Response/Notification so
// the conversation continues, instead of aborting the IKE_AUTH handshake.
func TestBuildEAPResponseNotification(t *testing.T) {
	req := eap.Packet{Code: eap.CodeRequest, Identifier: 7, Type: eap.TypeNotification, Data: []byte("server says hi")}
	resp, err := buildEAPResponse(nil, req)
	if err != nil {
		t.Fatalf("Notification request aborted the handshake: %v", err)
	}
	if resp.Code != eap.CodeResponse || resp.Type != eap.TypeNotification || resp.Identifier != 7 {
		t.Fatalf("unexpected Notification response: %+v", resp)
	}
}

// TestHandleSAInitResponseValidation is finding #3: an IKE_SA_INIT datagram that
// is a request, carries a foreign initiator SPI, or a non-zero Message ID must be
// rejected instead of being consumed as the genuine response.
func TestHandleSAInitResponseValidation(t *testing.T) {
	s := New(Config{Logger: slog.New(slog.DiscardHandler)})
	s.initiatorSPI = 0xAABBCCDDEEFF0011

	build := func(mod func(*ikemsg.Message)) []byte {
		m := &ikemsg.Message{
			InitiatorSPI: s.initiatorSPI,
			ResponderSPI: 0x99,
			Exchange:     ikemsg.ExchangeIKESAInit,
			Flags:        ikemsg.FlagResponse,
		}
		mod(m)
		raw, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	cases := []struct {
		name string
		mod  func(*ikemsg.Message)
	}{
		{"request not response", func(m *ikemsg.Message) { m.Flags = ikemsg.FlagInitiator }},
		{"wrong initiator SPI", func(m *ikemsg.Message) { m.InitiatorSPI = s.initiatorSPI ^ 1 }},
		{"nonzero message ID", func(m *ikemsg.Message) { m.MessageID = 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.handleSAInitResponse(build(tc.mod)); err == nil {
				t.Fatal("accepted an IKE_SA_INIT datagram that should be rejected")
			}
		})
	}
}

// TestIKESAInitInvalidKEThenCookie is finding #13: a responder that issues a
// COOKIE challenge only on the INVALID_KE retry must still complete — the cookie
// is re-checked after the group switch rather than falling through as a bare
// SA/KE/Nonce-less message.
func TestIKESAInitInvalidKEThenCookie(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	initSess := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		EAPUser:         "u",
		EAPPass:         []byte("p"),
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  time.Second,
		RetransmitMax:   2 * time.Second,
		RetransmitTries: 3,
	})
	initSess.conn = initConn

	done := make(chan error, 1)
	go func() { done <- invalidKEThenCookieResponder(respConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initSess.IKESAInit(ctx); err != nil {
		t.Fatalf("IKESAInit with INVALID_KE then COOKIE: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("responder: %v", err)
	}
	if initSess.ikeSA == nil {
		t.Fatal("IKE SA not derived after INVALID_KE + COOKIE")
	}
	if initSess.dh.Group != ikemsg.DH_MODP2048 {
		t.Fatalf("client did not fall back to group 14: dh=%d", initSess.dh.Group)
	}
}

// invalidKEThenCookieResponder answers the first offer with INVALID_KE(group 14),
// the group-14 retry with a COOKIE challenge, and the cookie echo with a complete
// IKE_SA_INIT response.
func invalidKEThenCookieResponder(conn transport.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hasCookie := func(m *ikemsg.Message) bool {
		for _, p := range m.Payloads {
			if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyCookie {
				return true
			}
		}
		return false
	}
	sendNotify := func(spi uint64, n *ikemsg.NotifyPayload) error {
		out, err := (&ikemsg.Message{
			InitiatorSPI: spi,
			Exchange:     ikemsg.ExchangeIKESAInit,
			Flags:        ikemsg.FlagResponse,
			Payloads:     ikemsg.Payloads{n},
		}).Marshal()
		if err != nil {
			return err
		}
		return conn.Send(ctx, out)
	}

	// 1) first offer (x25519) → INVALID_KE demanding group 14.
	raw1, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m1, err := ikemsg.Parse(raw1)
	if err != nil {
		return err
	}
	var grp [2]byte
	binary.BigEndian.PutUint16(grp[:], ikemsg.DH_MODP2048)
	if err := sendNotify(m1.InitiatorSPI, &ikemsg.NotifyPayload{Type: ikemsg.NotifyInvalidKEPayload, Data: grp[:]}); err != nil {
		return err
	}

	// 2) group-14 retry (no cookie yet) → COOKIE challenge.
	raw2, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m2, err := ikemsg.Parse(raw2)
	if err != nil {
		return err
	}
	if hasCookie(m2) {
		return errFail("INVALID_KE retry unexpectedly carried a cookie")
	}
	if err := sendNotify(m2.InitiatorSPI, &ikemsg.NotifyPayload{Type: ikemsg.NotifyCookie, Data: []byte("cookie-blob-123")}); err != nil {
		return err
	}

	// 3) cookie echo → complete the exchange.
	raw3, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m3, err := ikemsg.Parse(raw3)
	if err != nil {
		return err
	}
	if !hasCookie(m3) {
		return errFail("final request did not echo the cookie")
	}
	var keiData []byte
	var keiGroup uint16
	for _, p := range m3.Payloads {
		if v, ok := p.(*ikemsg.KEPayload); ok {
			keiData = v.Data
			keiGroup = v.Group
		}
	}
	if keiGroup != ikemsg.DH_MODP2048 {
		return errFail("final KEi was not group 14")
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return err
	}
	if _, err := respDH.Shared(keiData); err != nil {
		return err
	}
	var spiBuf [8]byte
	rand.Read(spiBuf[:])
	out, err := (&ikemsg.Message{
		InitiatorSPI: m3.InitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint64(spiBuf[:]),
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildProposalForSuite(1, gcmIKESuite(), nil, keiGroup)}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0x42}, 32)},
		},
	}).Marshal()
	if err != nil {
		return err
	}
	return conn.Send(ctx, out)
}

// --- test helpers ---

type errFail string

func (e errFail) Error() string { return string(e) }

func mschapChallenge(id uint8, authChallenge []byte) eap.Packet {
	data := []byte{1, id, 0, 0, 16}
	data = append(data, authChallenge...)
	data = append(data, []byte("responder")...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return eap.Packet{Code: eap.CodeRequest, Identifier: id, Type: eap.TypeMSCHAPv2, Data: data}
}

func mschapSuccessRequest(id uint8, authResp string) eap.Packet {
	data := append([]byte{3, id, 0, 0}, []byte(authResp)...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return eap.Packet{Code: eap.CodeRequest, Identifier: id, Type: eap.TypeMSCHAPv2, Data: data}
}

func signRFC7427(key *rsa.PrivateKey, signed []byte) ([]byte, error) {
	h := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}
	type ai struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	algoDER, err := asn1.Marshal(ai{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		Parameters: asn1.NullRawValue,
	})
	if err != nil {
		return nil, err
	}
	out := append([]byte{byte(len(algoDER))}, algoDER...)
	return append(out, sig...), nil
}

func makeTestCert(t *testing.T, dns string) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dns},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dns},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return leaf, leafKey, roots
}

// saInitOnlyResponder answers a single IKE_SA_INIT with a complete response
// whose narrowed proposal (GCM by default) is first passed through mangle,
// then exits — the negative-path tests fail in handleSAInitResponse before
// IKE_AUTH begins.
func saInitOnlyResponder(conn transport.Conn, mangle func(*ikemsg.Proposal)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw1, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	m1, err := ikemsg.Parse(raw1)
	if err != nil {
		return err
	}
	var keiData []byte
	var keiGroup uint16
	for _, p := range m1.Payloads {
		if v, ok := p.(*ikemsg.KEPayload); ok {
			keiData = v.Data
			keiGroup = v.Group
		}
	}
	respDH, err := ikesa.NewDH(keiGroup)
	if err != nil {
		return err
	}
	if _, err := respDH.Shared(keiData); err != nil {
		return err
	}
	prop := buildProposalForSuite(1, gcmIKESuite(), nil, keiGroup)
	if mangle != nil {
		mangle(&prop)
	}
	var spiBuf [8]byte
	rand.Read(spiBuf[:])
	out, err := (&ikemsg.Message{
		InitiatorSPI: m1.InitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint64(spiBuf[:]),
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagResponse,
		Payloads: ikemsg.Payloads{
			&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{prop}},
			&ikemsg.KEPayload{Group: keiGroup, Data: respDH.Public},
			&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0x42}, 32)},
		},
	}).Marshal()
	if err != nil {
		return err
	}
	return conn.Send(ctx, out)
}

// newSAInitOnlySession builds an initiator session over a fresh memory pair
// for the IKE_SA_INIT negative tests, optionally restricting the enabled IKE
// suites.
func newSAInitOnlySession(ikeSuites []ikesa.Suite) (*Session, transport.Conn) {
	initConn, respConn := transport.MemoryPair()
	s := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("user@example.com")},
		EAPUser:         "u",
		EAPPass:         []byte("p"),
		IKESuites:       ikeSuites,
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  time.Second,
		RetransmitMax:   2 * time.Second,
		RetransmitTries: 3,
	})
	s.conn = initConn
	return s, respConn
}

// TestIKESAInitDisabledSuiteRejected pins the enabled-suite gate for the IKE
// envelope: the client restricts the offer to CBC via Config.IKESuites, but
// the responder answers with a GCM selection. IKE_SA_INIT must fail — a suite
// the operator disabled must never key the envelope, even if the server picked
// it.
func TestIKESAInitDisabledSuiteRejected(t *testing.T) {
	initSess, respConn := newSAInitOnlySession([]ikesa.Suite{ikesa.SuiteAESCBC256SHA256})

	done := make(chan error, 1)
	go func() { done <- saInitOnlyResponder(respConn, nil) }() // narrows to GCM

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := initSess.IKESAInit(ctx)
	if err == nil {
		t.Fatal("IKE_SA_INIT accepted an IKE suite the config disabled")
	}
	if !strings.Contains(err.Error(), "unsupported or ambiguous IKE proposal") {
		t.Fatalf("unexpected error: %v", err)
	}
	if rerr := <-done; rerr != nil {
		t.Fatalf("responder: %v", rerr)
	}
}

// TestIKESAInitAmbiguousSelectionRejected: a responder "selection" that still
// carries two ENCR alternatives leaves the SKEYSEED split undefined, so
// IKE_SA_INIT must reject it instead of guessing.
func TestIKESAInitAmbiguousSelectionRejected(t *testing.T) {
	initSess, respConn := newSAInitOnlySession(nil)

	ambiguous := func(p *ikemsg.Proposal) {
		p.Transforms = append(p.Transforms,
			ikemsg.Transform{Type: ikemsg.TransformEncr, ID: ikemsg.ENCR_CHACHA20_POLY1305})
	}
	done := make(chan error, 1)
	go func() { done <- saInitOnlyResponder(respConn, ambiguous) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := initSess.IKESAInit(ctx)
	if err == nil {
		t.Fatal("IKE_SA_INIT accepted an ambiguous two-ENCR selection")
	}
	if !strings.Contains(err.Error(), "unsupported or ambiguous IKE proposal") {
		t.Fatalf("unexpected error: %v", err)
	}
	if rerr := <-done; rerr != nil {
		t.Fatalf("responder: %v", rerr)
	}
}

// TestSAInitCookieBounds: RFC 7296 §2.6 caps COOKIE notification data at 64
// octets. An oversized (or empty) cookie from the responder is ignored rather
// than echoed back verbatim into our retry request.
func TestSAInitCookieBounds(t *testing.T) {
	build := func(cookie []byte) []byte {
		m := &ikemsg.Message{
			InitiatorSPI: 1, ResponderSPI: 2,
			Exchange: ikemsg.ExchangeIKESAInit,
			Flags:    ikemsg.FlagResponse,
			Payloads: ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyCookie, Data: cookie}},
		}
		raw, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if c, ok := saInitCookie(build(bytes.Repeat([]byte{0xAB}, 64))); !ok || len(c) != 64 {
		t.Fatal("a valid 64-byte cookie was rejected")
	}
	if _, ok := saInitCookie(build(bytes.Repeat([]byte{0xAB}, 65))); ok {
		t.Fatal("a 65-byte cookie (over the RFC 7296 §2.6 cap) was accepted")
	}
	if _, ok := saInitCookie(build(nil)); ok {
		t.Fatal("an empty cookie was accepted")
	}
}
