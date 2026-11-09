package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/n0madic/go-ipsec/internal/auth"
	"github.com/n0madic/go-ipsec/internal/eap"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
)

// maxEAPRounds bounds the EAP request/response conversation so a misbehaving
// responder that never sends Success/Failure cannot loop the handshake forever.
const maxEAPRounds = 32

// ChildSA holds the first Child SA negotiated during IKE_AUTH.
type ChildSA struct {
	InitiatorSPI uint32 // our SPI (responder sends to it)
	ResponderSPI uint32 // responder SPI (we send to it)
	Suite        esp.Suite
	Keys         ikesa.ChildKeys
}

// Assigned is the layer-3 configuration the responder pushed via the CFG payload.
type Assigned struct {
	IP      netip.Addr
	Netmask netip.Addr
	Gateway netip.Addr
	DNS     []netip.Addr

	// IP6 is the inner IPv6 address + prefix the responder assigned (zero value
	// when none was pushed — e.g. a v4-only server). DNS6 holds any IPv6 resolvers.
	IP6  netip.Prefix
	DNS6 []netip.Addr
}

// IKEAuth runs the IKE_AUTH exchange and installs the first Child SA. It
// dispatches on the configured credential: a pre-shared key (PSK) authenticates
// in a single round-trip, while EAP-MSCHAPv2 runs the multi-message EAP
// conversation. It must be called after IKESAInit.
func (s *Session) IKEAuth(ctx context.Context) error {
	if s.ikeSA == nil {
		return errors.New("session: IKEAuth before IKESAInit")
	}
	if s.cfg.FortinetSAML {
		return s.ikeAuthFortinetSAML(ctx)
	}
	if len(s.cfg.PSK) > 0 {
		return s.ikeAuthPSK(ctx)
	}
	if s.cfg.ClientCertificate != nil {
		return s.ikeAuthCertificate(ctx)
	}
	return s.ikeAuthEAP(ctx)
}

// allocChildSPI generates and records this client's first Child SA SPI, returning
// the 4-byte value for the ESP proposal.
func (s *Session) allocChildSPI() ([]byte, error) {
	var spiBuf [4]byte
	if _, err := rand.Read(spiBuf[:]); err != nil {
		return nil, err
	}
	s.childInitiatorSPI = binary.BigEndian.Uint32(spiBuf[:])
	return spiBuf[:], nil
}

// ikeAuthPSK runs the PSK IKE_AUTH exchange: a single SK{IDi, AUTH, SA2, TSi, TSr,
// CP} request carrying the shared-key AUTH up front (no EAP request), and the
// responder's SK{IDr, AUTH, SAr2, TSi, TSr, CP} reply that proves it holds the
// same PSK and installs the first Child SA.
func (s *Session) ikeAuthPSK(ctx context.Context) error {
	spi, err := s.allocChildSPI()
	if err != nil {
		return err
	}

	// IDi, the shared-key AUTH, the ESP proposals (one per enabled suite),
	// full-tunnel selectors and the CFG request — everything the EAP path
	// spreads across several messages, in one request because PSK needs no EAP
	// round-trip. The initial Child SA uses the IKE SA's key material, with no
	// separate DH exchange (RFC 7296 section 1.2).
	first := ikemsg.Payloads{
		&ikemsg.IDiPayload{IDType: ikemsg.IDType(s.cfg.LocalID.Type), Data: s.cfg.LocalID.Data},
		&ikemsg.AuthPayload{Method: auth.MethodSharedKeyMIC, Data: s.computeInitiatorAuth(s.cfg.PSK)},
		&ikemsg.SAPayload{Proposals: buildProposals(spi, s.enabledESPSuites())},
	}
	appendTrafficSelectors(&first, s.cfg.RequestIPv6)
	buildCPRequest(&first, s.cfg.RequestIPv6)

	resp, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, first)
	if err != nil {
		return fmt.Errorf("session: IKE_AUTH (PSK): %w", err)
	}
	s.messageID++

	// Surface a responder error notify (e.g. AUTHENTICATION_FAILED for a wrong PSK)
	// before the generic AUTH-verification failure below.
	if err := firstNotifyError(resp); err != nil {
		return err
	}
	return s.handleFinalAuthResponse(resp, s.cfg.PSK)
}

// ikeAuthEAP runs the full IKE_AUTH exchange with EAP-MSCHAPv2 and installs the
// first Child SA.
func (s *Session) ikeAuthEAP(ctx context.Context) error {
	spi, err := s.allocChildSPI()
	if err != nil {
		return err
	}

	// --- Message 3: IDi, SA2, TSi, TSr, CP(request); no AUTH → request EAP. ---
	// The first Child SA is keyed from the IKE SA and carries no separate KE or
	// DH transforms (RFC 7296 section 1.2). One proposal per enabled ESP suite,
	// in our preference order. PFS is negotiated in CREATE_CHILD_SA instead.
	first := ikemsg.Payloads{
		&ikemsg.IDiPayload{IDType: ikemsg.IDType(s.cfg.LocalID.Type), Data: s.cfg.LocalID.Data},
		&ikemsg.SAPayload{Proposals: buildProposals(spi, s.enabledESPSuites())},
	}
	appendTrafficSelectors(&first, s.cfg.RequestIPv6)
	buildCPRequest(&first, s.cfg.RequestIPv6)

	respPayloads, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, first)
	if err != nil {
		return fmt.Errorf("session: IKE_AUTH message 3: %w", err)
	}
	s.messageID++

	// --- Message 4: IDr, CERT, AUTH(cert), EAP(first request). ---
	eapReq, err := s.handleAuthResponse(respPayloads)
	if err != nil {
		return err
	}

	// --- EAP loop. ---
	// The conversation owns a private tracked copy of the password; wipe it
	// (and every password-derived buffer) as soon as IKE_AUTH is over — the
	// MSK is the only thing the rest of the session needs, and rekeys use
	// SK_d, never the password.
	mschap := eap.NewMSCHAPv2(s.cfg.EAPUser, s.cfg.EAPPass)
	defer mschap.Wipe()
	for round := 0; ; round++ {
		if round >= maxEAPRounds {
			return fmt.Errorf("session: EAP did not converge within %d rounds", maxEAPRounds)
		}
		if eapReq.Code == eap.CodeSuccess {
			// Gate on mutual auth: if we ran an MSCHAPv2 challenge (MSK inputs are
			// present) the server MUST have sent a verified MSCHAPv2-Success first.
			// A server that skips it and jumps to an outer EAP-Success would
			// otherwise let us derive an MSK and finish IKE_AUTH without ever
			// proving it knows the password (RFC draft-kamath §2 / RFC 2759 §8).
			if phh, ntResp := mschap.MSKInputs(); len(phh) > 0 && len(ntResp) > 0 && !mschap.Verified() {
				return errors.New("session: server sent EAP-Success without verifying MSCHAPv2 AuthenticatorResponse")
			}
			break
		}
		if eapReq.Code == eap.CodeFailure {
			return errors.New("session: EAP authentication failed (server sent EAP-Failure)")
		}
		eapResp, err := buildEAPResponse(mschap, eapReq)
		if err != nil {
			return err
		}
		inner := ikemsg.Payloads{&ikemsg.EAPPayload{Data: eapResp.Marshal()}}

		resp, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, inner)
		if err != nil {
			return fmt.Errorf("session: IKE_AUTH EAP exchange: %w", err)
		}
		s.messageID++
		// Surface a responder error notify (e.g. AUTHENTICATION_FAILED) instead of
		// masking it as the generic "expected EAP payload" error below.
		if err := firstNotifyError(resp); err != nil {
			return err
		}
		next, ok, err := firstEAP(resp)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("session: expected EAP payload in IKE_AUTH response")
		}
		eapReq = next
	}

	// --- EAP done: derive MSK and send the initiator AUTH. ---
	// The MSK stays local: after the AUTH exchange below nothing needs it
	// (IKE rekeys are keyed by SK_d), so it is dropped — and, with
	// runtime/secret active, erased — when this function returns.
	phh, ntResp := mschap.MSKInputs()
	msk, err := eap.DeriveMSK(phh, ntResp)
	if err != nil {
		return fmt.Errorf("session: derive MSK: %w", err)
	}

	initiatorAuth := s.computeInitiatorAuth(msk)
	authPayloads := ikemsg.Payloads{&ikemsg.AuthPayload{Method: auth.MethodSharedKeyMIC, Data: initiatorAuth}}

	finalResp, err := s.exchangeSK(ctx, ikemsg.ExchangeIKEAuth, s.messageID, authPayloads)
	if err != nil {
		return fmt.Errorf("session: IKE_AUTH final: %w", err)
	}
	s.messageID++

	return s.handleFinalAuthResponse(finalResp, msk)
}

// handleAuthResponse processes message 4: cert chain, responder cert AUTH, and
// extracts the first EAP request.
func (s *Session) handleAuthResponse(payloads ikemsg.Payloads) (eap.Packet, error) {
	var (
		idr      *ikemsg.IDrPayload
		authP    *ikemsg.AuthPayload
		certsDER [][]byte
	)
	for _, p := range payloads {
		switch v := p.(type) {
		case *ikemsg.IDrPayload:
			idr = v
		case *ikemsg.CertPayload:
			certsDER = append(certsDER, v.Data)
		case *ikemsg.AuthPayload:
			authP = v
		case *ikemsg.NotifyPayload:
			if err := notifyError(v); err != nil {
				return eap.Packet{}, err
			}
		}
	}
	if idr == nil {
		return eap.Packet{}, errors.New("session: IKE_AUTH response missing IDr")
	}
	s.remoteIDr = WireID{Type: uint8(idr.IDType), Data: append([]byte(nil), idr.Data...)}

	// Verify the certificate chain and bind it to the exchange via the cert AUTH.
	if s.cfg.FortinetSAML {
		if authP == nil || authP.Method != auth.MethodSharedKeyMIC || len(s.cfg.ServerPSK) == 0 {
			return eap.Packet{}, errors.New("session: Fortinet responder PSK authentication missing")
		}
		if s.cfg.RemoteID.Type != 0 && (s.cfg.RemoteID.Type != uint8(idr.IDType) || !constTimeEqual(s.cfg.RemoteID.Data, idr.Data)) {
			return eap.Packet{}, errors.New("session: Fortinet responder identity mismatch")
		}
		signed := s.responderSignedOctets(ikemsg.MarshalIDBody(idr.IDType, idr.Data))
		if !constTimeEqual(authP.Data, auth.SharedSecretAuth(s.ikeSA.PRF, s.cfg.ServerPSK, signed)) {
			return eap.Packet{}, errors.New("session: Fortinet responder PSK authentication failed")
		}
		eapReq, ok, err := firstEAP(payloads)
		if err != nil {
			return eap.Packet{}, err
		}
		if !ok {
			return eap.Packet{}, errors.New("session: Fortinet EAP request missing")
		}
		return eapReq, nil
	}
	leaf, err := auth.VerifyServerChain(certsDER, s.cfg.RootCAs, s.peerName(), time.Now())
	if err != nil {
		return eap.Packet{}, err
	}
	if authP == nil {
		return eap.Packet{}, errors.New("session: IKE_AUTH response missing responder AUTH")
	}
	respSigned := s.responderSignedOctets(ikemsg.MarshalIDBody(idr.IDType, idr.Data))
	if err := auth.VerifyCertAuth(authP.Method, authP.Data, respSigned, leaf); err != nil {
		return eap.Packet{}, fmt.Errorf("session: responder certificate AUTH invalid: %w", err)
	}

	eapReq, ok, err := firstEAP(payloads)
	if err != nil {
		return eap.Packet{}, err
	}
	if !ok {
		return eap.Packet{}, errors.New("session: IKE_AUTH response missing EAP payload")
	}
	return eapReq, nil
}

// handleFinalAuthResponse verifies the responder's shared-secret AUTH (keyed by
// the EAP MSK or the PSK) and installs the Child SA + assigned configuration. The
// EAP path already captured the responder's IDr from message 4; the PSK path
// carries IDr in this single response, so it is captured here when present.
func (s *Session) handleFinalAuthResponse(payloads ikemsg.Payloads, secret []byte) error {
	var (
		idr      *ikemsg.IDrPayload
		authP    *ikemsg.AuthPayload
		saP      *ikemsg.SAPayload
		cp       *ikemsg.ConfigPayload
		tsi, tsr []ikemsg.TrafficSelector
	)
	for _, p := range payloads {
		switch v := p.(type) {
		case *ikemsg.IDrPayload:
			idr = v
		case *ikemsg.AuthPayload:
			authP = v
		case *ikemsg.SAPayload:
			saP = v
		case *ikemsg.KEPayload:
			return errors.New("session: final IKE_AUTH cannot include a key exchange")
		case *ikemsg.ConfigPayload:
			cp = v
		case *ikemsg.TSiPayload:
			tsi = v.Selectors
		case *ikemsg.TSrPayload:
			tsr = v.Selectors
		case *ikemsg.NotifyPayload:
			if err := notifyError(v); err != nil {
				return err
			}
		}
	}
	if authP == nil {
		return errors.New("session: final IKE_AUTH missing responder AUTH")
	}
	// EAP set s.remoteIDr from message 4; PSK carries IDr in this response.
	if idr != nil {
		if s.cfg.FortinetSAML && (s.remoteIDr.Type != uint8(idr.IDType) || !constTimeEqual(s.remoteIDr.Data, idr.Data)) {
			return errors.New("session: Fortinet responder identity changed during authentication")
		}
		s.remoteIDr = WireID{Type: uint8(idr.IDType), Data: append([]byte(nil), idr.Data...)}
	}
	if s.remoteIDr.Type == 0 && len(s.remoteIDr.Data) == 0 {
		return errors.New("session: IKE_AUTH response missing IDr")
	}
	// Verify the responder's shared-secret AUTH over the responder signed octets.
	respSigned := s.responderSignedOctets(ikemsg.MarshalIDBody(ikemsg.IDType(s.remoteIDr.Type), s.remoteIDr.Data))
	if s.cfg.ClientCertificate != nil {
		var certs [][]byte
		for _, p := range payloads {
			if cert, ok := p.(*ikemsg.CertPayload); ok {
				certs = append(certs, cert.Data)
			}
		}
		leaf, err := auth.VerifyServerChain(certs, s.cfg.RootCAs, s.peerName(), time.Now())
		if err != nil {
			return err
		}
		if err := auth.VerifyCertAuth(authP.Method, authP.Data, respSigned, leaf); err != nil {
			return errors.New("session: responder certificate AUTH failed")
		}
	} else {
		want := auth.SharedSecretAuth(s.ikeSA.PRF, secret, respSigned)
		if authP.Method != auth.MethodSharedKeyMIC || !constTimeEqual(authP.Data, want) {
			return errors.New("session: responder AUTH verification failed")
		}
	}

	if saP == nil || len(saP.Proposals) == 0 {
		return errors.New("session: final IKE_AUTH missing the responder's ESP proposal")
	}
	prop := saP.Proposals[0]
	for _, dh := range prop.ByType(ikemsg.TransformDH) {
		if dh.ID != 0 {
			return errors.New("session: initial Child SA cannot select a DH group")
		}
	}
	suite, ok := selectedSuite(prop, s.enabledESPSuites())
	if !ok {
		return fmt.Errorf("session: responder selected an unsupported or ambiguous ESP proposal (%s)", describeProposals(saP))
	}
	if len(prop.SPI) != 4 {
		return fmt.Errorf("session: responder selected an ESP proposal with invalid SPI length %d (%s)", len(prop.SPI), describeProposals(saP))
	}
	// The responder MAY narrow our full-tunnel selectors (RFC 7296 §2.9). We only
	// route full-tunnel, so a narrowed selector means traffic outside it is dropped
	// by the gateway with no other client-side signal — surface it.
	s.warnNarrowedTS("IKE_AUTH", tsi, tsr)
	s.child = &ChildSA{
		InitiatorSPI: s.childInitiatorSPI,
		ResponderSPI: binary.BigEndian.Uint32(prop.SPI),
		Suite:        suite.id,
		Keys:         s.ikeSA.DeriveChildKeys(s.nonceI, s.nonceR, suite.encrKeyLen, suite.integKeyLen),
	}
	if cp != nil {
		s.assigned = parseCPReply(cp)
	}
	s.established = true
	s.log.Info("IKE_AUTH established",
		"assignedIP", s.assigned.IP,
		"espSuite", suite.name(),
		"childSPIout", fmt.Sprintf("%08x", s.child.ResponderSPI))
	return nil
}

// computeInitiatorAuth builds the initiator's shared-secret AUTH value over its
// signed octets, keyed by the PSK or the EAP-derived MSK.
func (s *Session) computeInitiatorAuth(secret []byte) []byte {
	signed := s.initiatorSignedOctets()
	return auth.SharedSecretAuth(s.ikeSA.PRF, secret, signed)
}

// initiatorSignedOctets = RealMessage1 | Nr | prf(SK_pi, IDi').
func (s *Session) initiatorSignedOctets() []byte {
	idi := ikemsg.MarshalIDBody(ikemsg.IDType(s.cfg.LocalID.Type), s.cfg.LocalID.Data)
	return auth.SignedOctets(s.ikeSA.PRF, s.initSAInitReq, s.nonceR, idi, s.ikeSA.SKpi)
}

// responderSignedOctets = RealMessage2 | Ni | prf(SK_pr, IDr').
func (s *Session) responderSignedOctets(idrPrime []byte) []byte {
	return auth.SignedOctets(s.ikeSA.PRF, s.initSAInitRsp, s.nonceI, idrPrime, s.ikeSA.SKpr)
}

// peerName derives the certificate-matching name from the configured RemoteID.
// An unset RemoteID disables name matching (chain trust only); a RemoteID that
// is set but of an unsupported type is marked Unverifiable so matchName fails
// closed instead of silently trusting the chain alone.
func (s *Session) peerName() auth.PeerName {
	switch s.cfg.RemoteID.Type {
	case uint8(ikemsg.IDTypeFQDN):
		return auth.PeerName{DNS: string(s.cfg.RemoteID.Data)}
	case uint8(ikemsg.IDTypeRFC822):
		return auth.PeerName{Email: string(s.cfg.RemoteID.Data)}
	case uint8(ikemsg.IDTypeIPv4), uint8(ikemsg.IDTypeIPv6):
		if a, ok := netip.AddrFromSlice(s.cfg.RemoteID.Data); ok {
			return auth.PeerName{IP: a}
		}
	case uint8(ikemsg.IDTypeDERASN1DN):
		return auth.PeerName{DN: append([]byte(nil), s.cfg.RemoteID.Data...)}
	}
	// No RemoteID configured → chain trust only. A configured-but-unsupported
	// RemoteID must not silently downgrade to that, so flag it.
	if s.cfg.RemoteID.Type != 0 || len(s.cfg.RemoteID.Data) != 0 {
		return auth.PeerName{Unverifiable: true}
	}
	return auth.PeerName{}
}

// exchangeSK encodes, sends (with retransmit) an SK{} request and returns the
// decoded inner payloads of the matching response.
func (s *Session) exchangeSK(ctx context.Context, exchangeType ikemsg.ExchangeType, msgID uint32, inner ikemsg.Payloads) (ikemsg.Payloads, error) {
	reqBytes, err := s.encodeSK(exchangeType, ikeRoleBit(s.ikeSA.Role), msgID, inner)
	if err != nil {
		return nil, err
	}
	rawResp, err := s.exchange(ctx, reqBytes, msgID)
	if err != nil {
		return nil, err
	}
	_, payloads, err := s.decodeSK(rawResp)
	if err != nil {
		return nil, err
	}
	return payloads, nil
}

// exchange sends a request and waits for the response with the expected message
// ID, retransmitting with exponential backoff on timeout.
func (s *Session) exchange(ctx context.Context, reqBytes []byte, expectMsgID uint32) ([]byte, error) {
	backoff := s.retransmitBase()
	for attempt := 0; attempt < s.retransmitTries(); attempt++ {
		if err := s.sendDatagram(ctx, reqBytes); err != nil {
			return nil, err
		}
		deadlineCtx, cancel := context.WithTimeout(ctx, backoff)
		raw, err := s.recvMatching(deadlineCtx, expectMsgID)
		cancel()
		if err == nil {
			return raw, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		backoff = minDuration(backoff*2, s.retransmitMax())
	}
	return nil, fmt.Errorf("session: no response after %d retransmits", s.retransmitTries())
}

// recvMatching receives datagrams until one decodes with the expected message
// ID (dropping stale retransmits) or the context fires.
func (s *Session) recvMatching(ctx context.Context, expectMsgID uint32) ([]byte, error) {
	for {
		raw, err := s.recvDatagram(ctx)
		if err != nil {
			return nil, err
		}
		hdr, err := ikemsg.Parse(raw)
		if err != nil {
			s.log.Debug("dropping undecodable datagram", "err", err)
			continue
		}
		if hdr.MessageID != expectMsgID {
			s.log.Debug("dropping out-of-window message", "got", hdr.MessageID, "want", expectMsgID)
			continue
		}
		if !hdr.Flags.IsResponse() {
			// A server-originated request that happens to carry the awaited Message ID
			// is not the response we are waiting for; drop it rather than feed a request
			// into the response handler.
			s.log.Debug("dropping request with matching message ID", "id", hdr.MessageID)
			continue
		}
		return append([]byte(nil), raw...), nil
	}
}

// --- payload helpers ---

// appendTrafficSelectors adds full-tunnel TSi and TSr (0.0.0.0/0, all ports,
// all protocols). When includeV6 is set it also offers the IPv6 full range
// (::/0) so the responder can narrow ESP to carry inner IPv6.
func appendTrafficSelectors(c *ikemsg.Payloads, includeV6 bool) {
	full := []ikemsg.TrafficSelector{{
		TSType:    ikemsg.TSIPv4AddrRange,
		StartPort: 0,
		EndPort:   65535,
		StartAddr: []byte{0, 0, 0, 0},
		EndAddr:   []byte{255, 255, 255, 255},
	}}
	if includeV6 {
		full = append(full, ikemsg.TrafficSelector{
			TSType:    ikemsg.TSIPv6AddrRange,
			StartPort: 0,
			EndPort:   65535,
			StartAddr: make([]byte, 16),               // ::
			EndAddr:   bytes.Repeat([]byte{0xff}, 16), // ::ffff:...:ffff (all-ones)
		})
	}
	*c = append(*c,
		&ikemsg.TSiPayload{Selectors: append([]ikemsg.TrafficSelector(nil), full...)},
		&ikemsg.TSrPayload{Selectors: append([]ikemsg.TrafficSelector(nil), full...)},
	)
}

// selectorIsFullRange reports whether ts covers the entire address space for its
// family, all ports and all protocols — the full-tunnel selector this client
// offers in appendTrafficSelectors.
func selectorIsFullRange(ts ikemsg.TrafficSelector) bool {
	if ts.Protocol != 0 || ts.StartPort != 0 || ts.EndPort != 65535 {
		return false
	}
	switch ts.TSType {
	case ikemsg.TSIPv4AddrRange:
		return bytes.Equal(ts.StartAddr, []byte{0, 0, 0, 0}) &&
			bytes.Equal(ts.EndAddr, []byte{255, 255, 255, 255})
	case ikemsg.TSIPv6AddrRange:
		return bytes.Equal(ts.StartAddr, make([]byte, 16)) &&
			bytes.Equal(ts.EndAddr, bytes.Repeat([]byte{0xff}, 16))
	default:
		return false
	}
}

// warnNarrowedTS logs when the responder narrowed the DESTINATION traffic
// selectors (TSr) below the full-tunnel range we offered. We route full-tunnel, so
// a narrowed TSr means packets to addresses outside it are silently dropped by the
// gateway — this Warn is the only client-side diagnostic for that. TSi is NOT
// checked: a gateway legitimately narrows TSi to our assigned inner address (our
// traffic's only valid source), so warning on it would fire on every normal
// handshake.
func (s *Session) warnNarrowedTS(phase string, tsi, tsr []ikemsg.TrafficSelector) {
	narrowed := func(sels []ikemsg.TrafficSelector) bool {
		for _, ts := range sels {
			if !selectorIsFullRange(ts) {
				return true
			}
		}
		return false
	}
	if narrowed(tsr) {
		s.log.Warn("responder narrowed the destination traffic selectors (TSr) below the offered full-tunnel range; traffic outside them will be dropped",
			"phase", phase, "tsi", describeSelectors(tsi), "tsr", describeSelectors(tsr))
	}
}

// describeSelectors renders traffic selectors for a diagnostic log line.
func describeSelectors(sels []ikemsg.TrafficSelector) string {
	if len(sels) == 0 {
		return "(none)"
	}
	var b bytes.Buffer
	for i, ts := range sels {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "type=%d %x-%x proto=%d ports=%d-%d",
			ts.TSType, ts.StartAddr, ts.EndAddr, ts.Protocol, ts.StartPort, ts.EndPort)
	}
	return b.String()
}

// buildCPRequest adds a CFG_REQUEST asking for an internal address, netmask and
// DNS. When requestIPv6 is set it additionally requests an internal IPv6 address
// and IPv6 DNS (empty values, same as the v4 attributes).
func buildCPRequest(c *ikemsg.Payloads, requestIPv6 bool) {
	attrs := []ikemsg.ConfigAttr{
		{Type: ikemsg.ConfigAttrInternalIP4Address},
		{Type: ikemsg.ConfigAttrInternalIP4Netmask},
		{Type: ikemsg.ConfigAttrInternalIP4DNS},
	}
	if requestIPv6 {
		attrs = append(attrs,
			ikemsg.ConfigAttr{Type: ikemsg.ConfigAttrInternalIP6Address},
			ikemsg.ConfigAttr{Type: ikemsg.ConfigAttrInternalIP6DNS},
		)
	}
	*c = append(*c, &ikemsg.ConfigPayload{
		CfgType:    ikemsg.ConfigRequest,
		Attributes: attrs,
	})
}

// parseCPReply extracts the assigned IPv4/IPv6 addresses, netmask and DNS
// servers. IPv6 attributes are parsed unconditionally — they are harmless when
// absent — and gated downstream on whether an IPv6 address was actually assigned.
func parseCPReply(cp *ikemsg.ConfigPayload) Assigned {
	var a Assigned
	for _, attr := range cp.Attributes {
		switch attr.Type {
		case ikemsg.ConfigAttrInternalIP4Address:
			if v, ok := netip.AddrFromSlice(attr.Value); ok && len(attr.Value) == 4 {
				a.IP = v
			}
		case ikemsg.ConfigAttrInternalIP4Netmask:
			if v, ok := netip.AddrFromSlice(attr.Value); ok && len(attr.Value) == 4 {
				a.Netmask = v
			}
		case ikemsg.ConfigAttrInternalIP4DNS:
			if v, ok := netip.AddrFromSlice(attr.Value); ok && len(attr.Value) == 4 {
				a.DNS = append(a.DNS, v)
			}
		case ikemsg.ConfigAttrInternalIP6Address:
			// INTERNAL_IP6_ADDRESS is a 16-byte address plus a 1-byte prefix length
			// (RFC 7296 §3.15.1); some servers omit the prefix byte, for which /64 is
			// the sensible default.
			if v, ok := netip.AddrFromSlice(addr16(attr.Value)); ok {
				plen := 64
				if len(attr.Value) == 17 {
					plen = int(attr.Value[16])
				}
				if plen <= 128 {
					a.IP6 = netip.PrefixFrom(v, plen)
				}
			}
		case ikemsg.ConfigAttrInternalIP6DNS:
			if v, ok := netip.AddrFromSlice(attr.Value); ok && len(attr.Value) == 16 {
				a.DNS6 = append(a.DNS6, v)
			}
		}
	}
	return a
}

// addr16 returns the leading 16 address bytes of an INTERNAL_IP6_ADDRESS value
// (17-byte addr+prefix or a bare 16-byte addr), or nil for any other length so
// netip.AddrFromSlice fails closed.
func addr16(value []byte) []byte {
	switch len(value) {
	case 16, 17:
		return value[:16]
	default:
		return nil
	}
}

// buildEAPResponse maps an inbound EAP request to the response to send.
func buildEAPResponse(m *eap.MSCHAPv2, req eap.Packet) (eap.Packet, error) {
	switch req.Type {
	case eap.TypeIdentity:
		return m.IdentityResponse(req), nil
	case eap.TypeMSCHAPv2:
		if len(req.Data) == 0 {
			return eap.Packet{}, errors.New("session: empty MSCHAPv2 request")
		}
		switch req.Data[0] {
		case 1: // Challenge
			return m.HandleChallenge(req)
		case 3: // Success
			return m.HandleSuccess(req)
		case 4: // Failure
			return eap.Packet{}, errors.New("session: server reported MSCHAPv2 failure")
		default:
			return eap.Packet{}, fmt.Errorf("session: unexpected MSCHAPv2 opcode %d", req.Data[0])
		}
	case eap.TypeNotification:
		// RFC 3748 §5.2: a Notification request carries a displayable message and
		// MUST be acknowledged with an empty EAP-Response/Notification (matching
		// Identifier) so the conversation continues, rather than aborting it.
		return eap.Packet{Code: eap.CodeResponse, Identifier: req.Identifier, Type: eap.TypeNotification}, nil
	default:
		return eap.Packet{}, fmt.Errorf("session: unsupported EAP request type %d", req.Type)
	}
}

// notifyError returns an error for IKE error-class notify types.
func notifyError(n *ikemsg.NotifyPayload) error {
	if n.Type.IsError() {
		return fmt.Errorf("session: responder error notify %d", n.Type)
	}
	return nil
}

// firstNotifyError returns the first error-class notify in payloads, or nil.
func firstNotifyError(payloads ikemsg.Payloads) error {
	for _, p := range payloads {
		if n, ok := p.(*ikemsg.NotifyPayload); ok {
			if err := notifyError(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func constTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (s *Session) retransmitBase() time.Duration {
	if s.cfg.RetransmitBase > 0 {
		return s.cfg.RetransmitBase
	}
	return 2 * time.Second
}

func (s *Session) retransmitMax() time.Duration {
	if s.cfg.RetransmitMax > 0 {
		return s.cfg.RetransmitMax
	}
	return 30 * time.Second
}

func (s *Session) retransmitTries() int {
	if s.cfg.RetransmitTries > 0 {
		return s.cfg.RetransmitTries
	}
	return 5
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
