// Package session drives the IKEv2 initiator state machine: IKE_SA_INIT,
// IKE_AUTH (EAP-MSCHAPv2 or PSK), Child SA install, and the INFORMATIONAL lifecycle
// (DPD, rekey, DELETE). It owns all IKE SA state on a single goroutine; the
// data plane (ESP) runs alongside but is keyed from material this package
// derives.
package session

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/ikesa"
	"github.com/n0madic/go-ipsec/internal/secretmem"
	"github.com/n0madic/go-ipsec/internal/transport"
)

// nonceLen is the length of the nonces we generate (RFC 7296 requires 16..256
// bytes and at least half the PRF key size; 32 is comfortably valid for SHA2-256).
const nonceLen = 32

// WireID is an IKE identity in wire form (type byte + data), decoupled from the
// public ipsec.Identity to keep this package free of the root import.
type WireID struct {
	Type uint8
	Data []byte
}

// Config is the internal session configuration translated from ipsec.Config.
// EAPPass and PSK are bytes, not strings: the session owns these copies
// (toSessionConfig allocates them fresh, inside secretmem.Do) and wipes them
// on Close — a string would be unwipeable for the process lifetime.
type Config struct {
	FortinetSAML bool
	ServerPSK    []byte
	Server       string
	LocalID      WireID
	RemoteID     WireID
	EAPUser      string
	EAPPass      []byte
	PSK          []byte
	RootCAs      *x509.CertPool
	Dialer       transport.DialFunc
	MTU          uint32
	Logger       *slog.Logger

	KeepAlive        time.Duration
	DPDTimeout       time.Duration
	RekeyLifetime    time.Duration
	IKERekeyLifetime time.Duration
	ReplayWindow     uint32
	RekeyMaxPackets  uint32
	ChildSAPFS       bool

	// ESPSuites restricts and orders the ESP suites offered for Child SAs, in
	// preference order. nil/empty offers the full built-in table. Resolved from
	// ipsec.Config.ESPCipherSuites (which validates the values).
	ESPSuites []esp.Suite

	// IKESuites restricts and orders the IKE SA (SK{} envelope) suites offered
	// at IKE_SA_INIT and on IKE SA rekeys, in preference order. nil/empty
	// offers the full built-in table. Resolved from ipsec.Config.IKECipherSuites
	// (which validates the values).
	IKESuites []ikesa.Suite

	// RequestIPv6 asks the responder for an inner IPv6 address (CFG) and offers
	// IPv6 traffic selectors. Resolved from ipsec.Config.RequestIPv6; a v4-only
	// responder simply does not assign one and behaviour is unchanged.
	RequestIPv6 bool

	RetransmitBase  time.Duration
	RetransmitMax   time.Duration
	RetransmitTries int
}

// Session is one IKE SA and its first Child SA.
type Session struct {
	cfg Config
	log *slog.Logger

	conn transport.Conn

	// IKE SA identifiers and crypto state.
	initiatorSPI uint64
	responderSPI uint64
	ikeSA        *ikesa.IKESA

	// Ephemeral IKE_SA_INIT material.
	dh        *ikesa.DH
	nonceI    []byte
	nonceR    []byte
	peerDHPub []byte

	// Verbatim transmitted/received IKE_SA_INIT datagrams, kept byte-exact for
	// the AUTH signed-octets computation (RFC 7296 §2.15). Never re-encoded.
	initSAInitReq []byte
	initSAInitRsp []byte

	// messageID is the next initiator-originated exchange ID.
	messageID uint32

	// IKE_AUTH / Child SA state.
	childInitiatorSPI uint32
	remoteIDr         WireID
	child             *ChildSA
	assigned          Assigned
	established       bool

	// NAT-T state.
	nattMode    bool // IKE framed with the non-ESP marker on :4500
	natDetected bool

	// Rekey / driver state (touched only by the driver goroutine after the
	// handshake completes).
	dataPlane        DataPlane
	pending          *pendingExchange // at most one outstanding initiator request (window=1)
	lastInbound      time.Time
	lastTickWall     time.Time // wall-clock of the previous housekeeping tick, for suspend/wake detection
	fastDPDDue       bool      // a post-suspend fast DPD is armed, pending a free request window
	childInstalledAt time.Time
	ikeInstalledAt   time.Time
	nextChildRekey   time.Time
	nextIKERekey     time.Time
	nextVolumeRekey  time.Time // earliest next volume-based Child rekey (backoff)
	oldIKE           *ikeCtx   // superseded IKE SA kept briefly for grace decode
	oldIKEUntil      time.Time // grace deadline for oldIKE

	// childReestablish is set when the peer DELETEs the live Child SA but a fresh
	// CREATE_CHILD_SA could not be started immediately — either an exchange was
	// already outstanding (window size 1) or the initiation errored. housekeeping
	// retries it once the window frees, clearing the flag only on a successful
	// initiation and throttling retries via nextChildReestablish.
	childReestablish     bool
	nextChildReestablish time.Time // earliest next re-establishment retry (backoff)

	// childPFS enables per-Child Diffie-Hellman (PFS) on Child SA rekeys this client
	// originates. It is seeded from Config.ChildSAPFS and additionally learned: once
	// we answer a server-initiated PFS rekey it latches true, so our own rekeys and
	// re-establishments also offer PFS and a PFS-requiring peer accepts them. A
	// server-initiated PFS rekey is always honored regardless.
	childPFS bool

	// ikeDHGroup is the DH group negotiated for the IKE SA at IKE_SA_INIT (x25519
	// or MODP-2048). IKE-SA rekeys reuse it, and Child rekeys default to it until a
	// server PFS rekey teaches a specific group.
	ikeDHGroup uint16

	// childPFSGroup is the DH group learned from a server-initiated Child PFS rekey
	// (0 until one is answered). When set it overrides ikeDHGroup for the PFS group
	// our own Child rekeys offer, so we mirror the group the server requires.
	childPFSGroup uint16

	// Responder-side retransmit handling for server-initiated exchanges. IKEv2
	// requires a responder to cache its response and resend it on a duplicate
	// request rather than reprocessing — reprocessing re-derives keys and
	// re-swaps SAs, corrupting state. peer tracks the current SA; oldPeer is
	// migrated on IKE rekey so a retransmit of the rekey request (which arrives
	// under the old SA during the grace window) resends the cached response.
	peer    peerDedup
	oldPeer peerDedup

	// oldIKEDelete is the INFORMATIONAL{Delete(IKE)} sent for a superseded IKE
	// SA after an initiator IKE rekey, retransmitted under the old SA during the
	// grace window until acked (a lost DELETE would otherwise leak the old SA).
	oldIKEDelete *pendingExchange
}

// peerDedup caches the last response sent to a server-initiated request so a
// retransmit can be answered without reprocessing.
type peerDedup struct {
	msgID uint32
	set   bool
	resp  []byte
}

// New constructs a session from its translated config.
func New(cfg Config) *Session {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Session{cfg: cfg, log: log, childPFS: cfg.ChildSAPFS}
}

// dialDefault is the network used for the underlying socket.
const network = "udp"

// IKESAInit performs the IKE_SA_INIT exchange and derives the IKE SA keys. It
// is the first step of Dial; subsequent steps (IKE_AUTH) reuse the derived
// state and the stored verbatim datagrams.
func (s *Session) IKESAInit(ctx context.Context) error {
	if err := s.checkConfiguredSuites(); err != nil {
		return err
	}
	if s.conn == nil {
		conn, err := transport.DialUDP(ctx, s.cfg.Dialer, network, withDefaultPort(s.cfg.Server))
		if err != nil {
			return err
		}
		s.conn = conn
	}

	var err error
	if s.initiatorSPI, err = randUint64(); err != nil {
		return err
	}
	// Prefer x25519 (group 31); switch to another supported group if the
	// responder requests it via INVALID_KE_PAYLOAD below.
	if s.dh, err = ikesa.NewDH(ikemsg.DH_X25519); err != nil {
		return err
	}
	if s.nonceI, err = randBytes(nonceLen); err != nil {
		return err
	}

	rspBytes, err := s.sendSAInit(ctx, nil)
	if err != nil {
		return err
	}
	// RFC 7296 §2.6: a COOKIE notify asks us to retry once with the cookie
	// echoed back as the first payload (DoS protection). The SPI, nonce and DH
	// value are reused; only the cookie is added.
	var cookie []byte
	if c, ok := saInitCookie(rspBytes); ok {
		cookie = c
		s.log.Debug("IKE_SA_INIT COOKIE challenge, retrying")
		if rspBytes, err = s.sendSAInit(ctx, cookie); err != nil {
			return err
		}
	}
	// RFC 7296 §1.2 / §3.10.1: the responder may require a different DH group than
	// our KEi and answer with N(INVALID_KE_PAYLOAD) carrying the group it wants.
	// Retry once with the requested supported group. Re-echo the cookie if the
	// responder is still challenging.
	if g, ok := saInitInvalidKE(rspBytes); ok {
		if !supportedDHGroup(g) || g == s.dh.Group {
			return fmt.Errorf("session: responder requires DH group %d (INVALID_KE_PAYLOAD); no mutually-supported DH group", g)
		}
		s.log.Debug("IKE_SA_INIT INVALID_KE_PAYLOAD, retrying with the responder's DH group", "group", g)
		if s.dh, err = ikesa.NewDH(g); err != nil {
			return err
		}
		if rspBytes, err = s.sendSAInit(ctx, cookie); err != nil {
			return err
		}
		// The responder may begin demanding a cookie only on this group-changed
		// retry (RFC 7296 §2.6: a responder may cross its cookie threshold between
		// our two requests). Echo it once more, or the cookie notify falls through
		// to handleSAInitResponse as a bare SA/KE/Nonce-less message.
		if c, ok := saInitCookie(rspBytes); ok {
			s.log.Debug("IKE_SA_INIT COOKIE challenge after INVALID_KE retry, retrying")
			if _, err = s.sendSAInit(ctx, c); err != nil {
				return err
			}
		}
	}

	if err := s.handleSAInitResponse(s.initSAInitRsp); err != nil {
		return err
	}
	s.migrateNATT()
	s.messageID = 1 // IKE_AUTH is message ID 1
	return nil
}

// sendSAInit builds and sends an IKE_SA_INIT request (optionally carrying a
// COOKIE notify), stores the verbatim request/response for the AUTH signed
// octets, and returns the response datagram. IKE_SA_INIT is message ID 0 and,
// like every later exchange, retransmits with backoff on loss (UDP) via
// exchange() rather than failing the whole Dial on a single dropped datagram.
func (s *Session) sendSAInit(ctx context.Context, cookie []byte) ([]byte, error) {
	_, reqBytes, err := s.buildSAInit(cookie)
	if err != nil {
		return nil, err
	}
	s.initSAInitReq = reqBytes
	// exchange() returns a fresh copy (transport.Recv only lends its buffer until
	// the next Recv), so the stored response stays valid for the AUTH octets.
	rspBytes, err := s.exchange(ctx, reqBytes, 0)
	if err != nil {
		return nil, fmt.Errorf("session: IKE_SA_INIT exchange: %w", err)
	}
	s.initSAInitRsp = rspBytes
	return s.initSAInitRsp, nil
}

// saInitCookie returns the COOKIE notify data from an IKE_SA_INIT response, if
// the responder issued a cookie challenge.
func saInitCookie(raw []byte) ([]byte, bool) {
	m, err := ikemsg.Parse(raw)
	if err != nil {
		return nil, false
	}
	for _, p := range m.Payloads {
		if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyCookie {
			// RFC 7296 §2.6: cookie data MUST be 1..64 octets. Rejecting an
			// out-of-range cookie (rather than echoing an attacker-sized blob
			// back) also keeps the retry request comfortably below the marshal
			// layer's uint16 length fields.
			if len(n.Data) == 0 || len(n.Data) > 64 {
				return nil, false
			}
			return n.Data, true
		}
	}
	return nil, false
}

// buildSAInit assembles the IKE_SA_INIT request and returns the message and its
// exact encoded bytes. A non-empty cookie is prepended as the first payload
// (RFC 7296 §2.6).
func (s *Session) buildSAInit(cookie []byte) (*ikemsg.Message, []byte, error) {
	m := &ikemsg.Message{
		InitiatorSPI: s.initiatorSPI,
		Exchange:     ikemsg.ExchangeIKESAInit,
		Flags:        ikemsg.FlagInitiator,
	}

	if len(cookie) > 0 {
		m.Payloads = append(m.Payloads, &ikemsg.NotifyPayload{Type: ikemsg.NotifyCookie, Data: cookie})
	}
	// Offer one proposal per enabled IKE suite, each advertising all supported
	// DH groups. The KE carries our current group, which the INVALID_KE_PAYLOAD
	// retry may switch.
	m.Payloads = append(m.Payloads,
		&ikemsg.SAPayload{Proposals: buildProposals(nil, s.enabledIKESuites(), preferredDHGroups...)},
		&ikemsg.KEPayload{Group: s.dh.Group, Data: s.dh.Public},
		&ikemsg.NoncePayload{Data: s.nonceI},
	)
	s.appendNATDetection(&m.Payloads)

	raw, err := m.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("session: encode IKE_SA_INIT: %w", err)
	}
	return m, raw, nil
}

// handleSAInitResponse validates the responder's IKE_SA_INIT and derives keys.
func (s *Session) handleSAInitResponse(raw []byte) error {
	m, err := ikemsg.Parse(raw)
	if err != nil {
		return fmt.Errorf("session: decode IKE_SA_INIT response: %w", err)
	}
	if m.Exchange != ikemsg.ExchangeIKESAInit {
		return fmt.Errorf("session: unexpected exchange type %d in IKE_SA_INIT response", m.Exchange)
	}
	// Bind the datagram to our pending IKE_SA_INIT exchange (RFC 7296 §2.2/§3.1):
	// it must be a response, carry our initiator SPI, and be message ID 0. Without
	// these checks a stray, reordered, or spoofed SA_INIT-typed datagram on our
	// 4-tuple is consumed as the genuine response, deriving keys from the wrong
	// KE/Nonce and aborting the handshake.
	if !m.Flags.IsResponse() {
		return errors.New("session: IKE_SA_INIT datagram is a request, not the expected response")
	}
	if m.InitiatorSPI != s.initiatorSPI {
		return fmt.Errorf("session: IKE_SA_INIT response initiator SPI %016x does not match ours %016x", m.InitiatorSPI, s.initiatorSPI)
	}
	if m.MessageID != 0 {
		return fmt.Errorf("session: IKE_SA_INIT response message ID %d is not 0", m.MessageID)
	}
	if m.ResponderSPI == 0 {
		return errors.New("session: responder SPI is zero")
	}
	s.responderSPI = m.ResponderSPI

	var (
		gotSA, gotKE, gotNonce bool
		suite                  ikeSuite
		natNotifies            []*ikemsg.NotifyPayload
		notifyErr              error
	)
	for _, p := range m.Payloads {
		switch payload := p.(type) {
		case *ikemsg.SAPayload:
			// The response must be a strict narrowed SELECTION of one enabled
			// suite: the suite fixes the SKEYSEED split (RFC 5282 §7), so an
			// ambiguous echo or a suite we did not offer must be rejected.
			if len(payload.Proposals) == 0 {
				return errors.New("session: IKE_SA_INIT response carries no proposal")
			}
			var ok bool
			if suite, ok = selectedSuite(payload.Proposals[0], s.enabledIKESuites()); !ok {
				return fmt.Errorf("session: responder selected an unsupported or ambiguous IKE proposal (%s)", describeProposals(payload))
			}
			// The responder's narrowed proposal must carry the same DH group as our
			// KEi; a different group would mean it should have sent INVALID_KE_PAYLOAD
			// (handled before we get here) rather than a proposal we cannot key.
			if g := selectedDHGroup(payload.Proposals[0]); g != s.dh.Group {
				return fmt.Errorf("session: responder selected DH group %d but our KE is group %d", g, s.dh.Group)
			}
			gotSA = true
		case *ikemsg.KEPayload:
			s.peerDHPub = append([]byte(nil), payload.Data...)
			gotKE = true
		case *ikemsg.NoncePayload:
			s.nonceR = append([]byte(nil), payload.Data...)
			gotNonce = true
		case *ikemsg.NotifyPayload:
			if err := saInitNotifyError(payload); err != nil {
				notifyErr = err
			}
			if payload.Type == ikemsg.NotifyNATDetectionSourceIP ||
				payload.Type == ikemsg.NotifyNATDetectionDestinationIP {
				natNotifies = append(natNotifies, payload)
			}
		}
	}
	// Surface an explicit error notify (e.g. INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN)
	// instead of the misleading "missing SA/KE/Nonce" the absent payloads cause.
	if notifyErr != nil {
		return notifyErr
	}
	if !gotSA || !gotKE || !gotNonce {
		return errors.New("session: IKE_SA_INIT response missing SA/KE/Nonce")
	}
	s.processNATDetection(natNotifies)

	shared, err := s.dh.Shared(s.peerDHPub)
	if err != nil {
		return fmt.Errorf("session: DH: %w", err)
	}
	sa := &ikesa.IKESA{}
	if err := sa.Derive(suite.id, ikesa.Initiator, s.initiatorSPI, s.responderSPI, s.nonceI, s.nonceR, shared); err != nil {
		return fmt.Errorf("session: derive IKE keys: %w", err)
	}
	s.ikeSA = sa
	s.ikeDHGroup = s.dh.Group
	s.log.Debug("IKE_SA_INIT complete",
		"initiatorSPI", fmt.Sprintf("%016x", s.initiatorSPI),
		"responderSPI", fmt.Sprintf("%016x", s.responderSPI),
		"suite", suite.name())
	return nil
}

// saInitNotifyError maps an error-class IKE_SA_INIT notify to a descriptive
// error. COOKIE and INVALID_KE_PAYLOAD are handled by the retry paths, and
// NAT-detection notifies are processed separately, so all three return nil here
// (a residual INVALID_KE_PAYLOAD that survives the retry is surfaced by IKESAInit
// as "no mutually-supported DH group").
func saInitNotifyError(n *ikemsg.NotifyPayload) error {
	switch n.Type {
	case ikemsg.NotifyNoProposalChosen:
		return errors.New("session: responder rejected all IKE proposals (NO_PROPOSAL_CHOSEN)")
	case ikemsg.NotifyInvalidSyntax:
		return errors.New("session: responder reported INVALID_SYNTAX in IKE_SA_INIT")
	}
	return nil
}

// saInitInvalidKE returns the DH group the responder requested via an
// IKE_SA_INIT N(INVALID_KE_PAYLOAD), whose 2-byte data is the group number
// (RFC 7296 §3.10.1). The bool reports whether the notify was present; an
// INVALID_KE_PAYLOAD without a parseable group returns (0, true), which the
// caller treats as an unsupported group.
func saInitInvalidKE(raw []byte) (uint16, bool) {
	m, err := ikemsg.Parse(raw)
	if err != nil {
		return 0, false
	}
	for _, p := range m.Payloads {
		if n, ok := p.(*ikemsg.NotifyPayload); ok && n.Type == ikemsg.NotifyInvalidKEPayload {
			if len(n.Data) >= 2 {
				return binary.BigEndian.Uint16(n.Data[:2]), true
			}
			return 0, true
		}
	}
	return 0, false
}

// Close tears down the transport and wipes the session's credential copies
// (best-effort in the default build; with runtime/secret active they are also
// erased by the GC once dropped — see internal/secretmem).
func (s *Session) Close() error {
	secretmem.Wipe(s.cfg.PSK)
	secretmem.Wipe(s.cfg.ServerPSK)
	secretmem.Wipe(s.cfg.EAPPass)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// IKESA exposes the derived IKE SA (nil until IKESAInit succeeds).
func (s *Session) IKESA() *ikesa.IKESA { return s.ikeSA }

// Established reports whether IKE_AUTH completed and the Child SA is installed.
func (s *Session) Established() bool { return s.established }

// Assigned returns the layer-3 configuration pushed by the responder.
func (s *Session) Assigned() Assigned { return s.assigned }

// SetAssigned overrides the layer-3 configuration. It is a test seam for the
// root package, which cannot set the unexported field across the package
// boundary, to exercise the public DNS()/DNS6()/LocalIP6 accessors without a
// full handshake; production code fills s.assigned during IKE_AUTH.
func (s *Session) SetAssigned(a Assigned) { s.assigned = a }

// Child returns the installed Child SA (nil until IKE_AUTH completes).
func (s *Session) Child() *ChildSA { return s.child }

// NATTMode reports whether IKE/ESP run NAT-T framed on port 4500.
func (s *Session) NATTMode() bool { return s.nattMode }

// RecvRaw returns the next raw datagram from the socket (no NAT-T classification),
// for the data-plane rx demux which classifies IKE vs ESP itself.
func (s *Session) RecvRaw(ctx context.Context) ([]byte, error) { return s.conn.Recv(ctx) }

// SendESP transmits a raw ESP datagram to the peer (UDP-encapsulated on 4500,
// no non-ESP marker).
func (s *Session) SendESP(ctx context.Context, pkt []byte) error { return s.conn.Send(ctx, pkt) }

// SendKeepalive sends a NAT keepalive (a single 0xFF) to keep the mapping open.
func (s *Session) SendKeepalive(ctx context.Context) error {
	return s.conn.Send(ctx, []byte{0xFF})
}

// --- helpers ---

func randUint64() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// withDefaultPort appends the IKE port 500 when none is present.
func withDefaultPort(server string) string {
	for i := len(server) - 1; i >= 0; i-- {
		switch server[i] {
		case ':':
			return server
		case ']':
			i = -1 // IPv6 literal without port
		}
	}
	return server + ":500"
}
