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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// netstackDialer dials TCP through a gVisor stack that owns the client-side of the Fortinet
// PPP link. Outbound IPv4 packets are written into the channel endpoint; inbound packets
// from the gateway are injected by the PPP read loop in ppp.go.
//
// Hostname targets received over SOCKS5 are resolved using the VPN-provided DNS servers
// (carried by `dnsServers`). When the gateway does not push usable IPv4 DNS servers,
// hostname targets fail closed; IP literals still dial normally.
type netstackDialer struct {
	stack      *stack.Stack
	assignedIP netip.Addr
	dnsServers []netip.Addr // populated from session.DNS; empty means hostname lookup fails closed
}

func newNetstack(assignedIP netip.Addr, mtu int) (*stack.Stack, *channel.Endpoint, error) {
	if !assignedIP.Is4() {
		return nil, nil, fmt.Errorf("netstack: only IPv4 is supported; got %v", assignedIP)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if mtu <= 0 {
		mtu = 1500
	}
	// Clamp the upper bound: buildEncapFrame writes the total/payload length fields as
	// uint16, so outbound IPv4 packets larger than ~64 KB would silently overflow the header
	// and desync the gateway's framer. Fortinet's PPP encap has a 6-byte header + 2-byte
	// PPP protocol field, so the effective ceiling is fortinetMaxPayloadLen - 2. A
	// misbehaving or malicious gateway that returns mtu=70000 in its XML config would
	// otherwise let gVisor emit unframeable packets — clamp explicitly and warn.
	const maxNetstackMTU = fortinetMaxPayloadLen - 2
	if mtu > maxNetstackMTU {
		logf("netstack: gateway-advertised MTU %d exceeds %d; clamping to %d",
			mtu, maxNetstackMTU, maxNetstackMTU)
		mtu = maxNetstackMTU
	}
	ch := channel.New(512, uint32(mtu), "")
	const nicID tcpip.NICID = 1
	if tcpErr := s.CreateNIC(nicID, ch); tcpErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpErr)
	}

	addr := tcpip.AddrFromSlice(assignedIP.AsSlice())
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}
	if tcpErr := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); tcpErr != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress: %v", tcpErr)
	}
	// 0.0.0.0/0 → NIC 1 default route. The PPP write loop is the only on-ramp, so all
	// outbound traffic goes through it regardless of destination prefix.
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	return s, ch, nil
}

// newNetstackDialer wraps a configured stack with a Dial-friendly facade plus the list of
// VPN-pushed DNS servers (filtered to IPv4). Name resolution goes through resolveViaVPN
// (real DNS A queries via gonet.DialUDP, retransmitting across the VPN DNS servers on packet
// loss). When no usable VPN DNS servers are present, hostname targets fail closed rather than
// leaking queries to the host OS resolver.
func newNetstackDialer(s *stack.Stack, assignedIP netip.Addr, dns []netip.Addr) netstackDialer {
	d := netstackDialer{stack: s, assignedIP: assignedIP}
	if len(dns) == 0 {
		logf("netstack: gateway did not push DNS servers; hostname lookups are disabled to avoid host DNS leaks")
		return d
	}
	v4 := make([]netip.Addr, 0, len(dns))
	for _, a := range dns {
		if a.Is4() {
			v4 = append(v4, a)
		}
	}
	if len(v4) == 0 {
		logf("netstack: gateway DNS servers %v contain no IPv4 entries; hostname lookups are disabled to avoid host DNS leaks", dns)
		return d
	}
	d.dnsServers = v4
	return d
}

func (d netstackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4":
	default:
		return nil, fmt.Errorf("unsupported network %q (only tcp/tcp4)", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split host:port: %w", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", port, err)
	}

	ip, err := d.resolveHostV4(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}

	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(p),
	}
	return gonet.DialContextTCP(ctx, d.stack, fa, ipv4.ProtocolNumber)
}

// resolveHostV4 turns a hostname into an IPv4 address. It never uses the host resolver:
// without VPN-pushed DNS, hostnames fail closed and IP literals remain supported.
func (d netstackDialer) resolveHostV4(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			return a, nil
		}
		return netip.Addr{}, fmt.Errorf("only IPv4 supported; got %v", a)
	}
	if len(d.dnsServers) == 0 {
		return netip.Addr{}, errors.New("no VPN DNS servers configured; refusing to use host OS resolver")
	}
	return resolveViaVPN(ctx, d.stack, d.dnsServers, host)
}

// dnsQueryFunc performs a single DNS A-record exchange with one server. queryAOne is the
// production implementation; tests inject a stub to exercise the retransmit scheduling in
// queryServersUntilAnswer without standing up a live netstack.
type dnsQueryFunc func(ctx context.Context, server netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error)

// dnsResponseError wraps a failure where the DNS server answered our query (a datagram
// carrying our transaction ID arrived) but the contents are unusable — NXDOMAIN/SERVFAIL
// rcode, a malformed body, or an answer with neither A nor CNAME. It is deliberately distinct
// from a transport timeout/loss: re-sending the same query to a server that already answered
// won't change a response error, whereas a dropped datagram is worth retransmitting. (A stray
// wrong-txid datagram is not a response error — see queryAOne, which discards it.)
// queryServersUntilAnswer keys its retry decision off this distinction so NXDOMAIN stays fast
// while packet loss gets retried.
type dnsResponseError struct{ err error }

func (e *dnsResponseError) Error() string { return e.err.Error() }
func (e *dnsResponseError) Unwrap() error { return e.err }

var errDNSUDPTruncated = errors.New("DNS UDP response truncated")

// answerOrResponseErr adapts a parseDNSResponse outcome to queryAOne's return convention: a
// parse/rcode/no-records failure means the server answered with something unusable, so it is
// marked as a (non-retryable) dnsResponseError rather than transport loss. Shared by the UDP
// and TCP read paths so this classification lives in exactly one place.
func answerOrResponseErr(addr netip.Addr, cname string, err error) (netip.Addr, string, error) {
	if err != nil {
		return netip.Addr{}, "", &dnsResponseError{err}
	}
	return addr, cname, nil
}

// resolveViaVPN resolves a hostname to an IPv4 address using the gateway-pushed DNS servers,
// retransmitting through dropped datagrams. It wires UDP and TCP query functions into
// resolveViaVPNQueryWithFallback; the split exists so the retransmit logic is unit-testable.
func resolveViaVPN(ctx context.Context, s *stack.Stack, servers []netip.Addr, host string) (netip.Addr, error) {
	return resolveViaVPNQueryWithFallback(
		ctx,
		servers,
		host,
		func(ctx context.Context, srv netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
			return queryAOne(ctx, s, srv, qname, timeout)
		},
		func(ctx context.Context, srv netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
			return queryAOneTCPByName(ctx, s, srv, qname, timeout)
		})
}

// resolveViaVPNQuery drives the CNAME-following lookup loop on top of an injectable query
// function. Each hop is resolved by queryServersUntilAnswerWithTCPFallback, which cycles the
// DNS servers and retransmits on packet loss until one answers or the overall budget elapses.
//
// The whole lookup is bounded by an OVERALL deadline (well under the SOCKS5 dial budget) so a
// pathological configuration of many lossy servers can't drag a single hostname resolution
// past the SLO the SOCKS5 client expects.
func resolveViaVPNQuery(ctx context.Context, servers []netip.Addr, host string, query dnsQueryFunc) (netip.Addr, error) {
	return resolveViaVPNQueryWithFallback(ctx, servers, host, query, nil)
}

func resolveViaVPNQueryWithFallback(ctx context.Context, servers []netip.Addr, host string, query dnsQueryFunc, tcpFallback dnsQueryFunc) (netip.Addr, error) {
	const (
		// perTryTimeout is intentionally short: internal DNS over the tunnel answers in well
		// under a second, so anything past this is almost certainly a lost datagram — re-send
		// rather than keep waiting. overallTimeout then bounds the total retransmit budget. At
		// 1s/try over 6s that's ~3 round-trips per server (vs. the pre-fix single shot), which
		// is what absorbs the occasional UDP drop on the FortiGate PPP-over-TLS link that used
		// to surface as "RDP through the tunnel randomly won't connect."
		perTryTimeout  = 1 * time.Second
		overallTimeout = 6 * time.Second
		maxCNAMEHops   = 8
	)

	ctx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	current := host
	for hop := 0; hop <= maxCNAMEHops; hop++ {
		// Build a fully-qualified DNS name. If the caller (or the previous CNAME hop)
		// already passed an FQDN with the trailing dot (e.g. "host.example.com."),
		// don't double it — dnsmessage.NewName rejects "host.example.com.." with an
		// invalid-name error.
		fqdn := current
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		qname, err := dnsmessage.NewName(fqdn)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS name %q: %w", current, err)
		}

		addr, cname, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, current, perTryTimeout, query, tcpFallback)
		if err != nil {
			return netip.Addr{}, err
		}
		if addr.IsValid() {
			return addr, nil
		}
		// No A but a CNAME — follow it. Some recursive resolvers return CNAME-only
		// responses (or CNAME chains whose final A isn't included in the same packet)
		// instead of inlining the resolved A record; without this loop those names
		// would fail to resolve here even though `dig`/the OS resolver finds them.
		if cname == "" {
			return netip.Addr{}, fmt.Errorf("DNS: no A or CNAME records returned for %q", current)
		}
		current = cname
	}
	return netip.Addr{}, fmt.Errorf("DNS: CNAME chain exceeded %d hops starting from %q", maxCNAMEHops, host)
}

// queryServersUntilAnswer cycles through the DNS servers re-sending the query on each
// timeout/loss until one returns an answer (A or CNAME) or ctx's deadline elapses. This
// retransmission is the core fix: the pre-fix code sent a single datagram per server in a
// single pass, so one lost query or reply failed the entire lookup — and therefore the whole
// RDP/SSH connect through the tunnel.
//
// Retry policy hinges on dnsResponseError. A *transport* failure (timeout, dial/write/read
// error) means no usable reply came back — likely a dropped datagram — so we retransmit. An
// authoritative *response* error (NXDOMAIN/SERVFAIL, unparseable, no records) means the server
// answered; re-asking it won't help, so once every server has given a response error in a
// round we stop and fail fast instead of burning the whole budget on a name that doesn't exist.
func queryServersUntilAnswer(ctx context.Context, servers []netip.Addr, qname dnsmessage.Name, label string, perTry time.Duration, query dnsQueryFunc) (netip.Addr, string, error) {
	return queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, label, perTry, query, nil)
}

type dnsTransportFailure struct {
	server netip.Addr
	err    error
}

// queryServersUntilAnswerWithTCPFallback first gives every VPN DNS server a full UDP slot.
// Only after that UDP round fails does it try DNS-over-TCP for the servers that had transport
// loss or truncation, so a slow-but-valid UDP resolver is not preempted by TCP fallback.
func queryServersUntilAnswerWithTCPFallback(ctx context.Context, servers []netip.Addr, qname dnsmessage.Name, label string, perTry time.Duration, query dnsQueryFunc, tcpFallback dnsQueryFunc) (netip.Addr, string, error) {
	var lastErr error
	for ctx.Err() == nil {
		sawLoss := false
		var tcpCandidates []dnsTransportFailure
		for _, srv := range servers {
			slotStart := time.Now()
			addr, cname, err := query(ctx, srv, qname, perTry)
			if err == nil {
				return addr, cname, nil
			}
			lastErr = fmt.Errorf("%s: %w", srv, err)

			var respErr *dnsResponseError
			if errors.As(err, &respErr) {
				// The server answered with something unusable (e.g. NXDOMAIN). Move on to the
				// next server — it might be authoritative for a split-horizon name — but don't
				// count this as packet loss, so a round of pure response errors ends the lookup.
				logf("netstack: DNS A query for %q via %s rejected (%v)", label, srv, err)
				continue
			}

			padSlot := true
			if tcpFallback != nil {
				tcpCandidates = append(tcpCandidates, dnsTransportFailure{server: srv, err: err})
				if errors.Is(err, errDNSUDPTruncated) {
					padSlot = false
					logf("netstack: DNS A query for %q via %s returned a truncated UDP response; TCP fallback queued", label, srv)
				} else {
					logf("netstack: DNS A query for %q via %s failed over UDP (%v); TCP fallback queued", label, srv, err)
				}
			} else {
				// No reply came back — treat as a dropped datagram and retransmit.
				sawLoss = true
				logf("netstack: DNS A query for %q via %s failed (%v); retransmitting", label, srv, err)
			}

			if padSlot {
				waitDNSQuerySlot(ctx, slotStart, perTry)
			}
			if ctx.Err() != nil {
				break
			}
		}

		if ctx.Err() == nil && tcpFallback != nil {
			for _, candidate := range tcpCandidates {
				slotStart := time.Now()
				logf("netstack: DNS A query for %q via %s trying TCP fallback", label, candidate.server)
				addr, cname, err := tcpFallback(ctx, candidate.server, qname, perTry)
				if err == nil {
					logf("netstack: DNS A query for %q via %s succeeded over TCP fallback", label, candidate.server)
					return addr, cname, nil
				}

				var respErr *dnsResponseError
				if errors.As(err, &respErr) {
					lastErr = fmt.Errorf("%s TCP fallback: %w", candidate.server, err)
					logf("netstack: DNS A query for %q via %s TCP fallback was rejected (%v)", label, candidate.server, err)
					continue
				}

				sawLoss = true
				lastErr = fmt.Errorf("%s: UDP failed (%v); TCP fallback failed (%w)", candidate.server, candidate.err, err)
				logf("netstack: DNS A query for %q via %s TCP fallback failed (%v)", label, candidate.server, err)
				waitDNSQuerySlot(ctx, slotStart, perTry)
				if ctx.Err() != nil {
					break
				}
			}
		} else if ctx.Err() != nil && len(tcpCandidates) > 0 {
			sawLoss = true
		}

		// Only retransmit when at least one server failed to answer at all. If every server
		// returned an authoritative negative, more rounds can't change the outcome.
		if !sawLoss {
			break
		}
	}

	if lastErr != nil {
		logf("netstack: DNS A query for %q failed after exhausting VPN DNS servers: %v", label, lastErr)
		return netip.Addr{}, "", lastErr
	}
	// lastErr is nil only when no query ran at all — i.e. servers was empty (callers guard
	// against this upstream). Surface the context error if cancellation/budget is why we
	// stopped, otherwise say plainly that there was nothing to query.
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, "", err
	}
	return netip.Addr{}, "", errors.New("no DNS servers configured")
}

func waitDNSQuerySlot(ctx context.Context, slotStart time.Time, perTry time.Duration) {
	// Pad out the slot so an *instant* transport failure (a dial error returning well
	// before perTry) can't busy-spin the loop or hammer the gateway. A genuine read
	// timeout already consumed the slot, so this is a no-op in the common loss case.
	if remain := perTry - time.Since(slotStart); remain > 0 {
		t := time.NewTimer(remain)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}

func packAQuery(qname dnsmessage.Name) ([]byte, uint16, error) {
	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, 0, fmt.Errorf("DNS txid: %w", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(txid[:]),
			RecursionDesired: true,
			OpCode:           0, // standard query
		},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("DNS pack: %w", err)
	}
	return wire, msg.Header.ID, nil
}

// queryAOne sends a single DNS A-record query to one server over UDP via the VPN netstack.
func queryAOne(ctx context.Context, s *stack.Stack, server netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
	if !server.Is4() {
		return netip.Addr{}, "", fmt.Errorf("DNS server %v is not IPv4", server)
	}
	wire, txid, err := packAQuery(qname)
	if err != nil {
		return netip.Addr{}, "", err
	}
	return queryAOneUDP(ctx, s, server, wire, txid, timeout)
}

func queryAOneTCPByName(ctx context.Context, s *stack.Stack, server netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
	if !server.Is4() {
		return netip.Addr{}, "", fmt.Errorf("DNS server %v is not IPv4", server)
	}
	wire, txid, err := packAQuery(qname)
	if err != nil {
		return netip.Addr{}, "", err
	}
	return queryAOneTCP(ctx, s, server, wire, txid, timeout)
}

// queryAOneUDP sends one DNS A-record query over UDP via the netstack. It returns
// errDNSUDPTruncated when the server sets the TC bit so queryServersUntilAnswerWithTCPFallback
// can retry the name over DNS-over-TCP.
func queryAOneUDP(ctx context.Context, s *stack.Stack, server netip.Addr, query []byte, txid uint16, timeout time.Duration) (netip.Addr, string, error) {
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(server.AsSlice()),
		Port: 53,
	}
	conn, err := gonet.DialUDP(s, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS dial: %w", err)
	}
	defer conn.Close()

	// Per-try read timeout — queryServersUntilAnswer retransmits (and fails over to the next
	// server) when this fires, which is what gives us loss resilience and real failover
	// (gonet.DialUDP can't fail on an unreachable UDP destination because UDP has no handshake).
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS deadline: %w", err)
	}

	if _, err := conn.Write(query); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS write: %w", err)
	}

	// Allocate generously — DNS responses without EDNS are capped at 512 bytes, but EDNS-
	// extended responses can be up to ~4 KB.
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return netip.Addr{}, "", errors.New("DNS connection closed")
			}
			return netip.Addr{}, "", fmt.Errorf("DNS read: %w", err)
		}

		// Discard any datagram whose transaction ID isn't ours and keep waiting (within the
		// same read deadline) for the real reply. A wrong-txid packet is a transport artifact
		// — a delayed or duplicated reply, or an injected datagram — NOT an authoritative
		// answer. Returning it as a dnsResponseError would let a single stray packet fail the
		// whole lookup with no retransmit, reopening the intermittent-failure hole this
		// resolver exists to close. The conn deadline bounds the loop, so even a flood of
		// strays just falls through to a (retryable) read timeout.
		if n < 2 || binary.BigEndian.Uint16(buf[0:2]) != txid {
			continue
		}

		// Peek at the TC (truncation) flag at bit 9 of the 16-bit flags word (byte 2 high bits)
		// and let queryServersUntilAnswerWithTCPFallback retry over TCP if set. Without this, large internal
		// records (many A's, big TXT) silently get truncated answers — the parser would return
		// whatever fit in 4 KB without signalling truncation.
		if n >= 3 && buf[2]&0x02 != 0 {
			return netip.Addr{}, "", errDNSUDPTruncated
		}

		// Our reply (txid already matched above). A parse/rcode/no-records failure is an
		// authoritative response — the server answered — so answerOrResponseErr marks it
		// non-retryable rather than letting the loop re-query a name already resolved (or denied).
		return answerOrResponseErr(parseDNSResponse(buf[:n], txid))
	}
}

// parseDNSResponse decodes a DNS response packet (UDP or post-TCP-length-strip) and returns
// either the first A record, a CNAME target to follow, or an error. Shared by the UDP and
// TCP code paths so they have identical answer-section handling.
func parseDNSResponse(packet []byte, wantID uint16) (netip.Addr, string, error) {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(packet)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS parse: %w", err)
	}
	if hdr.ID != wantID {
		return netip.Addr{}, "", fmt.Errorf("DNS txid mismatch: want %#x got %#x", wantID, hdr.ID)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, "", fmt.Errorf("DNS rcode %v", hdr.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS skip questions: %w", err)
	}
	// Walk the entire answer section, preferring the first A record but tracking the
	// first CNAME as a fallback so resolveViaVPNQuery can follow the chain when the resolver
	// returns CNAME-only.
	var cname string
	for {
		ah, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return netip.Addr{}, "", fmt.Errorf("DNS answer header: %w", err)
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			a, err := parser.AResource()
			if err != nil {
				return netip.Addr{}, "", fmt.Errorf("DNS A resource: %w", err)
			}
			return netip.AddrFrom4(a.A), "", nil
		case dnsmessage.TypeCNAME:
			cn, err := parser.CNAMEResource()
			if err != nil {
				return netip.Addr{}, "", fmt.Errorf("DNS CNAME resource: %w", err)
			}
			if cname == "" {
				cname = cn.CNAME.String()
			}
		default:
			if err := parser.SkipAnswer(); err != nil {
				return netip.Addr{}, "", fmt.Errorf("DNS skip answer: %w", err)
			}
		}
	}
	if cname != "" {
		return netip.Addr{}, cname, nil
	}
	return netip.Addr{}, "", fmt.Errorf("DNS: no A or CNAME records returned")
}

// queryAOneTCP retries a DNS A query over TCP after a UDP response had the TC bit set.
// TCP DNS prefixes each message with a 2-byte length header (RFC 1035 §4.2.2). Returns the
// same (addr, cname, error) triple as queryAOne so resolveViaVPNQuery's CNAME-following loop
// works identically whether the answer arrived over UDP or TCP — the bug we'd reintroduce
// otherwise is "name resolves with `dig` but fails through the tunnel only for big answers
// that TC-fall-back to TCP."
func queryAOneTCP(ctx context.Context, s *stack.Stack, server netip.Addr, query []byte, txid uint16, timeout time.Duration) (netip.Addr, string, error) {
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(server.AsSlice()),
		Port: 53,
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := gonet.DialContextTCP(dialCtx, s, fa, ipv4.ProtocolNumber)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP deadline: %w", err)
	}

	// Write length-prefixed query.
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP write: %w", err)
	}

	// Read the 2-byte length prefix, then the message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	// Per RFC 1035 the response can be up to 65535 bytes; cap defensively at 64 KB minus
	// the header (anything larger is broken or hostile).
	if respLen < 12 || respLen > 0xFFFF {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP nonsense length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP read body: %w", err)
	}

	return answerOrResponseErr(parseDNSResponse(respBuf, txid))
}
