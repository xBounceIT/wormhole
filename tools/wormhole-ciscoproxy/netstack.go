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

// netstackDialer dials TCP through a gVisor stack that owns the client-side of the AnyConnect
// CSTP link. Outbound IPv4 packets are written into the channel endpoint; inbound packets from
// the gateway are injected by the CSTP read loop in stf.go.
//
// Hostname targets received over SOCKS5 are resolved using the VPN-provided DNS servers
// (carried by `dnsServers`). When the gateway does not push usable IPv4 DNS servers, hostname
// targets fail closed; IP literals still dial normally. This mirrors the Fortinet sidecar's
// netstack so the parent's Socks5Client sees identical behavior across tunnel kinds.
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
	// Clamp the upper bound: the STF frame writes the payload length as a uint16, so an IPv4
	// packet larger than cstpMaxPayloadLen would silently overflow the header and desync the
	// gateway's framer. A misbehaving or malicious gateway that advertised a huge X-CSTP-MTU
	// would otherwise let gVisor emit unframeable packets — clamp explicitly and warn.
	const maxNetstackMTU = cstpMaxPayloadLen
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
	// 0.0.0.0/0 → NIC 1 default route. The CSTP write loop is the only on-ramp, so all
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

// dnsResponseError wraps a failure where the DNS server answered our query (a datagram carrying
// our transaction ID arrived) but the contents are unusable — NXDOMAIN/SERVFAIL rcode, a
// malformed body, or an answer with neither A nor CNAME. It is deliberately distinct from a
// transport timeout/loss: re-sending the same query to a server that already answered won't
// change a response error, whereas a dropped datagram is worth retransmitting.
type dnsResponseError struct{ err error }

func (e *dnsResponseError) Error() string { return e.err.Error() }
func (e *dnsResponseError) Unwrap() error { return e.err }

// answerOrResponseErr adapts a parseDNSResponse outcome to queryAOne's return convention: a
// parse/rcode/no-records failure means the server answered with something unusable, so it is
// marked as a (non-retryable) dnsResponseError rather than transport loss.
func answerOrResponseErr(addr netip.Addr, cname string, err error) (netip.Addr, string, error) {
	if err != nil {
		return netip.Addr{}, "", &dnsResponseError{err}
	}
	return addr, cname, nil
}

// resolveViaVPN resolves a hostname to an IPv4 address using the gateway-pushed DNS servers,
// retransmitting through dropped datagrams. It wires the production queryAOne into
// resolveViaVPNQuery; the split exists so the retransmit logic is unit-testable.
func resolveViaVPN(ctx context.Context, s *stack.Stack, servers []netip.Addr, host string) (netip.Addr, error) {
	return resolveViaVPNQuery(ctx, servers, host, func(ctx context.Context, srv netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
		return queryAOne(ctx, s, srv, qname, timeout)
	})
}

// resolveViaVPNQuery drives the CNAME-following lookup loop on top of an injectable query
// function. Each hop is resolved by queryServersUntilAnswer, which cycles the DNS servers and
// retransmits on packet loss until one answers or the overall budget elapses.
func resolveViaVPNQuery(ctx context.Context, servers []netip.Addr, host string, query dnsQueryFunc) (netip.Addr, error) {
	const (
		perTryTimeout  = 1 * time.Second
		overallTimeout = 6 * time.Second
		maxCNAMEHops   = 8
	)

	ctx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	current := host
	for hop := 0; hop <= maxCNAMEHops; hop++ {
		fqdn := current
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		qname, err := dnsmessage.NewName(fqdn)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS name %q: %w", current, err)
		}

		addr, cname, err := queryServersUntilAnswer(ctx, servers, qname, current, perTryTimeout, query)
		if err != nil {
			return netip.Addr{}, err
		}
		if addr.IsValid() {
			return addr, nil
		}
		if cname == "" {
			return netip.Addr{}, fmt.Errorf("DNS: no A or CNAME records returned for %q", current)
		}
		current = cname
	}
	return netip.Addr{}, fmt.Errorf("DNS: CNAME chain exceeded %d hops starting from %q", maxCNAMEHops, host)
}

// queryServersUntilAnswer cycles through the DNS servers re-sending the query on each
// timeout/loss until one returns an answer (A or CNAME) or ctx's deadline elapses.
func queryServersUntilAnswer(ctx context.Context, servers []netip.Addr, qname dnsmessage.Name, label string, perTry time.Duration, query dnsQueryFunc) (netip.Addr, string, error) {
	var lastErr error
	for ctx.Err() == nil {
		sawLoss := false
		for _, srv := range servers {
			slotStart := time.Now()
			addr, cname, err := query(ctx, srv, qname, perTry)
			if err == nil {
				return addr, cname, nil
			}
			lastErr = fmt.Errorf("%s: %w", srv, err)

			var respErr *dnsResponseError
			if errors.As(err, &respErr) {
				logf("netstack: DNS A query for %q via %s rejected (%v)", label, srv, err)
				continue
			}

			sawLoss = true
			logf("netstack: DNS A query for %q via %s failed (%v); retransmitting", label, srv, err)
			if remain := perTry - time.Since(slotStart); remain > 0 {
				t := time.NewTimer(remain)
				select {
				case <-ctx.Done():
					t.Stop()
				case <-t.C:
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
		if !sawLoss {
			break
		}
	}

	if lastErr != nil {
		return netip.Addr{}, "", lastErr
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, "", err
	}
	return netip.Addr{}, "", errors.New("no DNS servers configured")
}

// queryAOne sends a single DNS A-record query to one server over UDP via the netstack.
func queryAOne(ctx context.Context, s *stack.Stack, server netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
	if !server.Is4() {
		return netip.Addr{}, "", fmt.Errorf("DNS server %v is not IPv4", server)
	}
	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS txid: %w", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(txid[:]),
			RecursionDesired: true,
			OpCode:           0,
		},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS pack: %w", err)
	}

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

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS deadline: %w", err)
	}

	if _, err := conn.Write(wire); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS write: %w", err)
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return netip.Addr{}, "", errors.New("DNS connection closed")
			}
			return netip.Addr{}, "", fmt.Errorf("DNS read: %w", err)
		}

		if n < 2 || binary.BigEndian.Uint16(buf[0:2]) != msg.Header.ID {
			continue
		}

		// Retry over TCP if the truncation bit is set.
		if n >= 3 && buf[2]&0x02 != 0 {
			return queryAOneTCP(ctx, s, server, wire, msg.Header.ID, timeout)
		}

		return answerOrResponseErr(parseDNSResponse(buf[:n], msg.Header.ID))
	}
}

// parseDNSResponse decodes a DNS response packet (UDP or post-TCP-length-strip) and returns
// either the first A record, a CNAME target to follow, or an error.
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

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP write: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 0xFFFF {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP nonsense length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return netip.Addr{}, "", fmt.Errorf("DNS-TCP read body: %w", err)
	}

	return answerOrResponseErr(parseDNSResponse(respBuf, txid))
}
