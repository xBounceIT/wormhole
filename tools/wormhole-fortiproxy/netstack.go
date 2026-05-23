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
// (carried by `dnsServers`); the host OS resolver is used only as a fallback when the
// gateway didn't push any DNS configuration. This prevents both DNS leaks (queries for
// `*.corp.local` going to the host's resolver) and resolution failures for internal names
// that don't resolve outside the tunnel.
type netstackDialer struct {
	stack      *stack.Stack
	assignedIP netip.Addr
	dnsServers []netip.Addr // populated from session.DNS; empty means fall back to OS resolver
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
// VPN-pushed DNS servers (filtered to IPv4). When dns is non-empty, name resolution goes
// through resolveViaVPN (real DNS A queries via gonet.DialUDP with per-server retry on
// timeout); when empty, we fall back to the OS resolver and log a warning so the user can
// see the DNS-leak risk in the logs.
func newNetstackDialer(s *stack.Stack, assignedIP netip.Addr, dns []netip.Addr) netstackDialer {
	d := netstackDialer{stack: s, assignedIP: assignedIP}
	if len(dns) == 0 {
		logf("netstack: gateway did not push DNS servers; name lookups will use the host OS resolver (queries may leak)")
		return d
	}
	v4 := make([]netip.Addr, 0, len(dns))
	for _, a := range dns {
		if a.Is4() {
			v4 = append(v4, a)
		}
	}
	if len(v4) == 0 {
		logf("netstack: gateway DNS servers %v contain no IPv4 entries; falling back to OS resolver", dns)
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

// resolveHostV4 turns a hostname into an IPv4 address. Uses resolveViaVPN when the gateway
// pushed DNS servers (the common case); falls back to the host OS resolver only when no
// gateway DNS was advertised.
func (d netstackDialer) resolveHostV4(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			return a, nil
		}
		return netip.Addr{}, fmt.Errorf("only IPv4 supported; got %v", a)
	}
	if len(d.dnsServers) == 0 {
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(addrs) == 0 {
			return netip.Addr{}, fmt.Errorf("no IPv4 addresses for %q", host)
		}
		return addrs[0].Unmap(), nil
	}
	return resolveViaVPN(ctx, d.stack, d.dnsServers, host)
}

// resolveViaVPN sends a DNS A-record query through the netstack to each gateway-pushed DNS
// server in order, with a 2-second read timeout per server. Returns the first valid answer.
// Unlike Go's net.Resolver with a custom Dial, this loop actually advances on read-timeout
// (broken-but-reachable DNS server) instead of being stuck on the first server because
// gonet.DialUDP doesn't probe reachability.
//
// The whole lookup is bounded by an OVERALL 5s deadline matching the OS-resolver fallback
// path, so a pathological configuration of many slow servers (N × 2s) can't drag a single
// hostname resolution past the SLO the SOCKS5 client expects.
func resolveViaVPN(ctx context.Context, s *stack.Stack, servers []netip.Addr, host string) (netip.Addr, error) {
	const (
		perServerTimeout = 2 * time.Second
		overallTimeout   = 5 * time.Second
	)

	ctx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	qname, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS name %q: %w", host, err)
	}
	var lastErr error
	for _, srv := range servers {
		// Respect the caller's (or our overall) deadline before each attempt.
		if ctx.Err() != nil {
			if lastErr != nil {
				return netip.Addr{}, lastErr
			}
			return netip.Addr{}, ctx.Err()
		}
		addr, err := queryAOne(ctx, s, srv, qname, perServerTimeout)
		if err == nil {
			return addr, nil
		}
		lastErr = fmt.Errorf("%s: %w", srv, err)
		logf("netstack: DNS A query for %q via %s failed (%v); trying next server", host, srv, err)
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers configured")
	}
	return netip.Addr{}, lastErr
}

// queryAOne sends a single DNS A-record query to one server over UDP via the netstack and
// returns the first A record from the answer section. Bounded by perServerTimeout regardless
// of the caller's ctx deadline (which is the OVERALL budget). The transaction ID is randomly
// generated per query so responses can't be cross-contaminated between concurrent lookups.
func queryAOne(ctx context.Context, s *stack.Stack, server netip.Addr, qname dnsmessage.Name, timeout time.Duration) (netip.Addr, error) {
	if !server.Is4() {
		return netip.Addr{}, fmt.Errorf("DNS server %v is not IPv4", server)
	}
	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS txid: %w", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 binary.BigEndian.Uint16(txid[:]),
			RecursionDesired:   true,
			OpCode:             0, // standard query
		},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS pack: %w", err)
	}

	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(server.AsSlice()),
		Port: 53,
	}
	conn, err := gonet.DialUDP(s, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS dial: %w", err)
	}
	defer conn.Close()

	// Per-server read timeout — the loop in resolveViaVPN advances on this timeout firing,
	// which is what gives us real failover (gonet.DialUDP can't fail on an unreachable UDP
	// destination because UDP has no handshake).
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS deadline: %w", err)
	}

	if _, err := conn.Write(wire); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS write: %w", err)
	}

	// Allocate generously — DNS responses without EDNS are capped at 512 bytes, but EDNS-
	// extended responses can be up to ~4 KB.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return netip.Addr{}, errors.New("DNS connection closed")
		}
		return netip.Addr{}, fmt.Errorf("DNS read: %w", err)
	}

	// Peek at the TC (truncation) flag at bit 9 of the 16-bit flags word (byte 2 high bits)
	// and retry over TCP if set. Without this, large internal records (many A's, big TXT)
	// silently get truncated answers — the parser would return whatever fit in 4 KB without
	// signalling truncation.
	if n >= 3 && buf[2]&0x02 != 0 {
		return queryAOneTCP(ctx, s, server, wire, msg.Header.ID, timeout)
	}

	var parser dnsmessage.Parser
	hdr, err := parser.Start(buf[:n])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS parse: %w", err)
	}
	if hdr.ID != msg.Header.ID {
		return netip.Addr{}, fmt.Errorf("DNS txid mismatch: want %#x got %#x", msg.Header.ID, hdr.ID)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, fmt.Errorf("DNS rcode %v", hdr.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS skip questions: %w", err)
	}
	for {
		hdr, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS answer header: %w", err)
		}
		if hdr.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return netip.Addr{}, fmt.Errorf("DNS skip answer: %w", err)
			}
			continue
		}
		a, err := parser.AResource()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS A resource: %w", err)
		}
		return netip.AddrFrom4(a.A), nil
	}
	return netip.Addr{}, fmt.Errorf("DNS: no A records returned")
}

// queryAOneTCP retries a DNS A query over TCP after a UDP response had the TC bit set.
// TCP DNS prefixes each message with a 2-byte length header (RFC 1035 §4.2.2).
func queryAOneTCP(ctx context.Context, s *stack.Stack, server netip.Addr, query []byte, txid uint16, timeout time.Duration) (netip.Addr, error) {
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(server.AsSlice()),
		Port: 53,
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := gonet.DialContextTCP(dialCtx, s, fa, ipv4.ProtocolNumber)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP deadline: %w", err)
	}

	// Write length-prefixed query.
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP write: %w", err)
	}

	// Read the 2-byte length prefix, then the message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	// Per RFC 1035 the response can be up to 65535 bytes; cap defensively at 64 KB minus
	// the header (anything larger is broken or hostile).
	if respLen < 12 || respLen > 0xFFFF {
		return netip.Addr{}, fmt.Errorf("DNS-TCP nonsense length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP read body: %w", err)
	}

	var parser dnsmessage.Parser
	hdr, err := parser.Start(respBuf)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP parse: %w", err)
	}
	if hdr.ID != txid {
		return netip.Addr{}, fmt.Errorf("DNS-TCP txid mismatch: want %#x got %#x", txid, hdr.ID)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, fmt.Errorf("DNS-TCP rcode %v", hdr.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return netip.Addr{}, fmt.Errorf("DNS-TCP skip questions: %w", err)
	}
	for {
		ah, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS-TCP answer header: %w", err)
		}
		if ah.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return netip.Addr{}, fmt.Errorf("DNS-TCP skip answer: %w", err)
			}
			continue
		}
		a, err := parser.AResource()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("DNS-TCP A resource: %w", err)
		}
		return netip.AddrFrom4(a.A), nil
	}
	return netip.Addr{}, fmt.Errorf("DNS-TCP: no A records returned")
}
