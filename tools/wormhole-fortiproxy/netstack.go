package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

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
// (carried by `resolver`, built in newNetstackDialer); the host OS resolver is used only as
// a fallback when the gateway did not push any DNS configuration. This prevents both DNS
// leaks (queries for `*.corp.local` going to the host's resolver) and resolution failures
// for internal names that don't resolve outside the tunnel.
type netstackDialer struct {
	stack      *stack.Stack
	assignedIP netip.Addr
	dnsServers []netip.Addr // populated from session.DNS; empty means fall back to OS resolver
	resolver   *net.Resolver
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

// newNetstackDialer wraps a configured stack with a Dial-friendly facade and an in-stack
// DNS resolver. When dns is non-empty the resolver answers every name lookup via
// gonet.DialUDP to the gateway-pushed DNS servers — never the host OS resolver — so
// internal hostnames work and queries don't leak. When dns is empty (gateway didn't push
// any DNS), the resolver field stays nil and DialContext falls back to net.DefaultResolver
// for backward-compat with public-host targets.
func newNetstackDialer(s *stack.Stack, assignedIP netip.Addr, dns []netip.Addr) netstackDialer {
	d := netstackDialer{stack: s, assignedIP: assignedIP, dnsServers: dns}
	if len(dns) == 0 {
		logf("netstack: gateway did not push DNS servers; name lookups will use the host OS resolver")
		return d
	}
	// Filter to IPv4 servers (our stack is IPv4-only). The first server is preferred; the
	// rest are retry candidates handled inside dialDNSServer below.
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
	d.resolver = &net.Resolver{
		// PreferGo forces Go's pure-Go resolver, which honors the Dial hook. Without it,
		// Windows would route the lookup through getaddrinfo (cgo) and our Dial would
		// never be called — defeating the whole point of this code.
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Go's resolver passes the system-configured DNS server in `address`. Ignore
			// it and use the gateway-pushed servers in order; this also forces UDP (TCP-
			// over-DNS retry on EDNS truncation is a follow-up).
			_ = network
			_ = address
			var lastErr error
			for _, srv := range v4 {
				fa := tcpip.FullAddress{
					NIC:  1,
					Addr: tcpip.AddrFromSlice(srv.AsSlice()),
					Port: 53,
				}
				conn, err := gonet.DialUDP(s, nil, &fa, ipv4.ProtocolNumber)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("no DNS servers available")
			}
			return nil, lastErr
		},
	}
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

// resolveHostV4 turns a hostname into an IPv4 address. Uses the in-stack VPN DNS resolver
// when configured (gateway pushed DNS servers), falling back to the host OS resolver only
// when the gateway didn't push any DNS — preserves DNS confidentiality for the common case
// and avoids breaking SOCKS for hosts on networks without a VPN-attached DNS.
func (d netstackDialer) resolveHostV4(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			return a, nil
		}
		return netip.Addr{}, fmt.Errorf("only IPv4 supported; got %v", a)
	}
	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupNetIP(lookupCtx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv4 addresses for %q", host)
	}
	return addrs[0].Unmap(), nil
}
