package ipsec

import (
	"context"
	"net"
	"net/netip"
)

// resolverServer picks the DNS server (host:port) for an empty server argument:
// the first responder-pushed IPv4 resolver, else the first IPv6 resolver (so a
// v6-only assignment is honored instead of being ignored), else the public
// 1.1.1.1 fallback.
func resolverServer(dns4, dns6 []netip.Addr) string {
	switch {
	case len(dns4) > 0:
		return net.JoinHostPort(dns4[0].String(), "53")
	case len(dns6) > 0:
		return net.JoinHostPort(dns6[0].String(), "53")
	default:
		return "1.1.1.1:53"
	}
}

// Resolver returns a *net.Resolver that performs DNS lookups through the tunnel.
// server is the DNS server as host[:port] (port defaults to 53); when empty the
// first responder-pushed resolver is used — the v4 list first, then the v6 list
// (so a v6-only assignment is honored), falling back to 1.1.1.1:53.
//
// go-tun2net exposes its UDP conns as net.PacketConn, so Go's resolver picks
// datagram framing for UDP queries without any adapter here.
func (c *Client) Resolver(server string) *net.Resolver {
	if server == "" {
		server = resolverServer(c.DNS(), c.DNS6())
	} else if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return c.DialContext(ctx, network, server)
		},
	}
}
