package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
)

// Keep address selection outside the CGO adapter so production tunnel dialing is
// exercised by the portable tests. Both DNS and connections use this tunnel only.
type tunnelDialer struct {
	tunnel   sockstun.Dialer
	resolver tunnelDNSResolver
}

func (d tunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			if !d.resolver.hasV4 {
				return nil, fmt.Errorf("IPv4 destination %s requested but tunnel is IPv6-only", host)
			}
		} else if !d.resolver.hasV6 {
			return nil, fmt.Errorf("IPv6 destination %s requested but tunnel is IPv4-only", host)
		}
		return d.tunnel.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	addrs, err := d.resolver.LookupContextHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s through tunnel DNS: %w", host, err)
	}
	var targets []string
	seen := make(map[string]bool)
	for _, address := range addrs {
		ip := net.ParseIP(address)
		if ip == nil || ip.To4() != nil && !d.resolver.hasV4 || ip.To4() == nil && !d.resolver.hasV6 {
			continue
		}
		target := net.JoinHostPort(ip.String(), port)
		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no addresses of installed family (v4=%v v6=%v) for %s", d.resolver.hasV4, d.resolver.hasV6, host)
	}
	var lastErr error
	for i, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dialCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok && len(targets)-i > 1 {
			// A CDN can return several addresses. Share the remaining SOCKS budget
			// so a blackholed first edge cannot prevent trying every other edge.
			remaining := time.Until(deadline)
			// Match the netstack's two-second minimum for a useful TCP attempt
			// when possible, while reserving at least half the time for retries.
			budget := max(remaining/time.Duration(len(targets)-i), min(2*time.Second, remaining/2))
			dialCtx, cancel = context.WithTimeout(ctx, budget)
		}
		conn, err := d.tunnel.DialContext(dialCtx, network, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
