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
	return d.dialTargets(ctx, network, targets)
}

func (d tunnelDialer) dialTargets(ctx context.Context, network string, targets []string) (net.Conn, error) {
	if len(targets) == 1 {
		return d.tunnel.DialContext(ctx, network, targets[0])
	}
	type result struct {
		conn net.Conn
		err  error
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result)
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	next, active := 0, 0
	startNext := func() {
		target := targets[next]
		next++
		active++
		go func() {
			conn, err := d.tunnel.DialContext(dialCtx, network, target)
			select {
			case results <- result{conn, err}:
			case <-dialCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
		if next < len(targets) {
			timer.Reset(250 * time.Millisecond)
		} else {
			timer.Stop()
		}
	}
	startNext()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case outcome := <-results:
			active--
			if err := ctx.Err(); err != nil {
				if outcome.conn != nil {
					outcome.conn.Close()
				}
				return nil, err
			}
			if outcome.err == nil {
				return outcome.conn, nil
			}
			if outcome.conn != nil {
				outcome.conn.Close()
			}
			if active == 0 {
				if next == len(targets) {
					return nil, outcome.err
				}
				startNext()
			}
		case <-timer.C:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Keep the caller's deadline on every attempt. A later reachable edge
			// must not inherit a geometrically shrinking slice of that deadline.
			if next < len(targets) {
				startNext()
			}
		}
	}
}
