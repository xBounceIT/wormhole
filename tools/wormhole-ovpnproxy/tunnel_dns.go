package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/xBounceIT/wormhole/tools/internal/sockstun"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/publicsuffix"
)

// Both the pushed-DNS lookup and the fallback dialer belong to the same netstack.
// No host resolver or OS socket is used, including when the VPN stops working.
type tunnelDNSResolver struct {
	primary  func(context.Context, string) ([]string, error)
	tunnel   sockstun.Dialer
	fallback bool
	hasV4    bool
	hasV6    bool
}

func (r tunnelDNSResolver) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The netstack resolver appends a dot itself. Normalize an already absolute
	// name to avoid turning it into an invalid DNS question with two trailing dots.
	host = strings.TrimSuffix(host, ".")
	allowFallback := r.fallback && publicDNSName(host)
	var primaryErr error
	if r.primary != nil {
		primaryCtx := ctx
		cancel := func() {}
		if allowFallback {
			// Leave time for public DNS and the TCP connect within SOCKS' 15s budget.
			primaryCtx, cancel = context.WithTimeout(ctx, 4*time.Second)
		}
		addrs, err := r.primary(primaryCtx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		primaryErr = err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !allowFallback {
		if primaryErr != nil {
			return nil, primaryErr
		}
		return nil, errors.New("VPN DNS returned no addresses or the server pushed no usable DNS servers")
	}

	servers := []string{}
	var types []dnsmessage.Type
	if r.hasV4 {
		servers = append(servers, "1.1.1.1", "8.8.8.8")
		types = append(types, dnsmessage.TypeA)
	} else if r.hasV6 {
		servers = append(servers, "2606:4700:4700::1111", "2001:4860:4860::8888")
	}
	if r.hasV6 {
		types = append(types, dnsmessage.TypeAAAA)
	}
	var fallbackErr error
	for _, server := range servers {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addrs, err := lookupTunnelDNS(lookupCtx, r.tunnel, net.JoinHostPort(server, "53"), host, types)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		fallbackErr = err
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("cannot resolve %s through VPN DNS: %w", host,
		errors.Join(primaryErr, fallbackErr, errors.New("public tunnel DNS returned no usable addresses")))
}

func publicDNSName(host string) bool {
	// Single-label names, private suffixes (.local/.internal/.corp), literals and
	// reverse zones must stay with the VPN's own DNS. An ICANN suffix alone is not
	// a host; require a registrable domain as well.
	host = strings.ToLower(host)
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if c != '-' && c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	if _, err := netip.ParseAddr(host); err == nil || strings.HasSuffix(host, ".arpa") || strings.HasSuffix(host, ".onion") {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(host)
	// Public hosting/CDN suffixes (cloudfront.net, github.io, etc.) are in the
	// PSL's PRIVATE section. Their parent ICANN suffix still makes them public.
	for !icann {
		_, parent, found := strings.Cut(suffix, ".")
		if !found {
			return false
		}
		suffix, icann = publicsuffix.PublicSuffix(parent)
	}
	return host != suffix
}
