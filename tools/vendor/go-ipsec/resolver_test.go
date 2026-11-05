package ipsec

import (
	"net/netip"
	"testing"
)

// TestResolverServerPrefersV6WhenNoV4 is finding #6: with only IPv6 resolvers
// assigned (a v6-only / dual-stack-v6 deployment), Resolver("") must use the
// assigned v6 server rather than ignoring DNS6 and falling back to 1.1.1.1.
func TestResolverServerPrefersV6WhenNoV4(t *testing.T) {
	v4 := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	v6 := []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}

	cases := []struct {
		name       string
		dns4, dns6 []netip.Addr
		want       string
	}{
		{"v4 present wins", v4, v6, "10.0.0.53:53"},
		{"v6 only honored", nil, v6, "[2606:4700:4700::1111]:53"},
		{"none falls back", nil, nil, "1.1.1.1:53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolverServer(tc.dns4, tc.dns6); got != tc.want {
				t.Fatalf("resolverServer = %q, want %q", got, tc.want)
			}
		})
	}
}
