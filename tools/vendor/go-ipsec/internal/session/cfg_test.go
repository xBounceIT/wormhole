package session

import (
	"net/netip"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// TestParseCPReplyIPv6 covers the IPv6 CFG_REPLY parsing: a 17-byte
// INTERNAL_IP6_ADDRESS (addr + prefix), the 16-byte default-/64 form, and
// INTERNAL_IP6_DNS, alongside the existing v4 attributes.
func TestParseCPReplyIPv6(t *testing.T) {
	addr := netip.MustParseAddr("fd00:abcd::42")
	dns6 := netip.MustParseAddr("2606:4700:4700::1111")
	a16 := addr.As16()
	d16 := dns6.As16()

	cases := []struct {
		name     string
		attrs    []ikemsg.ConfigAttr
		wantIP6  netip.Prefix
		wantDNS6 []netip.Addr
	}{
		{
			name: "addr_with_prefix",
			attrs: []ikemsg.ConfigAttr{
				{Type: ikemsg.ConfigAttrInternalIP6Address, Value: append(append([]byte(nil), a16[:]...), 96)},
				{Type: ikemsg.ConfigAttrInternalIP6DNS, Value: append([]byte(nil), d16[:]...)},
			},
			wantIP6:  netip.PrefixFrom(addr, 96),
			wantDNS6: []netip.Addr{dns6},
		},
		{
			name: "addr_default_64",
			attrs: []ikemsg.ConfigAttr{
				{Type: ikemsg.ConfigAttrInternalIP6Address, Value: append([]byte(nil), a16[:]...)},
			},
			wantIP6: netip.PrefixFrom(addr, 64),
		},
		{
			name: "invalid_prefix_dropped",
			attrs: []ikemsg.ConfigAttr{
				// prefixlen 200 > 128 → ignored, IP6 stays zero.
				{Type: ikemsg.ConfigAttrInternalIP6Address, Value: append(append([]byte(nil), a16[:]...), 200)},
			},
			wantIP6: netip.Prefix{},
		},
		{
			name: "malformed_length_dropped",
			attrs: []ikemsg.ConfigAttr{
				{Type: ikemsg.ConfigAttrInternalIP6Address, Value: a16[:8]}, // 8 bytes → not a valid v6 addr
			},
			wantIP6: netip.Prefix{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCPReply(&ikemsg.ConfigPayload{CfgType: ikemsg.ConfigReply, Attributes: tc.attrs})
			if got.IP6 != tc.wantIP6 {
				t.Fatalf("IP6 = %v, want %v", got.IP6, tc.wantIP6)
			}
			if len(got.DNS6) != len(tc.wantDNS6) {
				t.Fatalf("DNS6 = %v, want %v", got.DNS6, tc.wantDNS6)
			}
			for i := range tc.wantDNS6 {
				if got.DNS6[i] != tc.wantDNS6[i] {
					t.Fatalf("DNS6[%d] = %v, want %v", i, got.DNS6[i], tc.wantDNS6[i])
				}
			}
		})
	}
}

// TestBuildCPRequestIPv6Gate asserts the IPv6 CFG attributes are present only
// when requestIPv6 is set.
func TestBuildCPRequestIPv6Gate(t *testing.T) {
	hasAttr := func(p ikemsg.Payloads, want ikemsg.ConfigAttrType) bool {
		for _, pl := range p {
			cp, ok := pl.(*ikemsg.ConfigPayload)
			if !ok {
				continue
			}
			for _, attr := range cp.Attributes {
				if attr.Type == want {
					return true
				}
			}
		}
		return false
	}

	var with ikemsg.Payloads
	buildCPRequest(&with, true)
	if !hasAttr(with, ikemsg.ConfigAttrInternalIP6Address) {
		t.Error("requestIPv6=true: missing INTERNAL_IP6_ADDRESS")
	}
	if !hasAttr(with, ikemsg.ConfigAttrInternalIP6DNS) {
		t.Error("requestIPv6=true: missing INTERNAL_IP6_DNS")
	}
	if !hasAttr(with, ikemsg.ConfigAttrInternalIP4Address) {
		t.Error("requestIPv6=true: dropped INTERNAL_IP4_ADDRESS")
	}

	var without ikemsg.Payloads
	buildCPRequest(&without, false)
	if hasAttr(without, ikemsg.ConfigAttrInternalIP6Address) {
		t.Error("requestIPv6=false: unexpected INTERNAL_IP6_ADDRESS")
	}
	if hasAttr(without, ikemsg.ConfigAttrInternalIP6DNS) {
		t.Error("requestIPv6=false: unexpected INTERNAL_IP6_DNS")
	}
}

// TestAppendTrafficSelectorsIPv6Gate asserts the IPv6 full-tunnel selector is
// offered in both TSi and TSr only when includeV6 is set, and the v4 selector is
// always present.
func TestAppendTrafficSelectorsIPv6Gate(t *testing.T) {
	hasType := func(sel []ikemsg.TrafficSelector, want ikemsg.TSType) bool {
		for _, s := range sel {
			if s.TSType == want {
				return true
			}
		}
		return false
	}
	selectors := func(p ikemsg.Payloads) (tsi, tsr []ikemsg.TrafficSelector) {
		for _, pl := range p {
			switch v := pl.(type) {
			case *ikemsg.TSiPayload:
				tsi = v.Selectors
			case *ikemsg.TSrPayload:
				tsr = v.Selectors
			}
		}
		return tsi, tsr
	}

	var with ikemsg.Payloads
	appendTrafficSelectors(&with, true)
	tsi, tsr := selectors(with)
	for _, pair := range []struct {
		name string
		sel  []ikemsg.TrafficSelector
	}{{"TSi", tsi}, {"TSr", tsr}} {
		if !hasType(pair.sel, ikemsg.TSIPv4AddrRange) {
			t.Errorf("includeV6=true: %s missing v4 selector", pair.name)
		}
		if !hasType(pair.sel, ikemsg.TSIPv6AddrRange) {
			t.Errorf("includeV6=true: %s missing v6 selector", pair.name)
		}
	}

	var without ikemsg.Payloads
	appendTrafficSelectors(&without, false)
	tsi, tsr = selectors(without)
	for _, pair := range []struct {
		name string
		sel  []ikemsg.TrafficSelector
	}{{"TSi", tsi}, {"TSr", tsr}} {
		if !hasType(pair.sel, ikemsg.TSIPv4AddrRange) {
			t.Errorf("includeV6=false: %s missing v4 selector", pair.name)
		}
		if hasType(pair.sel, ikemsg.TSIPv6AddrRange) {
			t.Errorf("includeV6=false: %s unexpected v6 selector", pair.name)
		}
	}
}
