package ipsec

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestFortinetManualDNSAddressFamily(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, tc := range []struct {
			dns   string
			valid bool
		}{
			{"", true}, {"10.1.0.53", true}, {"10.1.0.53, 10.2.0.53", true},
			{"2001:db8::53", false}, {"10.1.0.53,2001:db8::53", false},
			{"::ffff:10.1.0.53", false}, {"fe80::1%eth0", false}, {"invalid", false}, {"10.1.0.53,", false},
		} {
			t.Run(fmt.Sprintf("IKEv%d/%s", version, tc.dns), func(t *testing.T) {
				o := DefaultFortinetOptions()
				o.IkeVersion, o.AddressAssignment, o.ManualAddress, o.ManualDns = version, 1, "10.1.0.2", tc.dns
				_, err := ConfigureFortinet(Config{PSK: "secret"}, o, "", "", "")
				if (err == nil) != tc.valid {
					t.Fatalf("accepted=%v, want %v", err == nil, tc.valid)
				}
			})
		}
		for _, address := range []string{"invalid", "2001:db8::1", "::ffff:10.1.0.2"} {
			o := DefaultFortinetOptions()
			o.IkeVersion, o.AddressAssignment, o.ManualAddress = version, 1, address
			if _, err := ConfigureFortinet(Config{}, o, "", "", ""); err == nil {
				t.Fatal("accepted invalid manual IPv4 address")
			}
		}
		// Stale manual DNS is ignored in modes that negotiate their own servers.
		for _, mode := range []int{0, 2} {
			o := DefaultFortinetOptions()
			o.IkeVersion, o.AddressAssignment, o.ManualDns = version, mode, "2001:db8::53"
			if _, err := ConfigureFortinet(Config{}, o, "", "", ""); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestLegacyRemoteIdentityTranslation(t *testing.T) {
	gateway, natPort, _, _, _ := legacyTestGateway(t)
	o := DefaultFortinetOptions()
	o.IkeVersion, o.ExchangeMode = 1, 1
	o.DhGroups = "14"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	id := IPv4(netip.MustParseAddr("127.0.0.1"))
	c, err := dialLegacy(ctx, Config{Server: gateway, NATTPort: natPort, PSK: "legacy-secret", RemoteID: id, FortinetOptions: &o})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.controlConfig.RemoteIDType != uint8(id.Kind) || string(c.controlConfig.RemoteIDData) != string(id.Data) {
		t.Fatal("identity lost its wire type or bytes")
	}
	id.Data[0] = 99
	if c.controlConfig.RemoteIDData[0] != 127 {
		t.Fatal("session retained mutable caller identity")
	}
	if _, err := dialLegacy(ctx, Config{RemoteID: FQDN(""), FortinetOptions: &o}); err == nil {
		t.Fatal("accepted malformed configured identity")
	}
}
