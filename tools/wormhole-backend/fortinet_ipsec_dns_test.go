package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestFortinetIPsecManualDNSFamily(t *testing.T) {
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
				settings := ipsecTestSettings()
				settings["IkeVersion"], settings["UserAuth"], settings["AddressAssignment"], settings["ManualAddress"], settings["ManualDns"] = version, 0, 1, "10.1.0.2", tc.dns
				check := func() error {
					raw, _ := json.Marshal(settings)
					var values map[string]json.RawMessage
					if err := json.Unmarshal(raw, &values); err != nil {
						t.Fatal(err)
					}
					return validateFortinetIPsecSettings(values)
				}
				if err := check(); (err == nil) != tc.valid {
					t.Fatalf("accepted=%v, want %v", err == nil, tc.valid)
				}
				for _, mode := range []int{0, 2} {
					settings["AddressAssignment"], settings["ManualDns"] = mode, "2001:db8::53"
					if err := check(); err != nil {
						t.Fatal("ignored manual DNS rejected", err)
					}
				}
			})
		}
	}
}
