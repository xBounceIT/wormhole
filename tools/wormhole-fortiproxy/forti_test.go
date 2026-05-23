package main

import "testing"

// Both FortiGate XML layouts are seen in the wild. A previous parser that bound the
// assigned IP exclusively to the attribute form silently failed on the nested-element
// form (and vice versa), surfacing as "no assigned IPv4 address" even on successful
// logins. Lock both in.
func TestParseTunnelConfigXML_AttributeLayout(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1500" dpd-retry-interval="3">
		<ipv4 assigned-addr="10.212.134.205">
			<dns ip="10.0.0.1"/>
			<dns ip="10.0.0.2"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.212.134.205" {
		t.Errorf("assigned IP: got %q want 10.212.134.205", got.AssignedIP)
	}
	if got.MTU != 1500 {
		t.Errorf("mtu: got %d want 1500", got.MTU)
	}
	if len(got.DNS) != 2 {
		t.Errorf("dns count: got %d want 2", len(got.DNS))
	}
}

func TestParseTunnelConfigXML_NestedElementLayout(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1400">
		<ipv4>
			<assigned-addr ipv4="10.212.134.205"/>
			<dns ip="10.0.0.1"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.212.134.205" {
		t.Errorf("assigned IP: got %q want 10.212.134.205", got.AssignedIP)
	}
	if got.MTU != 1400 {
		t.Errorf("mtu: got %d want 1400", got.MTU)
	}
}

func TestParseTunnelConfigXML_NestedElementAddrAttr(t *testing.T) {
	// Some firmwares use `addr` instead of `ipv4` on the nested element.
	xml := []byte(`<sslvpn-tunnel>
		<ipv4>
			<assigned-addr addr="10.10.10.10"/>
		</ipv4>
	</sslvpn-tunnel>`)
	got, err := parseTunnelConfigXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AssignedIP.String() != "10.10.10.10" {
		t.Errorf("assigned IP: got %q want 10.10.10.10", got.AssignedIP)
	}
	if got.MTU != 1500 {
		t.Errorf("mtu default: got %d want 1500", got.MTU)
	}
}

func TestParseTunnelConfigXML_MissingAddress(t *testing.T) {
	xml := []byte(`<sslvpn-tunnel mtu="1500"><ipv4><dns ip="1.1.1.1"/></ipv4></sslvpn-tunnel>`)
	_, err := parseTunnelConfigXML(xml)
	if err == nil {
		t.Fatal("expected error for missing assigned IP, got nil")
	}
}

func TestStripHostBrackets(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"vpn.example.com", "vpn.example.com"}, // hostname unchanged
		{"10.0.0.1", "10.0.0.1"},               // IPv4 unchanged
		{"[2001:db8::1]", "2001:db8::1"},       // bracketed v6 stripped
		{"[::1]", "::1"},                       // shortest bracketed v6
		{"2001:db8::1", "2001:db8::1"},         // bare v6 unchanged (works with JoinHostPort)
		{"  [::1]  ", "::1"},                   // surrounding whitespace
		{"", ""},                               // empty
		{"[", "["},                             // unmatched bracket: pass-through
		{"]", "]"},
	}
	for _, tc := range cases {
		got := stripHostBrackets(tc.in)
		if got != tc.want {
			t.Errorf("stripHostBrackets(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
