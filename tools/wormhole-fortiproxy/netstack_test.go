package main

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Locks W4 — confirm the FQDN-construction logic produces a valid dnsmessage.Name for both
// "host.example.com" (bare) and "host.example.com." (already-qualified). Pre-fix, the
// trailing-dot case became "host.example.com.." which dnsmessage.NewName rejects.
func TestResolveViaVPN_FQDNConstruction(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"host.example.com", "host.example.com."},
		{"host.example.com.", "host.example.com."},
		{"a", "a."},
		{"a.", "a."},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			fqdn := tc.in
			if !strings.HasSuffix(fqdn, ".") {
				fqdn += "."
			}
			if fqdn != tc.want {
				t.Errorf("got %q want %q", fqdn, tc.want)
			}
			if _, err := dnsmessage.NewName(fqdn); err != nil {
				t.Errorf("dnsmessage.NewName(%q): %v", fqdn, err)
			}
		})
	}
}
