package main

import (
	"net/netip"
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

// Locks W15 — parseDNSResponse must return the first A record when present, fall back to
// the first CNAME otherwise, and error out only when neither is in the answer section.
// Before W15 the resolver returned "no A records" the moment a recursive resolver answered
// with a CNAME-only packet, which broke real-world internal names that legitimately resolve
// via a CNAME chain.
func TestParseDNSResponse_PrefersAOverCNAME(t *testing.T) {
	// Build a packet with one CNAME (host.example.com. → alias.example.com.) and one A
	// (10.0.0.42). The A must win.
	name := dnsmessage.MustNewName("host.example.com.")
	target := dnsmessage.MustNewName("alias.example.com.")

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.CNAMEResource{CNAME: target},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 42}},
			},
		},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	addr, cname, err := parseDNSResponse(wire, 0x1234)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if cname != "" {
		t.Errorf("expected empty cname when A is present, got %q", cname)
	}
	if addr != netip.AddrFrom4([4]byte{10, 0, 0, 42}) {
		t.Errorf("addr: got %v want 10.0.0.42", addr)
	}
}

func TestParseDNSResponse_FallsBackToCNAME(t *testing.T) {
	// CNAME-only response — common for recursive resolvers that don't inline the final A,
	// or for chains whose terminal A spilled to a separate packet. resolveViaVPN's outer
	// loop relies on this fallback to follow the chain.
	name := dnsmessage.MustNewName("host.example.com.")
	target := dnsmessage.MustNewName("alias.example.com.")

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0xBEEF, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.CNAMEResource{CNAME: target},
			},
		},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	addr, cname, err := parseDNSResponse(wire, 0xBEEF)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if addr.IsValid() {
		t.Errorf("expected zero addr in CNAME-only case, got %v", addr)
	}
	if cname != "alias.example.com." {
		t.Errorf("cname: got %q want alias.example.com.", cname)
	}
}

func TestParseDNSResponse_NeitherAOrCNAME(t *testing.T) {
	// Answer section with only an unrelated record type (TXT) — must error, not silently
	// return a zero addr with no cname (which would loop forever in resolveViaVPN).
	name := dnsmessage.MustNewName("host.example.com.")
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0xCAFE, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: []string{"hello"}},
			},
		},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	_, _, err = parseDNSResponse(wire, 0xCAFE)
	if err == nil {
		t.Fatal("expected error for answer with neither A nor CNAME, got nil")
	}
}

func TestParseDNSResponse_TxidMismatch(t *testing.T) {
	// Cross-contamination guard: if the response's transaction ID doesn't match our query
	// (concurrent lookups, late reply from a previous query, hostile spoof), reject it
	// rather than blindly using the A record from it.
	name := dnsmessage.MustNewName("host.example.com.")
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1111, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
			},
		},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	_, _, err = parseDNSResponse(wire, 0x2222)
	if err == nil {
		t.Fatal("expected error on txid mismatch, got nil")
	}
}
