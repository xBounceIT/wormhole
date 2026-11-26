package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestResolveHostV4_NoDnsFailsClosedForHostnames(t *testing.T) {
	d := netstackDialer{}

	addr, err := d.resolveHostV4(context.Background(), "10.0.0.42")
	if err != nil {
		t.Fatalf("IP literal should not need DNS: %v", err)
	}
	if addr != netip.AddrFrom4([4]byte{10, 0, 0, 42}) {
		t.Fatalf("addr: got %v want 10.0.0.42", addr)
	}

	_, err = d.resolveHostV4(context.Background(), "internal.example")
	if err == nil {
		t.Fatal("expected hostname lookup to fail closed when VPN DNS is absent")
	}
	if !strings.Contains(err.Error(), "refusing to use host OS resolver") {
		t.Fatalf("error did not explain fail-closed DNS behavior: %v", err)
	}
}

func TestNewNetstackDialer_IPv6OnlyDnsFailsClosedForHostnames(t *testing.T) {
	d := newNetstackDialer(nil, netip.Addr{}, []netip.Addr{netip.MustParseAddr("fd00::53")})

	_, err := d.resolveHostV4(context.Background(), "internal.example")
	if err == nil {
		t.Fatal("expected hostname lookup to fail closed when VPN DNS has no IPv4 servers")
	}
	if !strings.Contains(err.Error(), "refusing to use host OS resolver") {
		t.Fatalf("error did not explain fail-closed DNS behavior: %v", err)
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

func TestQueryServersUntilAnswerWithTCPFallback_UDPTimeoutThenTCPSuccess(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1")}
	qname := dnsmessage.MustNewName("dyn-ar-cdb01.dynartis.local.")
	want := netip.AddrFrom4([4]byte{10, 155, 50, 99})

	var udpCalls, tcpCalls int
	var udpTimeout time.Duration
	udp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, timeout time.Duration) (netip.Addr, string, error) {
		udpCalls++
		udpTimeout = timeout
		return netip.Addr{}, "", errors.New("DNS read: i/o timeout")
	}
	tcp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		tcpCalls++
		return want, "", nil
	}

	addr, cname, err := queryServersUntilAnswerWithTCPFallback(context.Background(), servers, qname, "dyn-ar-cdb01.dynartis.local", 5*time.Millisecond, udp, tcp)
	if err != nil {
		t.Fatalf("expected TCP fallback to resolve after UDP timeout, got: %v", err)
	}
	if addr != want {
		t.Errorf("addr: got %v want %v", addr, want)
	}
	if cname != "" {
		t.Errorf("unexpected cname %q", cname)
	}
	if udpCalls != 1 || tcpCalls != 1 {
		t.Errorf("calls: udp=%d tcp=%d, want 1/1", udpCalls, tcpCalls)
	}
	if udpTimeout != 5*time.Millisecond {
		t.Errorf("UDP timeout: got %v want %v", udpTimeout, 5*time.Millisecond)
	}
}

func TestQueryServersUntilAnswerWithTCPFallback_TriesHealthyUDPServerBeforeTCP(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1"), netip.MustParseAddr("10.72.0.2")}
	qname := dnsmessage.MustNewName("dyn-ar-cdb01.dynartis.local.")
	want := netip.AddrFrom4([4]byte{10, 155, 50, 99})

	var tcpCalls int
	var udpOrder []netip.Addr
	udp := func(_ context.Context, server netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		udpOrder = append(udpOrder, server)
		if server == servers[0] {
			return netip.Addr{}, "", errors.New("DNS read: i/o timeout")
		}
		return want, "", nil
	}
	tcp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		tcpCalls++
		return netip.Addr{}, "", errors.New("unexpected TCP fallback")
	}

	addr, cname, err := queryServersUntilAnswerWithTCPFallback(context.Background(), servers, qname, "dyn-ar-cdb01.dynartis.local", time.Millisecond, udp, tcp)
	if err != nil {
		t.Fatalf("expected healthy second UDP server to resolve before TCP fallback, got: %v", err)
	}
	if addr != want {
		t.Errorf("addr: got %v want %v", addr, want)
	}
	if cname != "" {
		t.Errorf("unexpected cname %q", cname)
	}
	if tcpCalls != 0 {
		t.Fatalf("TCP fallback should not run before trying later UDP servers; got %d TCP call(s)", tcpCalls)
	}
	if len(udpOrder) != 2 || udpOrder[0] != servers[0] || udpOrder[1] != servers[1] {
		t.Fatalf("UDP order: got %v want %v", udpOrder, servers)
	}
}

func TestQueryServersUntilAnswerWithTCPFallback_TruncatedUDPUsesTCPFallback(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1")}
	qname := dnsmessage.MustNewName("large.dynartis.local.")
	want := netip.AddrFrom4([4]byte{10, 155, 50, 88})

	var tcpCalls int
	udp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		return netip.Addr{}, "", errDNSUDPTruncated
	}
	tcp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		tcpCalls++
		return want, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	addr, cname, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, "large.dynartis.local", 50*time.Millisecond, udp, tcp)
	if err != nil {
		t.Fatalf("expected TCP fallback to resolve after truncated UDP response, got: %v", err)
	}
	if addr != want {
		t.Errorf("addr: got %v want %v", addr, want)
	}
	if cname != "" {
		t.Errorf("unexpected cname %q", cname)
	}
	if tcpCalls != 1 {
		t.Fatalf("truncated UDP response must try TCP fallback once; got %d", tcpCalls)
	}
}

func TestQueryServersUntilAnswerWithTCPFallback_UDPTimeoutAndTCPTimeoutReportsBoth(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1")}
	qname := dnsmessage.MustNewName("dyn-ar-cdb01.dynartis.local.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		return netip.Addr{}, "", errors.New("DNS read: i/o timeout")
	}
	tcp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		cancel()
		return netip.Addr{}, "", errors.New("DNS-TCP read length: i/o timeout")
	}

	_, _, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, "dyn-ar-cdb01.dynartis.local", time.Millisecond, udp, tcp)
	if err == nil {
		t.Fatal("expected an error when both UDP and TCP DNS fail")
	}
	for _, want := range []string{"UDP failed", "DNS read: i/o timeout", "TCP fallback failed", "DNS-TCP read length"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestDNSCancellationStopsBeforeTheNextServer(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	name := dnsmessage.MustNewName("host.example.")
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			negative := &dnsResponseError{errors.New("name does not exist")}
			reject := func(_ context.Context, server netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
				if server != servers[0] {
					t.Fatal("queried another server after cancellation")
				}
				cancel()
				return netip.Addr{}, "", negative
			}
			udp, tcp := reject, reject
			if transport == "tcp" {
				udp = func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
					return netip.Addr{}, "", errDNSUDPTruncated
				}
			}
			_, _, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, name, "host.example", time.Second, udp, tcp)
			if ctx.Err() == nil || !errors.Is(err, negative) {
				t.Fatalf("expected cancellation after the negative response, got %v", err)
			}
		})
	}
}

func TestDNSLookupStopsRetransmittingAtTheCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 3500 * time.Millisecond
		ctx, cancel := context.WithTimeout(t.Context(), budget)
		defer cancel()
		lost := errors.New("DNS transport unavailable")
		attempts := 0
		start := time.Now()
		query := func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
			attempts++
			if attempts > 2 && time.Now().Equal(start) {
				t.Fatal("lookup retried without waiting for a new slot")
			}
			return netip.Addr{}, "", lost
		}
		addr, err := resolveViaVPNQueryWithFallback(ctx, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, "host.example", query, query)
		if addr.IsValid() || !errors.Is(err, lost) {
			t.Fatalf("exhausted lookup returned %v, %v", addr, err)
		}
		if attempts <= 2 || time.Since(start) != budget {
			t.Fatalf("got %d attempts over %s; want retries until %s", attempts, time.Since(start), budget)
		}
	})
}

func TestDNSCancellationInterruptsPendingUDPRead(t *testing.T) {
	s, link, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := queryAOne(ctx, s, netip.MustParseAddr("10.0.0.1"), dnsmessage.MustNewName("host.example."), 5*time.Second)
		result <- err
	}()
	ready, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	packet := link.ReadContext(ready)
	if packet == nil {
		t.Fatal("DNS query never reached the VPN link")
	}
	packet.DecRef()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled lookup returned an answer")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled lookup remained blocked waiting for the DNS server")
	}
}

func TestDNSCancellationInterruptsEstablishedTCPRead(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	defer s.Close()
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddr("127.0.0.1")
	address := tcpip.AddrFrom4(server.As4()).WithPrefix()
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: address}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: address.Subnet(), NIC: 1}})
	listener, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: address.Address, Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := queryAOneTCPByName(ctx, s, server, dnsmessage.MustNewName("host.example."), 5*time.Second)
		result <- err
	}()
	expire := time.AfterFunc(3*time.Second, func() { _ = listener.Close() })
	defer expire.Stop()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled lookup returned an answer")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled lookup remained blocked on the established DNS connection")
	}
}

func TestQueryServersUntilAnswerWithTCPFallback_AuthoritativeNegativeDoesNotTryTCP(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1"), netip.MustParseAddr("10.72.0.2")}
	qname := dnsmessage.MustNewName("nope.dynartis.local.")

	var udpCalls, tcpCalls int
	udp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		udpCalls++
		return netip.Addr{}, "", &dnsResponseError{errors.New("DNS rcode NameError")}
	}
	tcp := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		tcpCalls++
		return netip.Addr{}, "", nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, "nope.dynartis.local", time.Millisecond, udp, tcp)
	if err == nil {
		t.Fatal("expected authoritative negative response to fail")
	}
	if !strings.Contains(err.Error(), "NameError") {
		t.Fatalf("expected NXDOMAIN-style error to surface, got: %v", err)
	}
	if udpCalls != len(servers) {
		t.Fatalf("authoritative negatives triggered %d UDP queries for %d servers", udpCalls, len(servers))
	}
	if tcpCalls != 0 {
		t.Fatalf("authoritative UDP response must not try TCP fallback; got %d TCP call(s)", tcpCalls)
	}
}

// The core regression test for the "RDP through the Forti tunnel randomly won't connect"
// bug: a transport timeout (dropped UDP datagram on the PPP link) must NOT fail the lookup —
// queryServersUntilAnswer has to retransmit until a later attempt gets through.
func TestQueryServersUntilAnswer_RetransmitsPastTransientLoss(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1"), netip.MustParseAddr("10.72.0.2")}
	qname := dnsmessage.MustNewName("dyn-ar-cdb01.dynartis.local.")
	want := netip.AddrFrom4([4]byte{10, 155, 50, 99})

	var calls int
	query := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		calls++
		// Mimic the live log: both servers time out on the first round, then a retransmit
		// lands. Pre-fix (single shot, single pass) this lookup failed outright.
		if calls <= len(servers) {
			return netip.Addr{}, "", errors.New("DNS read: i/o timeout")
		}
		return want, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tcp := func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
		return netip.Addr{}, "", errors.New("DNS TCP timeout")
	}
	addr, cname, err := queryServersUntilAnswerWithTCPFallback(ctx, servers, qname, "dyn-ar-cdb01.dynartis.local", 5*time.Millisecond, query, tcp)
	if err != nil {
		t.Fatalf("expected resolution to survive transient loss, got error: %v", err)
	}
	if cname != "" {
		t.Errorf("unexpected cname %q", cname)
	}
	if addr != want {
		t.Errorf("addr: got %v want %v", addr, want)
	}
	if calls <= len(servers) {
		t.Errorf("expected a retransmit beyond the first round, only %d attempts", calls)
	}
}

func TestResolveViaVPNQuery_FollowsCNAMEChain(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1")}
	want := netip.AddrFrom4([4]byte{10, 155, 50, 7})

	query := func(_ context.Context, _ netip.Addr, qname dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		switch qname.String() {
		case "host.dynartis.local.":
			return netip.Addr{}, "alias.dynartis.local.", nil // CNAME-only
		case "alias.dynartis.local.":
			return want, "", nil // terminal A
		default:
			return netip.Addr{}, "", errors.New("unexpected qname " + qname.String())
		}
	}

	for _, host := range []string{"host.dynartis.local", "host.dynartis.local."} {
		t.Run(host, func(t *testing.T) {
			addr, err := resolveViaVPNQueryWithFallback(t.Context(), servers, host, query, query)
			if err != nil {
				t.Fatalf("expected the CNAME chain to resolve, got: %v", err)
			}
			if addr != want {
				t.Errorf("addr: got %v want %v", addr, want)
			}
		})
	}
}

// A CNAME chain that never reaches an A record must terminate with the hop-cap error rather
// than loop forever.
func TestResolveViaVPNQuery_CNAMELoopBounded(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.72.0.1")}

	var calls int
	query := func(_ context.Context, _ netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		calls++
		return netip.Addr{}, "loop.dynartis.local.", nil // always a CNAME, never an A
	}

	_, err := resolveViaVPNQueryWithFallback(t.Context(), servers, "loop.dynartis.local", query, query)
	if err == nil {
		t.Fatal("expected an error when a CNAME chain never terminates")
	}
	if !strings.Contains(err.Error(), "CNAME chain exceeded") {
		t.Errorf("expected a CNAME-chain-exceeded error, got: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected the hop loop to iterate a bounded number of times, got %d call(s)", calls)
	}
}

func TestNewNetstackValidatesAndBuildsIPv4Stack(t *testing.T) {
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("2001:db8::1")} {
		if stack, endpoint, err := newNetstack(address, 1500); err == nil || stack != nil || endpoint != nil {
			t.Fatalf("newNetstack(%v) = %#v, %#v, %v", address, stack, endpoint, err)
		}
	}
	for _, mtu := range []int{0, fortinetMaxPayloadLen + 100} {
		stack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), mtu)
		if err != nil || stack == nil || endpoint == nil {
			t.Fatalf("newNetstack(mtu=%d) = %#v, %#v, %v", mtu, stack, endpoint, err)
		}
		stack.Close()
	}
}

func TestNetstackDialerRejectsInvalidDialRequests(t *testing.T) {
	dialer := netstackDialer{}
	tests := []struct {
		network string
		address string
		want    string
	}{
		{network: "udp", address: "host:53", want: "unsupported network"},
		{network: "tcp", address: "missing-port", want: "split host:port"},
		{network: "tcp4", address: "host:not-a-port", want: "port"},
		{network: "tcp4", address: "host:0", want: "port"},
		{network: "tcp4", address: "host:65536", want: "port"},
		{network: "tcp", address: "[2001:db8::1]:443", want: "only IPv4"},
		{network: "tcp", address: "internal.example:443", want: "refusing to use host OS resolver"},
	}
	for _, test := range tests {
		if _, err := dialer.DialContext(context.Background(), test.network, test.address); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("DialContext(%q, %q) error = %v", test.network, test.address, err)
		}
	}
}

func TestDNSResponseErrorAndAdapter(t *testing.T) {
	want := errors.New("bad response")
	wrapped := &dnsResponseError{err: want}
	if wrapped.Error() != want.Error() || !errors.Is(wrapped, want) {
		t.Fatalf("dnsResponseError = %v", wrapped)
	}
	addr := netip.MustParseAddr("10.0.0.1")
	got, cname, err := answerOrResponseErr(addr, "alias.example.", nil)
	if err != nil || got != addr || cname != "alias.example." {
		t.Fatalf("answerOrResponseErr success = %v, %q, %v", got, cname, err)
	}
	if _, _, err := answerOrResponseErr(netip.Addr{}, "", want); err == nil || !errors.As(err, &wrapped) {
		t.Fatalf("answerOrResponseErr error = %v", err)
	}
}

func TestPackAQueryProducesStandardAQuestion(t *testing.T) {
	name := dnsmessage.MustNewName("host.example.")
	wire, id, err := packAQuery(name)
	if err != nil || len(wire) == 0 {
		t.Fatalf("packAQuery = %d bytes id=%d error=%v", len(wire), id, err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(wire)
	if err != nil || header.ID != id || !header.RecursionDesired {
		t.Fatalf("query header = %#v, %v", header, err)
	}
	question, err := parser.Question()
	if err != nil || question.Name.String() != name.String() || question.Type != dnsmessage.TypeA {
		t.Fatalf("query question = %#v, %v", question, err)
	}
}

func TestDNSQueriesFailWithinDeadlineWithoutGateway(t *testing.T) {
	stack, _, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	name := dnsmessage.MustNewName("host.example.")
	server := netip.MustParseAddr("10.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := queryAOne(ctx, stack, netip.MustParseAddr("2001:db8::1"), name, time.Millisecond); err == nil {
		t.Fatal("queryAOne accepted an IPv6 DNS server")
	}
	if _, _, err := queryAOneTCPByName(ctx, stack, netip.MustParseAddr("2001:db8::1"), name, time.Millisecond); err == nil {
		t.Fatal("queryAOneTCPByName accepted an IPv6 DNS server")
	}
	if _, _, err := queryAOne(ctx, stack, server, name, 2*time.Millisecond); err == nil {
		t.Fatal("queryAOne unexpectedly resolved without a gateway")
	}
	if _, _, err := queryAOneTCPByName(ctx, stack, server, name, 2*time.Millisecond); err == nil {
		t.Fatal("queryAOneTCPByName unexpectedly resolved without a gateway")
	}
}
