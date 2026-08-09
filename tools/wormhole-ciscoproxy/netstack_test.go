package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNewNetstackValidatesAndBuildsIPv4Stack(t *testing.T) {
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("2001:db8::1")} {
		if stack, endpoint, err := newNetstack(address, 1500); err == nil || stack != nil || endpoint != nil {
			t.Fatalf("newNetstack(%v) = %#v, %#v, %v", address, stack, endpoint, err)
		}
	}
	for _, mtu := range []int{0, cstpMaxPayloadLen + 100} {
		stack, endpoint, err := newNetstack(netip.MustParseAddr("10.0.0.2"), mtu)
		if err != nil || stack == nil || endpoint == nil {
			t.Fatalf("newNetstack(mtu=%d) = %#v, %#v, %v", mtu, stack, endpoint, err)
		}
		stack.Close()
	}
}

func TestNewNetstackDialerFiltersDNS(t *testing.T) {
	assigned := netip.MustParseAddr("10.0.0.2")
	if got := newNetstackDialer(nil, assigned, nil); len(got.dnsServers) != 0 || got.assignedIP != assigned {
		t.Fatalf("empty dialer = %#v", got)
	}
	if got := newNetstackDialer(nil, assigned, []netip.Addr{netip.MustParseAddr("2001:db8::53")}); len(got.dnsServers) != 0 {
		t.Fatalf("IPv6 DNS was retained: %#v", got.dnsServers)
	}
	got := newNetstackDialer(nil, assigned, []netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("10.0.0.53")})
	if len(got.dnsServers) != 1 || got.dnsServers[0].String() != "10.0.0.53" {
		t.Fatalf("filtered DNS = %#v", got.dnsServers)
	}
}

func TestNetstackDialerValidatesRequests(t *testing.T) {
	dialer := netstackDialer{}
	addr, err := dialer.resolveHostV4(context.Background(), "10.0.0.42")
	if err != nil || addr.String() != "10.0.0.42" {
		t.Fatalf("literal = %v, %v", addr, err)
	}
	for _, test := range []struct {
		network string
		address string
		want    string
	}{
		{network: "udp", address: "host:53", want: "unsupported network"},
		{network: "tcp", address: "missing-port", want: "split host:port"},
		{network: "tcp4", address: "host:not-a-port", want: "port"},
		{network: "tcp", address: "[2001:db8::1]:443", want: "only IPv4"},
		{network: "tcp", address: "internal.example:443", want: "refusing to use host OS resolver"},
	} {
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
		t.Fatalf("adapter success = %v, %q, %v", got, cname, err)
	}
	var responseError *dnsResponseError
	if _, _, err := answerOrResponseErr(netip.Addr{}, "", want); err == nil || !errors.As(err, &responseError) {
		t.Fatalf("adapter error = %v", err)
	}
}

func TestResolveViaVPNQueryFollowsCNAMEAndReturnsAddress(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	want := netip.MustParseAddr("10.0.0.42")
	calls := 0
	query := func(_ context.Context, _ netip.Addr, name dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		calls++
		if name.String() == "host.example." {
			return netip.Addr{}, "alias.example.", nil
		}
		return want, "", nil
	}
	got, err := resolveViaVPNQuery(context.Background(), servers, "host.example", query)
	if err != nil || got != want || calls != 2 {
		t.Fatalf("resolveViaVPNQuery = %v, %v after %d calls", got, err, calls)
	}
}

func TestResolveViaVPNQueryValidatesOutcomes(t *testing.T) {
	server := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	tests := []struct {
		name  string
		host  string
		query dnsQueryFunc
		want  string
	}{
		{name: "invalid name", host: strings.Repeat("abcd.", 70), query: func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
			return netip.Addr{}, "", nil
		}, want: "DNS name"},
		{name: "query error", host: "host", query: func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
			return netip.Addr{}, "", &dnsResponseError{errors.New("rejected")}
		}, want: "rejected"},
		{name: "no records", host: "host", query: func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
			return netip.Addr{}, "", nil
		}, want: "no A or CNAME"},
		{name: "CNAME loop", host: "host", query: func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
			return netip.Addr{}, "host.", nil
		}, want: "CNAME chain exceeded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := resolveViaVPNQuery(context.Background(), server, test.host, test.query); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestQueryServersUntilAnswerHandlesSuccessLossAndResponseErrors(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	name := dnsmessage.MustNewName("host.example.")
	want := netip.MustParseAddr("10.0.0.42")
	calls := 0
	query := func(_ context.Context, server netip.Addr, _ dnsmessage.Name, _ time.Duration) (netip.Addr, string, error) {
		calls++
		if server == servers[0] {
			return netip.Addr{}, "", errors.New("timeout")
		}
		return want, "", nil
	}
	got, _, err := queryServersUntilAnswer(context.Background(), servers, name, "host", time.Millisecond, query)
	if err != nil || got != want || calls != 2 {
		t.Fatalf("queryServersUntilAnswer = %v, %v after %d", got, err, calls)
	}

	calls = 0
	query = func(context.Context, netip.Addr, dnsmessage.Name, time.Duration) (netip.Addr, string, error) {
		calls++
		return netip.Addr{}, "", &dnsResponseError{errors.New("NXDOMAIN")}
	}
	if _, _, err := queryServersUntilAnswer(context.Background(), servers, name, "host", time.Millisecond, query); err == nil || calls != len(servers) {
		t.Fatalf("authoritative errors = %v after %d calls", err, calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := queryServersUntilAnswer(ctx, nil, name, "host", time.Millisecond, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query error = %v", err)
	}
	if _, _, err := queryServersUntilAnswer(context.Background(), nil, name, "host", time.Millisecond, query); err == nil || !strings.Contains(err.Error(), "no DNS servers") {
		t.Fatalf("empty server error = %v", err)
	}
}

func TestQueryAOneFailsWithinDeadlineWithoutGateway(t *testing.T) {
	stack, _, err := newNetstack(netip.MustParseAddr("10.0.0.2"), 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	name := dnsmessage.MustNewName("host.example.")
	if _, _, err := queryAOne(context.Background(), stack, netip.MustParseAddr("2001:db8::1"), name, time.Millisecond); err == nil {
		t.Fatal("queryAOne accepted IPv6 DNS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := queryAOne(ctx, stack, netip.MustParseAddr("10.0.0.1"), name, 2*time.Millisecond); err == nil {
		t.Fatal("queryAOne unexpectedly resolved")
	}
	if _, _, err := queryAOneTCP(ctx, stack, netip.MustParseAddr("10.0.0.1"), []byte{1, 2}, 1, 2*time.Millisecond); err == nil {
		t.Fatal("queryAOneTCP unexpectedly resolved")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := resolveViaVPN(cancelled, stack, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, "host.example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolveViaVPN cancellation = %v", err)
	}
}

func TestParseDNSResponseVariants(t *testing.T) {
	name := dnsmessage.MustNewName("host.example.")
	alias := dnsmessage.MustNewName("alias.example.")
	pack := func(id uint16, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
		message := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, Response: true, RCode: rcode},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers:   answers,
		}
		wire, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	aRecord := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 42}}}
	cnameRecord := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}
	txtRecord := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{"text"}}}
	if addr, _, err := parseDNSResponse(pack(1, dnsmessage.RCodeSuccess, []dnsmessage.Resource{aRecord}), 1); err != nil || addr.String() != "10.0.0.42" {
		t.Fatalf("A response = %v, %v", addr, err)
	}
	if _, cname, err := parseDNSResponse(pack(2, dnsmessage.RCodeSuccess, []dnsmessage.Resource{cnameRecord}), 2); err != nil || cname != "alias.example." {
		t.Fatalf("CNAME response = %q, %v", cname, err)
	}
	for _, test := range []struct {
		packet []byte
		id     uint16
	}{
		{packet: nil, id: 1},
		{packet: pack(3, dnsmessage.RCodeSuccess, []dnsmessage.Resource{aRecord}), id: 4},
		{packet: pack(5, dnsmessage.RCodeNameError, nil), id: 5},
		{packet: pack(6, dnsmessage.RCodeSuccess, []dnsmessage.Resource{txtRecord}), id: 6},
	} {
		if _, _, err := parseDNSResponse(test.packet, test.id); err == nil {
			t.Fatalf("invalid DNS response was accepted: %x", test.packet)
		}
	}
}
