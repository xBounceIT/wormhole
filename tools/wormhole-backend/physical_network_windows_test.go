//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsDNSInteropLayouts(t *testing.T) {
	request := dnsQueryRequest{}
	if unsafe.Sizeof(request) != 64 || unsafe.Offsetof(request.QueryName) != 8 ||
		unsafe.Offsetof(request.QueryType) != 16 || unsafe.Offsetof(request.QueryOptions) != 24 ||
		unsafe.Offsetof(request.InterfaceIndex) != 40 ||
		unsafe.Offsetof(request.QueryCompletionCallback) != 48 {
		t.Fatalf("unexpected DNS_QUERY_REQUEST layout: size=%d", unsafe.Sizeof(request))
	}
	result := dnsQueryResult{}
	if unsafe.Sizeof(result) != 32 || unsafe.Offsetof(result.QueryStatus) != 4 ||
		unsafe.Offsetof(result.QueryOptions) != 8 || unsafe.Offsetof(result.QueryRecords) != 16 {
		t.Fatalf("unexpected DNS_QUERY_RESULT layout: size=%d", unsafe.Sizeof(result))
	}
	record := dnsRecordHeader{}
	if unsafe.Offsetof(record.Data) != 32 {
		t.Fatalf("unexpected DNS_RECORD data offset: %d", unsafe.Offsetof(record.Data))
	}
}

func TestPhysicalAdapterOrderingKeepsDisconnectedRecoveryIDs(t *testing.T) {
	candidates := []physicalAdapterCandidate{
		{id: "offline-ethernet", ifType: windows.IF_TYPE_ETHERNET_CSMACD, metric: 1, speed: 10_000},
		{id: "active-wifi", active: true, ifType: windows.IF_TYPE_IEEE80211, metric: 20, speed: 1_000},
		{id: "active-ethernet", active: true, ifType: windows.IF_TYPE_ETHERNET_CSMACD, metric: 20, speed: 100},
	}

	ordered := orderPhysicalAdapterCandidates(candidates)
	if len(ordered) != 3 || ordered[0].id != "active-ethernet" || ordered[1].id != "active-wifi" || ordered[2].id != "offline-ethernet" {
		t.Fatalf("unexpected adapter recovery order: %#v", ordered)
	}
}

func TestResolvePortalLiteralRetainsItsPhysicalAdapterPair(t *testing.T) {
	candidates := []physicalAdapterCandidate{
		{id: "ethernet", active: true, ipv4Index: 4},
		{id: "wifi", active: true, ipv4Index: 7},
	}

	resolved, err := resolvePortalCandidates(context.Background(), "192.0.2.10", candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].adapter.id != "ethernet" || resolved[1].adapter.id != "wifi" ||
		!resolved[0].address.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("unexpected physical DNS candidates: %#v", resolved)
	}
}

func TestPhysicalPortalCandidatesAlternateAddressFamilies(t *testing.T) {
	candidates := []physicalPortalCandidate{
		{address: net.IPAddr{IP: net.ParseIP("192.0.2.1")}},
		{address: net.IPAddr{IP: net.ParseIP("192.0.2.2")}},
		{address: net.IPAddr{IP: net.ParseIP("2001:db8::1")}},
		{address: net.IPAddr{IP: net.ParseIP("2001:db8::2")}},
	}

	ordered := orderPhysicalPortalCandidates(candidates)
	if len(ordered) != 4 || ordered[0].address.IP.To4() == nil || ordered[1].address.IP.To4() != nil ||
		ordered[2].address.IP.To4() == nil || ordered[3].address.IP.To4() != nil {
		t.Fatalf("address families were not alternated: %#v", ordered)
	}
}

func TestPhysicalTransportAdapterIDsRequireActiveNetwork(t *testing.T) {
	previous := physicalAdapterSource
	t.Cleanup(func() { physicalAdapterSource = previous })

	physicalAdapterSource = func(bool) ([]physicalAdapterCandidate, error) {
		return nil, errors.New("enumeration failed")
	}
	if _, err := physicalTransportAdapterIDs(); err == nil {
		t.Fatal("adapter enumeration failure was ignored")
	}

	physicalAdapterSource = func(includeInactive bool) ([]physicalAdapterCandidate, error) {
		if !includeInactive {
			t.Fatal("transport ids did not request recovery adapters")
		}
		return []physicalAdapterCandidate{{id: "offline"}, {id: "up-no-address", active: true}}, nil
	}
	if _, err := physicalTransportAdapterIDs(); err == nil {
		t.Fatal("network without an active IP adapter was accepted")
	}

	physicalAdapterSource = func(bool) ([]physicalAdapterCandidate, error) {
		return []physicalAdapterCandidate{
			{id: "ethernet", active: true, ipv4Index: 4},
			{id: "recovery", active: false, ipv6Index: 8},
		}, nil
	}
	ids, err := physicalTransportAdapterIDs()
	if err != nil || strings.Join(ids, ",") != "ethernet,recovery" {
		t.Fatalf("adapter ids = %#v, %v", ids, err)
	}
}

func TestResolvePortalCandidatesUsesPerAdapterDNSAndDeduplicates(t *testing.T) {
	previous := physicalHostResolver
	t.Cleanup(func() { physicalHostResolver = previous })
	physicalHostResolver = func(_ context.Context, _ string, ipv4, ipv6 uint32) ([]net.IPAddr, error) {
		switch {
		case ipv4 == 4:
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("192.0.2.10")}}, nil
		case ipv6 == 6:
			return []net.IPAddr{{IP: net.ParseIP("2001:db8::10")}}, errors.New("partial DNS failure")
		default:
			return nil, errors.New("unresolved")
		}
	}
	candidates := []physicalAdapterCandidate{
		{id: "ethernet", ipv4Index: 4},
		{id: "wifi", ipv6Index: 6},
	}
	resolved, err := resolvePortalCandidates(context.Background(), "vpn.invalid", candidates)
	if err != nil || len(resolved) != 2 || resolved[0].address.IP.To4() == nil || resolved[1].address.IP.To4() != nil {
		t.Fatalf("resolved candidates = %#v, %v", resolved, err)
	}

	resolverDone := make(chan struct{}, len(candidates))
	physicalHostResolver = func(ctx context.Context, _ string, _, _ uint32) ([]net.IPAddr, error) {
		defer func() { resolverDone <- struct{}{} }()
		<-ctx.Done()
		time.Sleep(25 * time.Millisecond)
		return nil, ctx.Err()
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolvePortalCandidates(cancelled, "vpn.invalid", candidates); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution = %v", err)
	}
	for range candidates {
		<-resolverDone
	}
}

func TestResolvePortalHostQueriesBothAddressFamilies(t *testing.T) {
	previous := physicalDNSQuery
	t.Cleanup(func() { physicalDNSQuery = previous })
	physicalDNSQuery = func(host string, index uint32, recordType uint16) ([]net.IPAddr, error) {
		if host != "vpn.example" || index == 0 {
			t.Fatalf("unexpected DNS query: %q %d %d", host, index, recordType)
		}
		if recordType == dnsTypeA {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.20")}, {IP: net.ParseIP("192.0.2.20")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("2001:db8::20")}}, errors.New("IPv6 warning")
	}
	addresses, err := resolvePortalHostOnInterfaces(context.Background(), "vpn.example", 4, 6)
	if err != nil || len(addresses) != 2 {
		t.Fatalf("DNS addresses = %#v, %v", addresses, err)
	}

	physicalDNSQuery = func(string, uint32, uint16) ([]net.IPAddr, error) {
		return nil, errors.New("DNS failed")
	}
	if _, err := resolvePortalHostOnInterfaces(context.Background(), "vpn.example", 4, 6); err == nil {
		t.Fatal("complete per-interface DNS failure was ignored")
	}
}

func TestPhysicalPortalDialValidationAndInterfaceChanges(t *testing.T) {
	if _, err := physicalPortalDialContext(context.Background(), "tcp", "missing-port"); err == nil {
		t.Fatal("invalid portal address was accepted")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	connection, err := physicalPortalDialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if remote := <-accepted; remote != nil {
		_ = remote.Close()
	}

	if _, err := dialPortalCandidates(context.Background(), "tcp", "443", nil); err == nil {
		t.Fatal("empty portal candidate list was accepted")
	}
	previousCurrent := physicalCurrentAdapter
	t.Cleanup(func() { physicalCurrentAdapter = previousCurrent })
	physicalCurrentAdapter = func(string) (physicalAdapterCandidate, error) {
		return physicalAdapterCandidate{}, errors.New("interface vanished")
	}
	_, err = dialPortalCandidates(context.Background(), "tcp", "443", []physicalPortalCandidate{{
		adapter: physicalAdapterCandidate{id: "ethernet", ipv4Index: 4},
		address: net.IPAddr{IP: net.ParseIP("192.0.2.1")},
	}})
	if err == nil || !strings.Contains(err.Error(), "vanished") {
		t.Fatalf("vanished interface error = %v", err)
	}

	physicalCurrentAdapter = func(string) (physicalAdapterCandidate, error) {
		return physicalAdapterCandidate{id: "ethernet", ipv4Index: 5}, nil
	}
	_, err = dialPortalCandidates(context.Background(), "tcp", "443", []physicalPortalCandidate{{
		adapter: physicalAdapterCandidate{id: "ethernet", ipv4Index: 4},
		address: net.IPAddr{IP: net.ParseIP("192.0.2.1")},
	}})
	if !errors.Is(err, errPhysicalInterfaceChanged) {
		t.Fatalf("changed interface error = %v", err)
	}
}

func TestCurrentPhysicalAdapterAndAddressHelpers(t *testing.T) {
	previous := physicalAdapterSource
	t.Cleanup(func() { physicalAdapterSource = previous })
	physicalAdapterSource = func(includeInactive bool) ([]physicalAdapterCandidate, error) {
		if includeInactive {
			t.Fatal("current lookup included inactive adapters")
		}
		return []physicalAdapterCandidate{{id: "Ethernet", ipv4Index: 4}}, nil
	}
	candidate, err := currentPhysicalAdapter("ethernet")
	if err != nil || candidate.ipv4Index != 4 {
		t.Fatalf("current adapter = %#v, %v", candidate, err)
	}
	if _, err := currentPhysicalAdapter("missing"); err == nil {
		t.Fatal("missing current adapter was accepted")
	}
	physicalAdapterSource = func(bool) ([]physicalAdapterCandidate, error) {
		return nil, errors.New("enumeration failed")
	}
	if _, err := currentPhysicalAdapter("ethernet"); err == nil {
		t.Fatal("current adapter enumeration failure was ignored")
	}

	distinct := distinctIPAddresses([]net.IPAddr{
		{}, {IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("2001:db8::1")},
	})
	if len(distinct) != 2 {
		t.Fatalf("distinct addresses = %#v", distinct)
	}
	if _, err := queryWindowsDNS("bad\x00host", 4, dnsTypeA); err == nil {
		t.Fatal("invalid Windows DNS name was accepted")
	}
}

func TestPhysicalAdapterClassificationAndBounds(t *testing.T) {
	for _, value := range []uint32{
		windows.IF_TYPE_ETHERNET_CSMACD, ifTypeFastEthernetFX, ifTypeFastEthernetT,
		ifTypeGigabitEthernet, windows.IF_TYPE_IEEE80211, ifTypeWWANPP, ifTypeWWANPP2,
	} {
		if !isPhysicalInterfaceType(value) || physicalInterfaceScore(value) == 0 {
			t.Fatalf("physical interface type %d was rejected", value)
		}
	}
	if isPhysicalInterfaceType(9999) || physicalInterfaceScore(9999) != 0 {
		t.Fatal("unknown interface type was accepted")
	}
	for _, name := range []string{"Corporate VPN", "WireGuard Tunnel", "TAP adapter", "Tailscale"} {
		if !isVPNLikeAdapter(name) {
			t.Fatalf("VPN adapter %q was not filtered", name)
		}
	}
	if isVPNLikeAdapter("Intel Ethernet Connection") {
		t.Fatal("physical Ethernet was classified as VPN")
	}

	var candidates []physicalAdapterCandidate
	for index := 0; index < maxPhysicalAdapters+3; index++ {
		candidates = append(candidates, physicalAdapterCandidate{
			id: string(rune('a' + index)), active: true, ifType: windows.IF_TYPE_ETHERNET_CSMACD,
			metric: uint32(index + 1), speed: uint64(index),
		})
	}
	if ordered := orderPhysicalAdapterCandidates(candidates); len(ordered) != maxPhysicalAdapters {
		t.Fatalf("adapter limit = %d", len(ordered))
	}

	var portals []physicalPortalCandidate
	for index := 0; index < maxPhysicalCandidates+5; index++ {
		portals = append(portals, physicalPortalCandidate{address: net.IPAddr{IP: net.ParseIP("192.0.2.1")}})
	}
	if ordered := orderPhysicalPortalCandidates(portals); len(ordered) != maxPhysicalCandidates {
		t.Fatalf("portal candidate limit = %d", len(ordered))
	}
}

func TestPhysicalAdapterEnumerationIsBoundedAndClassified(t *testing.T) {
	for _, includeInactive := range []bool{false, true} {
		candidates, err := physicalAdapterCandidates(includeInactive)
		if err != nil {
			// Enumeration can be unavailable in restricted Windows sandboxes. The call still
			// exercises the production error path without making the suite host-dependent.
			continue
		}
		if len(candidates) > maxPhysicalAdapters {
			t.Fatalf("enumerated %d adapters, limit is %d", len(candidates), maxPhysicalAdapters)
		}
		for _, candidate := range candidates {
			if candidate.id == "" || !isPhysicalInterfaceType(candidate.ifType) ||
				(candidate.ipv4Index == 0 && candidate.ipv6Index == 0) {
				t.Fatalf("invalid physical adapter candidate: %#v", candidate)
			}
			if !includeInactive && !candidate.active {
				t.Fatalf("inactive adapter returned by active-only query: %#v", candidate)
			}
		}
	}
}

func TestPublishPhysicalDialResultClosesLateConnection(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	publishPhysicalDialResult(ctx, make(chan physicalDialResult), physicalDialResult{connection: left})
	_ = right.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := right.Write([]byte("closed")); err == nil {
		t.Fatal("late physical dial connection remained open")
	}
}

type physicalRawConn struct {
	controlErr error
}

func (connection physicalRawConn) Control(callback func(uintptr)) error {
	if connection.controlErr == nil {
		callback(0)
	}
	return connection.controlErr
}
func (physicalRawConn) Read(func(uintptr) bool) error  { return nil }
func (physicalRawConn) Write(func(uintptr) bool) error { return nil }

func TestBindWindowsPhysicalInterfaceReportsControlAndSocketErrors(t *testing.T) {
	controlFailure := errors.New("control failed")
	if err := bindWindowsPhysicalInterface(4, false)("tcp", "", physicalRawConn{controlErr: controlFailure}); !errors.Is(err, controlFailure) {
		t.Fatalf("control failure = %v", err)
	}
	for _, ipv6 := range []bool{false, true} {
		if err := bindWindowsPhysicalInterface(4, ipv6)("tcp", "", physicalRawConn{}); err == nil {
			t.Fatalf("setsockopt on invalid handle succeeded for ipv6=%v", ipv6)
		}
	}
}

var _ syscall.RawConn = physicalRawConn{}
