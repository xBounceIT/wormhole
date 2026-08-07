//go:build windows

package main

import (
	"context"
	"net"
	"testing"
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
