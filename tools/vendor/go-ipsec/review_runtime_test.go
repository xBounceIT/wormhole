package ipsec

import (
	"github.com/n0madic/go-ipsec/internal/dhcp"
	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/session"
	"net/netip"
	"testing"
	"time"
)

func TestDHCPDNSIsUsedByResolverAndCannotBeMutated(t *testing.T) {
	c := newClient(Config{AddressAssignment: 2})
	defer c.Close()
	s := session.New(session.Config{})
	c.session.Store(s)
	dns := netip.MustParseAddr("10.42.0.53")
	lease := &dhcp.Lease{IP: netip.MustParseAddr("10.42.0.9"), DNS: []netip.Addr{dns}, Expires: time.Now().Add(time.Hour)}
	c.dhcpLease.Store(lease)
	got := c.DNS()
	if len(got) != 1 || resolverServer(got, c.DNS6()) != "10.42.0.53:53" {
		t.Fatalf("DHCP DNS ignored: %v", got)
	}
	got[0] = netip.MustParseAddr("192.0.2.53")
	if c.DNS()[0] != dns {
		t.Fatal("DNS getter exposes mutable lease")
	}
	expired := *lease
	expired.Expires = time.Now().Add(-time.Second)
	c.dhcpLease.Store(&expired)
	if len(c.DNS()) != 0 {
		t.Fatal("expired lease retained stale DNS")
	}
	c.dhcpLease.Store(nil)
	if len(c.DNS()) != 0 {
		t.Fatal("missing lease retained stale DNS")
	}
}

func TestLateExpiredPreviousESPDoesNotKillCurrentSA(t *testing.T) {
	key := make([]byte, 32)
	current, err := esp.NewSA(0, 22, 12, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := esp.NewSA(0, 21, 11, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := esp.NewSA(0, 11, 21, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	previous.ConfigurePolicy(true, time.Nanosecond, 0)
	time.Sleep(time.Millisecond)
	if !previous.Expired() {
		t.Fatal("fixture old SA not expired")
	}
	options := DefaultFortinetOptions()
	c := &legacyClient{cfg: Config{FortinetOptions: &options}, sa: current, previousSA: previous, previousUntil: time.Now().Add(time.Minute), failed: make(chan error, 1)}
	packet, err := peer.Encrypt([]byte{0x45, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	c.deliverESP(packet)
	select {
	case err := <-c.failed:
		t.Fatalf("expired previous SA killed fresh keys: %v", err)
	default:
	}
	if _, err := current.Encrypt([]byte{0x45, 1}); err != nil {
		t.Fatal("current SA unusable", err)
	}
	current.ConfigurePolicy(true, time.Nanosecond, 0)
	time.Sleep(time.Millisecond)
	currentPeer, err := esp.NewSA(0, 12, 22, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	packet, err = currentPeer.Encrypt([]byte{0x45, 1})
	if err != nil {
		t.Fatal(err)
	}
	c.deliverESP(packet)
	select {
	case <-c.failed:
	default:
		t.Fatal("expired current SA did not fail closed")
	}
}

func TestScopedLocalIPv6AddressUsesLAN(t *testing.T) {
	if !isLocalLAN(netip.MustParseAddr("fe80::1234%Ethernet"), []netip.Prefix{netip.MustParsePrefix("fe80::/64")}) {
		t.Fatal("scoped IPv6 LAN destination sent into VPN")
	}
}
