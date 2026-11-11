package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type lanTestClient struct {
	dials   int
	closed  bool
	resolve *net.Resolver
}

func (c *lanTestClient) DialContext(context.Context, string, string) (net.Conn, error) {
	c.dials++
	return nil, errors.New("VPN unavailable")
}
func (c *lanTestClient) Resolver(string) *net.Resolver { return c.resolve }
func (c *lanTestClient) Close() error                  { c.closed = true; return nil }
func TestLocalLANIsExplicitAndCloses(t *testing.T) {
	inner := &lanTestClient{}
	if withLocalLAN(inner, false) != inner {
		t.Fatal("disabled LAN changed client")
	}
	c := withLocalLAN(inner, true).(*localLANClient)
	defer c.Close()
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.168.9.0/24")}
	c.prefixes = func() ([]netip.Prefix, error) { return prefixes, nil }
	directs := 0
	var peers []net.Conn
	c.direct = func(context.Context, string, string) (net.Conn, error) {
		directs++
		a, b := net.Pipe()
		peers = append(peers, b)
		return a, nil
	}
	for _, host := range []string{"8.8.8.8:53", "192.168.8.9:80", "127.0.0.1:80", "[::1]:80"} {
		if _, err := c.DialContext(context.Background(), "tcp", host); err == nil {
			t.Fatal("VPN failure hidden")
		}
	}
	if directs != 0 || inner.dials != 4 {
		t.Fatal("VPN failure used direct route")
	}
	conn, err := c.DialContext(context.Background(), "tcp", "192.168.9.42:80")
	if err != nil || directs != 1 {
		t.Fatal(err)
	}
	prefixes = nil
	if _, err = c.DialContext(context.Background(), "tcp", "192.168.9.42:80"); err == nil || directs != 1 {
		t.Fatal("stale LAN bypass retained")
	}
	c.prefixes = func() ([]netip.Prefix, error) { return nil, errors.New("interfaces") }
	if _, err = c.DialContext(context.Background(), "tcp", "8.8.8.8:80"); err == nil {
		t.Fatal("interface inspection failure ignored")
	}
	if _, err = c.DialContext(context.Background(), "tcp", "invalid"); err == nil {
		t.Fatal("bad destination accepted")
	}
	if err = c.Close(); err != nil || !inner.closed {
		t.Fatal(err)
	}
	_ = peers[0].SetReadDeadline(time.Now().Add(time.Second))
	if _, err = peers[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("LAN socket survived VPN close")
	}
	conn.Close()
	peers[0].Close()
	if _, err = c.DialContext(context.Background(), "tcp", "192.168.9.42:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed VPN allowed LAN dial")
	}
	c.Close()
}
func TestLANPrefixPolicy(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "127.0.0.0/8", "224.0.0.0/4", "::/0", "::1/128", "ff00::/8"} {
		if validLANPrefix(netip.MustParsePrefix(prefix)) {
			t.Fatal("unsafe LAN prefix", prefix)
		}
	}
	if validLANPrefix(netip.Prefix{}) {
		t.Fatal("empty prefix accepted")
	}
	if !isLocalLAN(netip.MustParseAddr("::ffff:192.168.1.9"), []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}) || !isLocalLAN(netip.MustParseAddr("fd00::9"), []netip.Prefix{netip.MustParsePrefix("fd00::/64")}) {
		t.Fatal("connected LAN address missed")
	}
	if isLocalLAN(netip.Addr{}, nil) {
		t.Fatal("invalid address accepted")
	}
	if prefixes, err := connectedLANs(); err == nil {
		for _, p := range prefixes {
			if !validLANPrefix(p) {
				t.Fatal("interface yielded unsafe prefix")
			}
		}
	}
}
