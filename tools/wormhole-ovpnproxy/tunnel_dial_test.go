package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestTunnelDialReservesTimeForOtherCDNAddresses(t *testing.T) {
	for _, budget := range []time.Duration{15 * time.Second, time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			deadline, _ := ctx.Deadline()
			var attempts []string
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
					return []string{"192.0.2.1", "192.0.2.2"}, nil
				}},
				tunnel: tunnelDNSDialFunc(func(attemptCtx context.Context, network, address string) (net.Conn, error) {
					attempts = append(attempts, address)
					if network != "tcp" {
						t.Fatalf("CDN connection network = %s", network)
					}
					if address == "192.0.2.1:443" {
						// Model a blackholed CDN edge. It must time out before the overall
						// SOCKS deadline, leaving another address a chance to connect.
						attemptDeadline, ok := attemptCtx.Deadline()
						if !ok || !attemptDeadline.Before(deadline) {
							t.Fatal("first CDN address can consume the entire connection timeout")
						}
						return nil, context.DeadlineExceeded
					}
					return client, nil
				}),
			}
			conn, err := dialer.DialContext(ctx, "tcp", "cdn.jsdelivr.net:443")
			if err != nil || conn != client || !reflect.DeepEqual(attempts, []string{"192.0.2.1:443", "192.0.2.2:443"}) {
				t.Fatalf("CDN retry = %v, %v; attempts = %v", conn, err, attempts)
			}
			if ctx.Err() != nil {
				t.Fatalf("address timeout cancelled the browser connection: %v", ctx.Err())
			}
		})
	}
}

func TestTunnelDialDoesNotStarveReachableCDNWithLargeDNSAnswer(t *testing.T) {
	addresses := make([]string, 64)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	attempts := 0
	dialer := tunnelDialer{
		resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
			return addresses, nil
		}},
		tunnel: tunnelDNSDialFunc(func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			attempts++
			// A reachable edge takes 250 ms to establish TCP over this VPN. A
			// large answer must not reduce every attempt below that latency.
			ready := time.NewTimer(250 * time.Millisecond)
			defer ready.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready.C:
				return client, nil
			}
		}),
	}
	conn, err := dialer.DialContext(ctx, "tcp", "cdn.jsdelivr.net:443")
	if err != nil || conn != client || attempts != 1 {
		t.Fatalf("reachable CDN starved by DNS answer size: conn=%v err=%v attempts=%d", conn, err, attempts)
	}
}

func TestTunnelDialLiteralAddressesUseOnlyTheInstalledFamily(t *testing.T) {
	for _, test := range []struct {
		address string
		v4, v6  bool
		want    string
	}{
		{"192.0.2.20:443", true, false, "192.0.2.20:443"},
		{"[2001:db8::20]:443", false, true, "[2001:db8::20]:443"},
		{"[::ffff:192.0.2.20]:443", true, false, "192.0.2.20:443"},
		{"192.0.2.20:443", false, true, ""},
		{"[2001:db8::20]:443", true, false, ""},
		{"[::ffff:192.0.2.20]:443", false, true, ""},
	} {
		t.Run(test.address+test.want, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			called := false
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: test.v4, hasV6: test.v6,
					primary: func(context.Context, string) ([]string, error) {
						t.Fatal("IP literal used DNS")
						return nil, nil
					}},
				tunnel: tunnelDNSDialFunc(func(_ context.Context, network, address string) (net.Conn, error) {
					called = true
					if network != "tcp" || address != test.want {
						t.Fatalf("literal connection = %s %s", network, address)
					}
					return client, nil
				}),
			}
			conn, err := dialer.DialContext(context.Background(), "tcp", test.address)
			if test.want == "" {
				if err == nil || conn != nil || called {
					t.Fatalf("unsupported address used tunnel: %v, %v", conn, err)
				}
			} else if err != nil || conn != client || !called {
				t.Fatalf("literal connection = %v, %v", conn, err)
			}
		})
	}
}

func TestTunnelDialRetriesUniqueSupportedAddresses(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			addresses := []string{"invalid", "2001:db8::1", "192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2", "2001:db8::2"}
			want := []string{"192.0.2.1:443", "192.0.2.2:443"}
			if v6 {
				want = []string{"[2001:db8::1]:443", "[2001:db8::2]:443"}
			}
			var attempts []string
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: !v6, hasV6: v6,
					primary: func(context.Context, string) ([]string, error) { return addresses, nil }},
				tunnel: tunnelDNSDialFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
					attempts = append(attempts, address)
					if len(attempts) == 1 {
						return nil, errors.New("first CDN edge refused connection")
					}
					return client, nil
				}),
			}
			conn, err := dialer.DialContext(context.Background(), "tcp", "cdn.jsdelivr.net:443")
			if err != nil || conn != client || !reflect.DeepEqual(attempts, want) {
				t.Fatalf("CDN addresses = %v, %v; attempts = %v", conn, err, attempts)
			}
		})
	}
}

func TestTunnelDialFailureAndCancellationNeverUseAnotherRoute(t *testing.T) {
	failure := errors.New("VPN disconnected")
	for _, scenario := range []string{"invalid endpoint", "DNS failure", "cancelled before DNS", "cancelled during connect", "all addresses fail"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled before DNS" {
				cancel()
			}
			attempts := 0
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
					if scenario == "cancelled before DNS" || scenario == "invalid endpoint" {
						t.Fatal("invalid/cancelled connection performed DNS")
					}
					if scenario == "DNS failure" {
						return nil, failure
					}
					return []string{"192.0.2.1", "192.0.2.2"}, nil
				}},
				tunnel: tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) {
					attempts++
					if scenario == "cancelled during connect" {
						cancel()
					}
					return nil, failure
				}),
			}
			address := "cdn.jsdelivr.net:443"
			if scenario == "invalid endpoint" {
				address = "not-an-endpoint"
			}
			conn, err := dialer.DialContext(ctx, "tcp", address)
			wantAttempts := 0
			switch scenario {
			case "cancelled before DNS", "cancelled during connect":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled connection = %v", err)
				}
				if scenario == "cancelled during connect" {
					wantAttempts = 1
				}
			case "DNS failure", "all addresses fail":
				if !errors.Is(err, failure) {
					t.Fatalf("lost tunnel error: %v", err)
				}
				if scenario == "all addresses fail" {
					wantAttempts = 2
				}
			}
			if conn != nil || err == nil || attempts != wantAttempts {
				t.Fatalf("failed connection = %v, %v; tunnel attempts = %d", conn, err, attempts)
			}
		})
	}
}

func TestTunnelDialRejectsMappedIPv4FromPublicAAAAOnIPv6Tunnel(t *testing.T) {
	resolver := tunnelDNSResolver{fallback: true, hasV6: true}
	resolver.tunnel = tunnelDNSPeer(t, func(_ string, q dnsmessage.Question) dnsmessage.Message {
		response := tunnelDNSAnswer(q)
		var mapped [16]byte
		copy(mapped[:], net.ParseIP("::ffff:192.0.2.20").To16())
		response.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: mapped}
		return response
	})
	dialer := tunnelDialer{resolver: resolver, tunnel: tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("IPv6 tunnel attempted mapped IPv4 address")
		return nil, nil
	})}
	conn, err := dialer.DialContext(context.Background(), "tcp", "cdn.jsdelivr.net:443")
	if conn != nil || err == nil || !strings.Contains(err.Error(), "no addresses of installed family") {
		t.Fatalf("mapped AAAA connection = %v, %v", conn, err)
	}
}
