package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestTunnelDialReservesTimeForOtherCDNAddresses(t *testing.T) {
	for _, budget := range []time.Duration{15 * time.Second, time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			attempts := make(chan string, 2)
			stopped := make(chan struct{})
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
					return []string{"192.0.2.1", "192.0.2.2"}, nil
				}},
				tunnel: tunnelDNSDialFunc(func(attemptCtx context.Context, network, address string) (net.Conn, error) {
					attempts <- address
					if network != "tcp" {
						t.Errorf("CDN connection network = %s", network)
						return nil, errors.New("unexpected network")
					}
					if address == "192.0.2.1:443" {
						<-attemptCtx.Done()
						close(stopped)
						return nil, attemptCtx.Err()
					}
					return client, nil
				}),
			}
			conn, err := dialer.DialContext(ctx, "tcp", "cdn.jsdelivr.net:443")
			if err != nil || conn != client {
				t.Fatalf("CDN retry = %v, %v", conn, err)
			}
			select {
			case <-stopped:
			case <-ctx.Done():
				t.Fatal("winning connection did not cancel the unresponsive edge")
			}
			got := []string{<-attempts, <-attempts}
			slices.Sort(got)
			if !reflect.DeepEqual(got, []string{"192.0.2.1:443", "192.0.2.2:443"}) {
				t.Fatalf("CDN attempts = %v", got)
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
	dialer := tunnelDialer{
		resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
			return addresses, nil
		}},
		tunnel: tunnelDNSDialFunc(func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			// A reachable edge takes 250 ms to establish TCP over this VPN. A
			// large answer must not reduce every attempt below that latency.
			ready := time.NewTimer(250 * time.Millisecond)
			defer ready.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready.C:
				client, peer := net.Pipe()
				peer.Close()
				return client, nil
			}
		}),
	}
	conn, err := dialer.DialContext(ctx, "tcp", "cdn.jsdelivr.net:443")
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil {
		t.Fatalf("reachable CDN starved by DNS answer size: conn=%v err=%v", conn, err)
	}
}

func TestTunnelDialReachesLaterCDNAfterSeveralBlackholedAddresses(t *testing.T) {
	addresses := make([]string, 64)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var reached atomic.Bool
	dialer := tunnelDialer{
		resolver: tunnelDNSResolver{hasV4: true, primary: func(context.Context, string) ([]string, error) {
			return addresses, nil
		}},
		tunnel: tunnelDNSDialFunc(func(ctx context.Context, _ string, address string) (net.Conn, error) {
			if address != "192.0.2.5:443" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ready := time.NewTimer(250 * time.Millisecond)
			defer ready.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready.C:
				reached.Store(true)
				client, peer := net.Pipe()
				peer.Close()
				return client, nil
			}
		}),
	}
	conn, err := dialer.DialContext(ctx, "tcp", "cdn.jsdelivr.net:443")
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil || !reached.Load() {
		t.Fatalf("later reachable CDN starved: conn=%v err=%v", conn, err)
	}
}

type observedTunnelConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *observedTunnelConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestTunnelDialClosesLateSuccessWithoutClosingWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	loser := &observedTunnelConn{Conn: first, closed: make(chan struct{})}
	defer loser.Close()
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	winner := &observedTunnelConn{Conn: second, closed: make(chan struct{})}
	defer winner.Close()
	release := make(chan struct{})
	var released sync.Once
	unblock := func() { released.Do(func() { close(release) }) }
	defer unblock()
	dialer := tunnelDialer{tunnel: tunnelDNSDialFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address == "192.0.2.1:443" {
			// Model a success completing concurrently with cancellation. The
			// caller has already selected a different connection when it arrives.
			<-release
			return loser, nil
		}
		return winner, nil
	})}
	conn, err := dialer.dialTargets(ctx, "tcp", []string{"192.0.2.1:443", "192.0.2.2:443"})
	if err != nil || conn != winner {
		t.Fatalf("selected connection = %v, %v", conn, err)
	}
	unblock()
	select {
	case <-loser.closed:
	case <-ctx.Done():
		t.Fatal("late successful connection was leaked")
	}
	select {
	case <-winner.closed:
		t.Fatal("cancelling pending attempts closed the winning connection")
	default:
	}
}

func TestTunnelDialCancellationStopsAllPendingAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 2)
	stopped := make(chan string, 2)
	dialer := tunnelDialer{tunnel: tunnelDNSDialFunc(func(ctx context.Context, _ string, address string) (net.Conn, error) {
		started <- address
		<-ctx.Done()
		stopped <- address
		return nil, ctx.Err()
	})}
	done := make(chan error, 1)
	go func() {
		_, err := dialer.dialTargets(ctx, "tcp", []string{"192.0.2.1:443", "192.0.2.2:443"})
		done <- err
	}()
	watchdog := time.NewTimer(5 * time.Second)
	defer watchdog.Stop()
	for range 2 {
		select {
		case <-started:
		case <-watchdog.C:
			t.Fatal("concurrent connection attempts did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled parallel connections = %v", err)
		}
	case <-watchdog.C:
		t.Fatal("cancelled browser connection did not return")
	}
	for range 2 {
		select {
		case <-stopped:
		case <-watchdog.C:
			t.Fatal("a pending connection outlived cancellation")
		}
	}
}

func TestTunnelDialReturnsErrorWhenOverlappingAttemptsAllFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	failure := errors.New("VPN disconnected")
	lastStarted := make(chan struct{})
	dialer := tunnelDialer{tunnel: tunnelDNSDialFunc(func(ctx context.Context, _ string, address string) (net.Conn, error) {
		if address == "192.0.2.1:443" {
			select {
			case <-lastStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else if address == "192.0.2.3:443" {
			close(lastStarted)
		}
		return nil, failure
	})}
	conn, err := dialer.dialTargets(ctx, "tcp", []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"})
	if conn != nil || !errors.Is(err, failure) {
		t.Fatalf("failed overlapping attempts = %v, %v", conn, err)
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
			attempts := make(chan string, len(addresses))
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			dialer := tunnelDialer{
				resolver: tunnelDNSResolver{hasV4: !v6, hasV6: v6,
					primary: func(context.Context, string) ([]string, error) { return addresses, nil }},
				tunnel: tunnelDNSDialFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
					attempts <- address
					if address == want[0] {
						return nil, errors.New("first CDN edge refused connection")
					}
					return client, nil
				}),
			}
			conn, err := dialer.DialContext(context.Background(), "tcp", "cdn.jsdelivr.net:443")
			var got []string
			for len(attempts) > 0 {
				got = append(got, <-attempts)
			}
			slices.Sort(got)
			if err != nil || conn != client || !reflect.DeepEqual(got, want) {
				t.Fatalf("CDN addresses = %v, %v; attempts = %v", conn, err, got)
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
			var attempts atomic.Int32
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
					attempts.Add(1)
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
			if conn != nil || err == nil || int(attempts.Load()) != wantAttempts {
				t.Fatalf("failed connection = %v, %v; tunnel attempts = %d", conn, err, attempts.Load())
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
