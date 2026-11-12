package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type tunnelDNSDialFunc func(context.Context, string, string) (net.Conn, error)

func (f tunnelDNSDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Exercise DNS wire encoding/decoding against an in-memory DNS peer. The
// only way to obtain an answer is the supplied tunnel dialer; no OS DNS is used.
func tunnelDNSPeer(t *testing.T, answer func(string, dnsmessage.Question) dnsmessage.Message) tunnelDNSDialFunc {
	t.Helper()
	return func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" && network != "tcp" {
			t.Errorf("unexpected DNS network %q", network)
		}
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			var size [2]byte
			if _, err := io.ReadFull(peer, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(peer, query); err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(query); err != nil || len(request.Questions) != 1 {
				t.Errorf("DNS request: %v, %v", request, err)
				return
			}
			response := answer(address, request.Questions[0])
			response.ID = request.ID
			response.Response = true
			response.RecursionAvailable = true
			response.Questions = request.Questions
			wire, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
			_, _ = peer.Write(append(size[:], wire...))
		}()
		return client, nil
	}
}

func tunnelDNSAnswer(q dnsmessage.Question) dnsmessage.Message {
	answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}}
	if q.Type == dnsmessage.TypeAAAA {
		answer.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20}}
	} else {
		answer.Body = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 20}}
	}
	return dnsmessage.Message{Answers: []dnsmessage.Resource{answer}}
}

func TestTunnelDNSPublicFallbackForMissingOrInternalOnlyPushedDNS(t *testing.T) {
	for _, primary := range []struct {
		name   string
		lookup func(context.Context, string) ([]string, error)
	}{
		{"missing", nil},
		{"NXDOMAIN", func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}},
		{"REFUSED", func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{Err: "server misbehaving"}
		}},
		{"empty", func(context.Context, string) ([]string, error) { return nil, nil }},
	} {
		t.Run(primary.name, func(t *testing.T) {
			resolver := tunnelDNSResolver{primary: primary.lookup, fallback: true, hasV4: true}
			resolver.tunnel = tunnelDNSPeer(t, func(address string, q dnsmessage.Question) dnsmessage.Message {
				if address != "1.1.1.1:53" || q.Name.String() != "images.example.com." || q.Type != dnsmessage.TypeA {
					t.Errorf("DNS escaped expected tunnel target: %s %v", address, q)
				}
				return tunnelDNSAnswer(q)
			})
			addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com.")
			if err != nil || !reflect.DeepEqual(addrs, []string{"192.0.2.20"}) {
				t.Fatalf("public resource DNS = %v, %v", addrs, err)
			}
		})
	}
}

func TestTunnelDNSPreservesPushedAnswersAndPrivateNames(t *testing.T) {
	primaryErr := errors.New("internal DNS refused")
	for _, test := range []struct {
		name     string
		host     string
		fallback bool
		addrs    []string
		err      error
	}{
		{"split public zone", "images.example.com", true, []string{"10.0.0.20"}, nil},
		{"private", "intranet.corp", true, nil, primaryErr},
		{"disabled", "images.example.com", false, nil, primaryErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := tunnelDNSResolver{fallback: test.fallback, hasV4: true,
				primary: func(_ context.Context, host string) ([]string, error) {
					if host != test.host {
						t.Errorf("primary host = %q", host)
					}
					return test.addrs, test.err
				},
				tunnel: tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) {
					t.Error("unexpected public DNS query")
					return nil, errors.New("unexpected query")
				}),
			}
			addrs, err := resolver.LookupContextHost(context.Background(), test.host)
			if !reflect.DeepEqual(addrs, test.addrs) || !errors.Is(err, test.err) {
				t.Fatalf("lookup = %v, %v", addrs, err)
			}
		})
	}
	for _, host := range []string{"intranet", "intranet.local", "images.example.com"} {
		resolver := tunnelDNSResolver{fallback: host != "images.example.com"}
		if _, err := resolver.LookupContextHost(context.Background(), host); err == nil {
			t.Fatalf("missing private/disabled DNS for %q succeeded", host)
		}
	}
}

func TestTunnelDNSFallsBackWhenPushedAnswersHaveNoRoutableAddress(t *testing.T) {
	for _, test := range []struct {
		name    string
		primary []string
		v6      bool
	}{
		{"IPv4 tunnel", []string{"2001:db8::50"}, false},
		{"IPv6 tunnel", []string{"192.0.2.50"}, true},
		{"IPv4 mapped on IPv6 tunnel", []string{"::ffff:192.0.2.50"}, true},
		{"invalid addresses", []string{"not-an-ip", "fe80::1%eth0"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			queried := false
			resolver := tunnelDNSResolver{fallback: true, hasV4: !test.v6, hasV6: test.v6,
				primary: func(context.Context, string) ([]string, error) { return test.primary, nil },
				tunnel: tunnelDNSPeer(t, func(_ string, q dnsmessage.Question) dnsmessage.Message {
					queried = true
					return tunnelDNSAnswer(q)
				}),
			}
			want := "192.0.2.20"
			if test.v6 {
				want = "2001:db8::14"
			}
			addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com")
			if err != nil || !reflect.DeepEqual(addrs, []string{want}) || !queried {
				t.Fatalf("unusable pushed DNS prevented fallback: %v, %v (public queried=%v)", addrs, err, queried)
			}
		})
	}
}

func TestTunnelDNSKeepsOnlyRoutablePrimaryAnswersWithoutMutatingThem(t *testing.T) {
	for _, test := range []struct {
		name    string
		primary []string
		v6      bool
		want    []string
	}{
		{"IPv4", []string{"2001:db8::50", "10.0.0.20", "invalid"}, false, []string{"10.0.0.20"}},
		{"IPv6", []string{"192.0.2.50", "2001:db8::50"}, true, []string{"2001:db8::50"}},
		{"IPv4 mapped", []string{"::ffff:192.0.2.50"}, false, []string{"::ffff:192.0.2.50"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := append([]string(nil), test.primary...)
			resolver := tunnelDNSResolver{fallback: true, hasV4: !test.v6, hasV6: test.v6,
				primary: func(context.Context, string) ([]string, error) { return test.primary, nil },
				tunnel: tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) {
					t.Error("usable pushed DNS answer sent to public DNS")
					return nil, errors.New("unexpected query")
				}),
			}
			addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com")
			if err != nil || !reflect.DeepEqual(addrs, test.want) || !reflect.DeepEqual(test.primary, original) {
				t.Fatalf("primary address filtering = %v, %v; input = %v", addrs, err, test.primary)
			}
		})
	}
}

func TestTunnelDNSRetriesPublicServerAndMatchesTunnelFamily(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]bool{}
			resolver := tunnelDNSResolver{fallback: true, hasV4: !v6, hasV6: v6}
			resolver.tunnel = tunnelDNSPeer(t, func(address string, q dnsmessage.Question) dnsmessage.Message {
				mu.Lock()
				seen[address] = true
				mu.Unlock()
				if address == "1.1.1.1:53" || address == "[2606:4700:4700::1111]:53" {
					return dnsmessage.Message{Header: dnsmessage.Header{RCode: dnsmessage.RCodeRefused}}
				}
				if v6 && (address != "[2001:4860:4860::8888]:53" || q.Type != dnsmessage.TypeAAAA) ||
					!v6 && (address != "8.8.8.8:53" || q.Type != dnsmessage.TypeA) {
					t.Errorf("wrong family or server: %s %v", address, q)
				}
				return tunnelDNSAnswer(q)
			})
			addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com")
			if err != nil || len(addrs) != 1 || (strings.Contains(addrs[0], ":") != v6) {
				t.Fatalf("lookup = %v, %v", addrs, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 2 {
				t.Fatalf("queried servers = %v", seen)
			}
		})
	}
}

func TestTunnelDNSDualStack(t *testing.T) {
	resolver := tunnelDNSResolver{fallback: true, hasV4: true, hasV6: true}
	resolver.tunnel = tunnelDNSPeer(t, func(_ string, q dnsmessage.Question) dnsmessage.Message { return tunnelDNSAnswer(q) })
	addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("dual stack = %v, %v", addrs, err)
	}
}

func TestTunnelDNSFailsClosedOnTunnelFailure(t *testing.T) {
	primaryErr := errors.New("pushed DNS unavailable")
	tunnelErr := errors.New("VPN disconnected")
	for _, hasFamily := range []bool{false, true} {
		resolver := tunnelDNSResolver{fallback: true, hasV4: hasFamily,
			primary: func(context.Context, string) ([]string, error) { return nil, primaryErr },
			tunnel:  tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, tunnelErr }),
		}
		if addrs, err := resolver.LookupContextHost(context.Background(), "images.example.com"); len(addrs) != 0 || !errors.Is(err, primaryErr) || !strings.Contains(err.Error(), "public tunnel DNS") {
			t.Fatalf("disconnected tunnel = %v, %v", addrs, err)
		}
	}
}

func TestTunnelDNSCancellationAndPrimaryBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := tunnelDNSResolver{fallback: true, hasV4: true}
	if _, err := resolver.LookupContextHost(ctx, "images.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	resolver.primary = func(primaryCtx context.Context, _ string) ([]string, error) {
		deadline, ok := primaryCtx.Deadline()
		if !ok || time.Until(deadline) > 4*time.Second {
			t.Error("primary DNS has no bounded budget")
		}
		cancel()
		return nil, context.Canceled
	}
	if _, err := resolver.LookupContextHost(ctx, "images.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	resolver.primary = nil
	resolver.tunnel = tunnelDNSDialFunc(func(_ context.Context, _, _ string) (net.Conn, error) {
		cancel()
		return nil, context.Canceled
	})
	if _, err := resolver.LookupContextHost(ctx, "images.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestTunnelDNSTimeoutsLeaveTimeForResourceConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	primaryTimedOut := false
	resolver := tunnelDNSResolver{fallback: true, hasV4: true,
		primary: func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			primaryTimedOut = true
			return nil, ctx.Err()
		},
	}
	peer := tunnelDNSPeer(t, func(_ string, q dnsmessage.Question) dnsmessage.Message { return tunnelDNSAnswer(q) })
	resolver.tunnel = tunnelDNSDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "1.1.1.1:53" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return peer(ctx, network, address)
	})
	started := time.Now()
	addrs, err := resolver.LookupContextHost(ctx, "images.example.com")
	if err != nil || len(addrs) != 1 || !primaryTimedOut || time.Since(started) > 8*time.Second {
		t.Fatalf("bounded DNS fallback = %v, %v after %s", addrs, err, time.Since(started))
	}
}

func TestPublicDNSName(t *testing.T) {
	for _, host := range []string{"images.example.com", "cdn.example.co.uk", "IMAGES.EXAMPLE.COM", "d123.cloudfront.net", "assets.github.io", "github.io", "my-host.example.com", "_service.example.com", strings.Repeat("a", 63) + ".com"} {
		if !publicDNSName(host) {
			t.Errorf("public host rejected: %s", host)
		}
	}
	for _, host := range []string{"", "intranet", "printer.local", "vpn.internal", "db.corp", "example.test", "com", "co.uk", "192.0.2.1", "2001:db8::1", "1.0.0.127.in-addr.arpa", "1.ip6.arpa", "service.onion", "token@example.com", "a\nb.example.com", "bücher.de", "foo..com", "-host.example.com", "host-.example.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"} {
		if publicDNSName(host) {
			t.Errorf("private or non-host name accepted: %s", host)
		}
	}
}

func TestTunnelDNSDoesNotQueryPublicResolversForPrivateOrMalformedNames(t *testing.T) {
	resolver := tunnelDNSResolver{fallback: true, hasV4: true,
		tunnel: tunnelDNSDialFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Error("private or malformed name sent to public DNS")
			return nil, errors.New("unexpected query")
		}),
	}
	for _, name := range []string{"intranet", "host.local", "service.onion", "token@example.com", "foo..com", "a\nb.example.com"} {
		if _, err := resolver.LookupContextHost(context.Background(), name); err == nil {
			t.Errorf("lookup %q succeeded", name)
		}
	}
}
