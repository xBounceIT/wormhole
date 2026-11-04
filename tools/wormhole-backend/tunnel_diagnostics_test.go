package main

import (
	"strings"
	"sync"
	"testing"
)

func TestBoundedStderrRetainsTailAndAcceptsEveryByte(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 8, 4096} {
		builder := &boundedStderrBuilder{limit: limit}
		var all string
		for _, chunk := range []string{"", "abc", "defg", "hi", "\x00\xff€", strings.Repeat("z", 9000), "AUTH_FAILED\n", ""} {
			n, err := builder.Write([]byte(chunk))
			if n != len(chunk) || err != nil {
				t.Fatalf("limit %d: Write returned %d, %v", limit, n, err)
			}
			all += chunk
			want := all
			if limit <= 0 {
				want = ""
			} else if len(want) > limit {
				want = want[len(want)-limit:]
			}
			if got := builder.text(); got != want {
				t.Fatalf("limit %d: retained %q, want %q", limit, got, want)
			}
			if limit > 0 && cap(builder.tail) > limit {
				t.Fatalf("buffer capacity exceeded limit: %d > %d", cap(builder.tail), limit)
			}
		}
	}
}

func TestBoundedStderrConcurrentSnapshots(t *testing.T) {
	builder := &boundedStderrBuilder{limit: 64}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for j := 0; j < 100; j++ {
				builder.Write([]byte("diagnostic\n"))
				if len(builder.text()) > builder.limit {
					t.Error("snapshot exceeded limit")
				}
			}
		})
	}
	workers.Wait()
}

func TestTunnelSidecarOpenVPNAuthenticationFailureIsSafe(t *testing.T) {
	t.Setenv("WORMHOLE_TUNNEL_DEBUG", "")
	for _, diagnostic := range []string{"AUTH_FAILED", "auth failed", "AUTH_FAILED: session=fixture-secret"} {
		err := tunnelSidecarFailureMessage("wormhole-ovpnproxy", diagnostic, 1)
		if !strings.Contains(err.Error(), "rejected the username") || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatalf("unclassified or unsafe authentication failure: %v", err)
		}
	}
}

func TestTunnelSidecarDebugNeverExposesUntrustedDiagnostics(t *testing.T) {
	for _, debug := range []string{"", "0", "1", "true"} {
		t.Run(debug, func(t *testing.T) {
			t.Setenv("WORMHOLE_TUNNEL_DEBUG", debug)
			for _, diagnostic := range []string{
				"AUTH_FAILED: session=fixture-secret",
				"unknown failure Cookie: fixture-secret",
				strings.Repeat("x", 9000) + "\nprivate-key=fixture-secret",
				"",
			} {
				err := tunnelSidecarFailureMessage("wormhole-ovpnproxy", diagnostic, 2)
				if err == nil || strings.Contains(err.Error(), "fixture-secret") || strings.Contains(err.Error(), "xxxxxxxx") {
					t.Fatalf("raw diagnostics exposed with debug=%q: %v", debug, err)
				}
			}
		})
	}
}
