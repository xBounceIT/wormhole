package main

import (
	"context"
	"errors"
	"testing"
)

func TestSSLFallbackPreservesCancellation(t *testing.T) {
	for _, prompt := range []bool{false, true} {
		t.Run(map[bool]string{false: "context", true: "prompt"}[prompt], func(t *testing.T) {
			snapshot, _ := fallbackFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cancelled := errors.New("VPN authentication was cancelled")
			snapshot.prompt = func(context.Context, tunnelPrompt) (string, error) { return "", cancelled }
			calls := 0
			_, err := startTunnelWithFallback(ctx, snapshot, func(ctx context.Context, s tunnelConfigSnapshot) (*tunnelProcess, error) {
				calls++
				if calls == 1 {
					return nil, errors.New("IPsec unavailable")
				}
				if prompt {
					_, err := s.prompt(ctx, tunnelPrompt{})
					return nil, err
				}
				cancel()
				return nil, ctx.Err()
			})
			if calls != 2 {
				t.Fatal("did not reach SSL fallback")
			}
			if prompt {
				if !errors.Is(err, cancelled) {
					t.Fatalf("SSL prompt cancellation lost: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) {
				t.Fatalf("SSL context cancellation lost: %v", err)
			}
		})
	}
}
