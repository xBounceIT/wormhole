package session

import (
	"context"
	"github.com/n0madic/go-ipsec/internal/transport"
	"testing"
	"time"
)

func TestPSKHonorsConfiguredResponderIdentity(t *testing.T) {
	for _, remote := range []string{"vpn.test", "different.test", ""} {
		t.Run("expected-"+remote, func(t *testing.T) {
			client, peer := transport.MemoryPair()
			defer client.Close()
			defer peer.Close()
			cfg := Config{Server: "mem:500", LocalID: WireID{Type: 2, Data: []byte("client.test")}, PSK: []byte("shared-fixture"), RetransmitBase: time.Second, RetransmitTries: 1}
			if remote != "" {
				cfg.RemoteID = WireID{Type: 2, Data: []byte(remote)}
			}
			s := New(cfg)
			s.conn = client
			defer s.Close()
			done := make(chan *responderResult, 1)
			go func() { done <- runResponderPSK(peer, cfg.PSK, cbcSuite(), nil) }()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := s.IKESAInit(ctx); err != nil {
				t.Fatal(err)
			}
			err := s.IKEAuth(ctx)
			wantSuccess := remote != "different.test"
			if (err == nil) != wantSuccess || s.Established() != wantSuccess {
				t.Fatalf("PSK RemoteID %q: established=%v err=%v", remote, s.Established(), err)
			}
			if result := <-done; result.err != nil {
				t.Fatal(result.err)
			}
		})
	}
}
