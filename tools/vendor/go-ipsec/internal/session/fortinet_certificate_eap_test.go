package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/n0madic/go-ipsec/internal/transport"
	"testing"
	"time"
)

func TestFortinetCertificateAndEAP(t *testing.T) {
	leaf, key, roots := makeTestCert(t, "vpn.test")
	for _, mode := range []string{"success", "success-mschap", "bad-final-auth", "wrong-id", "missing-eap", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			client, server := transport.MemoryPair()
			defer client.Close()
			defer server.Close()
			cfg := Config{Server: "mem:500", FortinetSAML: true, ClientCertificate: &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}, RootCAs: roots, LocalID: WireID{Type: 2, Data: []byte("client.test")}, RemoteID: WireID{Type: 2, Data: []byte("vpn.test")}, EAPUser: "UID", EAPPass: []byte("temporary-token"), RetransmitBase: time.Millisecond * 100, RetransmitTries: 1}
			if mode == "untrusted" {
				cfg.RootCAs = x509.NewCertPool()
			}
			s := New(cfg)
			s.conn = client
			defer s.Close()
			done := make(chan error, 1)
			go func() { done <- fortinetTestResponder(server, mode, fortinetCertFixture{leaf, key}) }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.IKESAInit(ctx); err != nil {
				t.Fatal(err)
			}
			err := s.IKEAuth(ctx)
			success := mode == "success" || mode == "success-mschap"
			if (err == nil) != success || s.Established() != success {
				t.Fatal("certificate and EAP outcome", err)
			}
			client.Close()
			server.Close()
			if err := <-done; success && err != nil {
				t.Fatal(err)
			}
		})
	}
}
