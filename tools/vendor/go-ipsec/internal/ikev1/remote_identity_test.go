package ikev1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRemoteIdentityAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Gateway"}, DNSNames: []string{"vpn.test"}, EmailAddresses: []string{"gateway@example.test"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	pairCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	hash := []byte("authenticated exchange hash")
	signer := &Session{cfg: Config{Certificate: pairCert}}
	payloads, err := signer.authenticationPayloads(hash)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := findPayload(payloads, 9)
	for _, tc := range []struct {
		name  string
		kind  uint8
		data  []byte
		valid bool
	}{
		{"unset", 0, nil, true},
		{"DNS", 2, []byte("vpn.test"), true},
		{"email", 3, []byte("gateway@example.test"), true},
		{"IPv4", 1, net.ParseIP("192.0.2.1").To4(), true},
		{"IPv6", 5, net.ParseIP("2001:db8::1").To16(), true},
		{"DN", 9, cert.RawSubject, true},
		{"wrong-SAN", 3, []byte("another@example.test"), false},
		{"email-as-DNS", 2, []byte("gateway@example.test"), false},
		{"opaque", 11, []byte{0, 1, 2}, false},
		{"unknown", 255, []byte{1}, false},
		{"short-IP", 1, []byte{1}, false},
		{"wrong-IP-family", 5, net.ParseIP("192.0.2.1").To4(), false},
		{"mapped-IPv6", 5, net.ParseIP("192.0.2.1").To16(), false},
		{"empty-DNS", 2, nil, false},
		{"empty-email", 3, nil, false},
		{"empty-DN", 9, nil, false},
		{"data-without-type", 0, []byte("vpn.test"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{cfg: Config{Role: Initiator, Certificate: pairCert, RootCAs: roots, RemoteIDType: tc.kind, RemoteIDData: tc.data}, idR: buildID(identity{idType: tc.kind, data: tc.data})}
			if err := s.verifyAuthentication(payloads, hash, proof.body); (err == nil) != tc.valid {
				t.Fatalf("certificate identity accepted=%v, want %v", err == nil, tc.valid)
			}
			if tc.kind != 0 {
				s.idR[0] = tc.kind + 1
				if err := s.verifyAuthentication(payloads, hash, proof.body); !errors.Is(err, ErrAuth) {
					t.Fatal("accepted wrong ID type")
				}
			}
		})
	}
	// A matching PSK proof cannot override a type or value mismatch in IDr.
	for _, kind := range []uint8{1, 2, 3, 5, 9, 11} {
		s := &Session{cfg: Config{Role: Initiator, RemoteIDType: kind, RemoteIDData: []byte("identity")}, idR: buildID(identity{idType: kind, data: []byte("identity")})}
		if err := s.verifyAuthentication(nil, hash, hash); err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]byte{nil, {kind, 0}, buildID(identity{idType: kind + 1, data: []byte("identity")}), buildID(identity{idType: kind, data: []byte("other")})} {
			s.idR = bad
			if err := s.verifyAuthentication(nil, hash, hash); !errors.Is(err, ErrAuth) {
				t.Fatal("accepted mismatched PSK peer identity")
			}
		}
	}
	// Main and Aggressive Mode must both accept a certificate with an email SAN
	// and no DNS SAN matching the configured RFC822 identity.
	for _, mode := range []Mode{ModeMain, ModeAggressive} {
		init, resp := remoteAccessConfigs("alice", "password", nil)
		for _, cfg := range []*Config{&init, &resp} {
			cfg.Mode, cfg.Certificate, cfg.RootCAs = mode, pairCert, roots
		}
		init.RemoteIDType, init.RemoteIDData = 3, []byte("gateway@example.test")
		resp.IdentityType, resp.GroupName = 3, "gateway@example.test"
		p := newPair(t, init, resp)
		p.run(t)
		p.initiator.Close()
		p.responder.Close()
		if p.initErr != nil || p.respErr != nil || p.initRes == nil {
			t.Fatalf("email certificate handshake failed: %v / %v", p.initErr, p.respErr)
		}
	}
}
