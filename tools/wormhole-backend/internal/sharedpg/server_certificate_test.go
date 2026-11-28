package sharedpg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

var serverCertNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func serverIssuer(t *testing.T, mutate func(*x509.Certificate)) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, subnet, _ := net.ParseCIDR("127.0.0.1/32")
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "workspace CA"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: serverCertNow.Add(-time.Hour), NotAfter: serverCertNow.Add(400 * 24 * time.Hour), PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"db.example.test"}, PermittedIPRanges: []*net.IPNet{subnet}}
	if mutate != nil {
		mutate(ca)
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func serverRequest(t *testing.T, key crypto.Signer, mutate func(*x509.CertificateRequest)) []byte {
	t.Helper()
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored.request.example"}, DNSNames: []string{"DB.example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if mutate != nil {
		mutate(csr)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueWorkspaceServerCertificate(t *testing.T) {
	ca, signer := serverIssuer(t, nil)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{signer, rsaKey} {
		csr := serverRequest(t, key, nil)
		out, err := IssueWorkspaceServerCertificate(ca, signer, csr, []string{"127.0.0.1", "db.example.test"}, serverCertNow.Add(500*time.Millisecond), MaxServerCertificateLifetime)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(out)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.IsCA || cert.Subject.CommonName != "" || cert.NotBefore != serverCertNow || cert.NotAfter.Sub(cert.NotBefore) != MaxServerCertificateLifetime || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 160 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Fatal("unsafe certificate template")
		}
		for _, host := range []string{"db.example.test", "127.0.0.1"} {
			if err := cert.VerifyHostname(host); err != nil {
				t.Fatal(err)
			}
		}
		if cert.VerifyHostname("other.example.test") == nil || cert.VerifyHostname("child.db.example.test") == nil {
			t.Fatal("unapproved SAN")
		}
		roots := x509.NewCertPool()
		issuer, _ := x509.ParseCertificate(ca)
		roots.AddCert(issuer)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: serverCertNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Fatal("client authentication allowed")
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotAfter.Add(time.Second)}); err == nil {
			t.Fatal("expired certificate accepted")
		}
		if !bytes.Equal(cert.RawSubjectPublicKeyInfo, mustParseServerCSR(t, csr).RawSubjectPublicKeyInfo) {
			t.Fatal("wrong key certified")
		}
	}
}

func mustParseServerCSR(t *testing.T, raw []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestServerCSRRejectsUnapprovedOrPrivilegedRequests(t *testing.T) {
	ca, signer := serverIssuer(t, nil)
	uri, _ := url.Parse("https://db.example.test")
	mutations := map[string]func(*x509.CertificateRequest){
		"missing":       func(c *x509.CertificateRequest) { c.DNSNames = nil; c.IPAddresses = nil },
		"different DNS": func(c *x509.CertificateRequest) { c.DNSNames = []string{"evil.test"} },
		"extra DNS":     func(c *x509.CertificateRequest) { c.DNSNames = append(c.DNSNames, "child.db.example.test") },
		"missing DNS":   func(c *x509.CertificateRequest) { c.DNSNames = nil },
		"different IP":  func(c *x509.CertificateRequest) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")} },
		"wildcard":      func(c *x509.CertificateRequest) { c.DNSNames = []string{"*.example.test"} },
		"duplicate":     func(c *x509.CertificateRequest) { c.DNSNames = append(c.DNSNames, "db.example.test") },
		"email":         func(c *x509.CertificateRequest) { c.EmailAddresses = []string{"a@db.example.test"} },
		"URI":           func(c *x509.CertificateRequest) { c.URIs = []*url.URL{uri} },
		"CA": func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}}}
		},
		"unknown SAN": func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 3, 0x88, 1, 1}}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if out, err := IssueWorkspaceServerCertificate(ca, signer, serverRequest(t, signer, mutate), []string{"db.example.test", "127.0.0.1"}, serverCertNow, time.Hour); !errors.Is(err, ErrServerCertificate) || out != nil {
				t.Fatal("accepted request", err)
			}
		})
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{edKey, weak, p224} {
		if _, err := IssueWorkspaceServerCertificate(ca, signer, serverRequest(t, key, nil), []string{"db.example.test", "127.0.0.1"}, serverCertNow, time.Hour); err == nil {
			t.Fatal("weak/unsupported key accepted")
		}
	}
	sha1 := serverRequest(t, signer, func(c *x509.CertificateRequest) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 })
	if _, err := IssueWorkspaceServerCertificate(ca, signer, sha1, []string{"db.example.test", "127.0.0.1"}, serverCertNow, time.Hour); err == nil {
		t.Fatal("SHA-1 request accepted")
	}
}

func TestServerCertificateRejectsBoundaryAndIssuerFailures(t *testing.T) {
	ca, signer := serverIssuer(t, nil)
	csr := serverRequest(t, signer, nil)
	hosts := []string{"db.example.test", "127.0.0.1"}
	for _, names := range [][]string{nil, make([]string, 65), {"*.test"}, {"a", "A"}, {"127.0.0.1", "::ffff:127.0.0.1"}, {"a."}, {"a b"}, {"fe80::1%eth0"}, {strings.Repeat("a", 254)}} {
		if _, err := IssueWorkspaceServerCertificate(ca, signer, csr, names, serverCertNow, time.Hour); err == nil {
			t.Fatal("invalid hosts accepted")
		}
	}
	for _, raw := range [][]byte{nil, []byte("junk"), bytes.Repeat([]byte("x"), 32769), append([]byte("junk\n"), csr...), append(bytes.Clone(csr), csr...), bytes.Replace(csr, []byte("CERTIFICATE REQUEST"), []byte("NEW CERTIFICATE REQUEST"), -1), []byte("-----BEGIN CERTIFICATE REQUEST-----\nbad\n-----END CERTIFICATE REQUEST-----")} {
		if _, err := IssueWorkspaceServerCertificate(ca, signer, raw, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("bad PEM accepted")
		}
	}
	block, _ := pem.Decode(csr)
	malformedPrefix := append([]byte("-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----\n"), csr...)
	if _, err := IssueWorkspaceServerCertificate(ca, signer, malformedPrefix, hosts, serverCertNow, time.Hour); err == nil {
		t.Fatal("PEM parser skipped malformed leading request")
	}
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := IssueWorkspaceServerCertificate(ca, signer, pem.EncodeToMemory(block), hosts, serverCertNow, time.Hour); err == nil {
		t.Fatal("tampered proof accepted")
	}
	for _, duration := range []time.Duration{0, -1, time.Nanosecond, MaxServerCertificateLifetime + 1} {
		if _, err := IssueWorkspaceServerCertificate(ca, signer, csr, hosts, serverCertNow, duration); err == nil {
			t.Fatal("bad lifetime")
		}
	}
	for _, now := range []time.Time{{}, serverCertNow.Add(-2 * time.Hour), serverCertNow.Add(400 * 24 * time.Hour)} {
		if _, err := IssueWorkspaceServerCertificate(ca, signer, csr, hosts, now, time.Hour); err == nil {
			t.Fatal("bad current time")
		}
	}
	for _, raw := range [][]byte{nil, {1}, make([]byte, 32769)} {
		if _, err := IssueWorkspaceServerCertificate(raw, signer, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("bad CA")
		}
	}
	if _, err := IssueWorkspaceServerCertificate(ca, nil, csr, hosts, serverCertNow, time.Hour); err == nil {
		t.Fatal("nil signer")
	}
	_, other := serverIssuer(t, nil)
	if _, err := IssueWorkspaceServerCertificate(ca, other, csr, hosts, serverCertNow, time.Hour); err == nil {
		t.Fatal("wrong signer")
	}
	for _, mutate := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.MaxPathLenZero = false },
		func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false },
		func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"different.test"} },
		func(c *x509.Certificate) {
			_, n, _ := net.ParseCIDR("127.0.0.2/32")
			c.PermittedIPRanges = []*net.IPNet{n}
		},
	} {
		der, key := serverIssuer(t, mutate)
		if _, err := IssueWorkspaceServerCertificate(der, key, csr, hosts, serverCertNow, time.Hour); err == nil {
			t.Fatal("unsafe issuer")
		}
	}
	if _, err := IssueWorkspaceServerCertificate(ca, failingServerSigner{signer}, csr, hosts, serverCertNow, time.Hour); err == nil {
		t.Fatal("signer failure")
	}
}

type failingServerSigner struct{ *ecdsa.PrivateKey }

func (f failingServerSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign failure")
}

func TestServerSANExtensionAndCanonicalNames(t *testing.T) {
	for _, value := range [][]byte{nil, {0x30, 0}, {0x30, 3, 0x22, 1, 1}, {0x30, 3, 0x82, 1, 'a', 0}} {
		if serverSANExtension(pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}) {
			t.Fatal("invalid SAN accepted")
		}
	}
	if serverSANExtension(pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3}}) {
		t.Fatal("wrong OID accepted")
	}
	dns, ips, err := serverCertificateNames([]string{"DB.Example.Test", "2001:db8::1"})
	if err != nil || dns[0] != "db.example.test" || ips[0].String() != "2001:db8::1" {
		t.Fatal("canonical names", err)
	}
}
