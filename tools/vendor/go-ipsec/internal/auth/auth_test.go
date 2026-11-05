package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

// simple HMAC-free deterministic PRF stand-in for assembly tests: SHA-256 of
// key||data. The real client uses HMAC-SHA256; assembly logic is PRF-agnostic.
func testPRF(key, data []byte) []byte {
	h := sha256.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

func TestSignedOctets(t *testing.T) {
	real := []byte("REAL_MESSAGE_1_BYTES")
	nr := []byte("responder-nonce")
	idPrime := []byte{0x02, 0, 0, 0, 'i', 'd'}
	skpi := bytes.Repeat([]byte{0xAA}, 32)

	got := SignedOctets(testPRF, real, nr, idPrime, skpi)
	want := append(append(append([]byte{}, real...), nr...), testPRF(skpi, idPrime)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed octets mismatch")
	}
	// Deterministic.
	if !bytes.Equal(got, SignedOctets(testPRF, real, nr, idPrime, skpi)) {
		t.Fatal("signed octets not deterministic")
	}
}

func TestSharedSecretAuth(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 64)
	so := []byte("signed-octets")
	got := SharedSecretAuth(testPRF, secret, so)
	want := testPRF(testPRF(secret, keyPad), so)
	if !bytes.Equal(got, want) {
		t.Fatal("SharedSecretAuth != prf(prf(secret,keypad),so)")
	}
}

// makeCert builds a CA and a leaf cert signed by it, returning the leaf, its
// key, and a roots pool containing the CA.
func makeCert(t *testing.T, dns string) (*x509.Certificate, *rsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dns},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dns},
		IPAddresses:  []net.IP{net.ParseIP("203.0.113.7")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return leaf, leafKey, roots
}

func TestVerifyServerChainAndName(t *testing.T) {
	leaf, _, roots := makeCert(t, "vpn.example.com")
	// Reassemble DER for the public API.
	der := [][]byte{leaf.Raw}

	if _, err := VerifyServerChain(der, roots, PeerName{DNS: "vpn.example.com"}, time.Now()); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if _, err := VerifyServerChain(der, roots, PeerName{DNS: "evil.example.com"}, time.Now()); err == nil {
		t.Fatal("name mismatch accepted")
	}
	if _, err := VerifyServerChain(der, x509.NewCertPool(), PeerName{}, time.Now()); err == nil {
		t.Fatal("untrusted chain accepted")
	}
}

func TestVerifyServerChainNameModes(t *testing.T) {
	leaf, _, roots := makeCert(t, "vpn.example.com")
	der := [][]byte{leaf.Raw}

	// Unset RemoteID → chain trust only (accepted, documented behaviour).
	if _, err := VerifyServerChain(der, roots, PeerName{}, time.Now()); err != nil {
		t.Fatalf("chain-only trust rejected: %v", err)
	}
	// DN matched against the leaf subject.
	if _, err := VerifyServerChain(der, roots, PeerName{DN: leaf.RawSubject}, time.Now()); err != nil {
		t.Fatalf("matching DN rejected: %v", err)
	}
	if _, err := VerifyServerChain(der, roots, PeerName{DN: []byte("not-the-subject")}, time.Now()); err == nil {
		t.Fatal("wrong DN accepted")
	}
	// A configured-but-unmatchable RemoteID must fail closed, not fall through
	// to chain-only trust.
	if _, err := VerifyServerChain(der, roots, PeerName{Unverifiable: true}, time.Now()); err == nil {
		t.Fatal("unverifiable RemoteID accepted (should fail closed)")
	}
	// IP SAN match (the leaf carries 203.0.113.7).
	if _, err := VerifyServerChain(der, roots, PeerName{IP: netip.MustParseAddr("203.0.113.7")}, time.Now()); err != nil {
		t.Fatalf("matching IP SAN rejected: %v", err)
	}
}

// makeCertEKU builds a leaf with the given extended key usages (named and raw-OID)
// chained to a fresh CA, returning the DER chain and trust pool.
func makeCertEKU(t *testing.T, eku []x509.ExtKeyUsage, unknownEKU []asn1.ObjectIdentifier) ([][]byte, *x509.CertPool) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		DNSNames:           []string{"vpn.example.com"},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        eku,
		UnknownExtKeyUsage: unknownEKU,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return [][]byte{leaf.Raw}, roots
}

// TestVerifyServerChainEKU is finding #5: the leaf's extended key usage is now
// enforced after chain building, so a clientAuth-only cert chaining to the pinned
// CA can no longer impersonate the gateway, while serverAuth / IPsec / ipsecIKE /
// no-EKU certs (strongSwan interop) still pass.
func TestVerifyServerChainEKU(t *testing.T) {
	ipsecIKE := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 17}
	cases := []struct {
		name    string
		eku     []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		ok      bool
	}{
		{"no-EKU unconstrained", nil, nil, true},
		{"serverAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, true},
		{"ipsec-tunnel", []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}, nil, true},
		{"ipsecIKE-oid", nil, []asn1.ObjectIdentifier{ipsecIKE}, true},
		{"clientAuth-only", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, false},
		{"emailProtection-only", []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, roots := makeCertEKU(t, tc.eku, tc.unknown)
			_, err := VerifyServerChain(der, roots, PeerName{}, time.Now())
			if tc.ok && err != nil {
				t.Fatalf("expected accept, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected reject, got accept")
			}
		})
	}
}

func TestVerifyCertAuth_Method1(t *testing.T) {
	leaf, key, _ := makeCert(t, "vpn.example.com")
	so := []byte("RESPONDER_SIGNED_OCTETS")

	h := sha1.Sum(so)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertAuth(MethodRSADigitalSignature, sig, so, leaf); err != nil {
		t.Fatalf("valid method-1 AUTH rejected: %v", err)
	}
	bad := append([]byte{}, sig...)
	bad[0] ^= 0xFF
	if err := VerifyCertAuth(MethodRSADigitalSignature, bad, so, leaf); err == nil {
		t.Fatal("tampered method-1 AUTH accepted")
	}
}

func TestVerifyCertAuth_Method14_RFC7427(t *testing.T) {
	leaf, key, _ := makeCert(t, "vpn.example.com")
	so := []byte("RESPONDER_SIGNED_OCTETS")

	// Sign with PKCS1v15-SHA256.
	h := sha256.Sum256(so)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	// Build the RFC 7427 AlgorithmIdentifier for sha256WithRSAEncryption.
	ai := algorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}
	algoDER, err := asn1.Marshal(ai)
	if err != nil {
		t.Fatal(err)
	}
	authData := append([]byte{byte(len(algoDER))}, algoDER...)
	authData = append(authData, sig...)

	if err := VerifyCertAuth(MethodDigitalSignature, authData, so, leaf); err != nil {
		t.Fatalf("valid RFC 7427 AUTH rejected: %v", err)
	}

	// Tamper the signature.
	bad := append([]byte{}, authData...)
	bad[len(bad)-1] ^= 0xFF
	if err := VerifyCertAuth(MethodDigitalSignature, bad, so, leaf); err == nil {
		t.Fatal("tampered RFC 7427 AUTH accepted")
	}
}
