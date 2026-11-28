package sharedpg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

var ErrServerCertificate = errors.New("shared_invalid_server_certificate")

const MaxServerCertificateLifetime = 397 * 24 * time.Hour

// IssueWorkspaceServerCertificate signs a server-generated CSR. The caller must
// authorize use of the organisation's CA and obtain approvedHosts from the
// authenticated workspace configuration, not from the request. It owns signer;
// this function neither persists nor returns private key material.
//
// The issuer must be a currently valid, self-signed P-256 server-only CA with
// pathlen zero. The resulting chain is verified before publication, including
// the issuer's name constraints. Exact SAN approval is enforced separately:
// X.509 DNS constraints alone also permit subdomains.
func IssueWorkspaceServerCertificate(caDER []byte, signer crypto.Signer, csrPEM []byte, approvedHosts []string, now time.Time, lifetime time.Duration) ([]byte, error) {
	if signer == nil || len(caDER) == 0 || len(caDER) > 32*1024 || now.IsZero() || lifetime <= 0 || lifetime > MaxServerCertificateLifetime {
		return nil, ErrServerCertificate
	}
	dns, ips, err := serverCertificateNames(approvedHosts)
	if err != nil {
		return nil, err
	}
	request, err := approvedServerCSR(csrPEM, dns, ips)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, ErrServerCertificate
	}
	public, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(signer.Public()) || !validWorkspaceServerCA(ca) {
		return nil, ErrServerCertificate
	}
	// X.509 encodes whole seconds. Normalize once so duration/issuer checks and
	// the encoded validity describe the same interval (without clock backdating).
	now = now.UTC().Truncate(time.Second)
	until := now.Add(lifetime).Truncate(time.Second)
	if now.Before(ca.NotBefore) || !until.After(now) || until.After(ca.NotAfter) || until.Year() > 9999 {
		return nil, ErrServerCertificate
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, ErrServerCertificate
	}
	serial.Add(serial, big.NewInt(1))
	leaf := &x509.Certificate{
		SerialNumber: serial, NotBefore: now, NotAfter: until,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dns, IPAddresses: ips,
	}
	if _, ok := request.PublicKey.(*rsa.PublicKey); ok {
		leaf.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, request.PublicKey, signer)
	if err != nil {
		return nil, ErrServerCertificate
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrServerCertificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, ErrServerCertificate
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func validWorkspaceServerCA(cert *x509.Certificate) bool {
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && public.Curve == elliptic.P256() && cert.IsCA && cert.BasicConstraintsValid &&
		cert.MaxPathLenZero && cert.KeyUsage == x509.KeyUsageCertSign &&
		len(cert.ExtKeyUsage) == 1 && cert.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth &&
		len(cert.UnknownExtKeyUsage) == 0 && cert.CheckSignatureFrom(cert) == nil &&
		cert.PermittedDNSDomainsCritical && len(cert.PermittedDNSDomains)+len(cert.PermittedIPRanges) > 0
}

func serverCertificateNames(hosts []string) ([]string, []net.IP, error) {
	if len(hosts) == 0 || len(hosts) > 64 {
		return nil, nil, ErrServerCertificate
	}
	var dns []string
	var ips []net.IP
	seen := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if !hostname(host) {
			return nil, nil, ErrServerCertificate
		}
		name := strings.ToLower(host)
		if ip, err := netip.ParseAddr(host); err == nil {
			ip = ip.Unmap()
			name = ip.String()
			ips = append(ips, net.IP(ip.AsSlice()))
		} else {
			dns = append(dns, name)
		}
		if seen[name] {
			return nil, nil, ErrServerCertificate
		}
		seen[name] = true
	}
	return dns, ips, nil
}

func approvedServerCSR(raw []byte, dns []string, ips []net.IP) (*x509.CertificateRequest, error) {
	if len(raw) == 0 || len(raw) > MaxServerCSRBytes || !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE REQUEST-----")) || bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
		return nil, ErrServerCertificate
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrServerCertificate
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || len(csr.Extensions) != 1 || !serverSANExtension(csr.Extensions[0]) {
		return nil, ErrServerCertificate
	}
	switch csr.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
	default:
		return nil, ErrServerCertificate
	}
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() {
			return nil, ErrServerCertificate
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 65537 || key.E%2 == 0 {
			return nil, ErrServerCertificate
		}
	default:
		return nil, ErrServerCertificate
	}
	if csr.CheckSignature() != nil {
		return nil, ErrServerCertificate
	}
	hosts := append([]string(nil), csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	requestedDNS, requestedIPs, err := serverCertificateNames(hosts)
	if err != nil || len(requestedDNS) != len(dns) || len(requestedIPs) != len(ips) {
		return nil, ErrServerCertificate
	}
	approved := make(map[string]bool, len(hosts))
	for _, name := range dns {
		approved[name] = true
	}
	for _, ip := range ips {
		approved[ip.String()] = true
	}
	for _, name := range requestedDNS {
		if !approved[name] {
			return nil, ErrServerCertificate
		}
	}
	for _, ip := range requestedIPs {
		if !approved[ip.String()] {
			return nil, ErrServerCertificate
		}
	}
	return csr, nil
}

// Reject GeneralName kinds the standard parser ignores, not just the parsed
// DNS/IP fields. Requested CA/EKU/custom extensions are never copied to a leaf.
func serverSANExtension(ext pkix.Extension) bool {
	if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
		return false
	}
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &names)
	if err != nil || len(rest) != 0 || len(names) == 0 || len(names) > 64 {
		return false
	}
	for _, name := range names {
		if name.Class != asn1.ClassContextSpecific || name.IsCompound || (name.Tag != 2 && name.Tag != 7) {
			return false
		}
	}
	return true
}
