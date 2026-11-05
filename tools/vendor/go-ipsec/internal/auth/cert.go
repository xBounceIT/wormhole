// Package auth implements the IKEv2 AUTH machinery for an EAP initiator:
// assembling the signed octets (RFC 7296 §2.15), verifying the responder's
// certificate-based AUTH and certificate chain, and computing/verifying the
// final MSK-keyed AUTH values.
package auth

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// PeerName is the expected responder identity to match against the server
// certificate. At most one of DNS/IP/Email/DN is set; the zero value disables
// name matching (chain trust only). Unverifiable marks a RemoteID that was
// configured but is of a type we cannot match — matchName then fails closed
// rather than silently trusting the chain alone.
type PeerName struct {
	DNS          string
	IP           netip.Addr
	Email        string
	DN           []byte // raw DER Distinguished Name (ID_DER_ASN1_DN)
	Unverifiable bool
}

// VerifyServerChain parses the responder's certificate payloads (leaf first,
// then any intermediates, each a DER-encoded X.509 certificate), verifies the
// chain to roots, and matches the leaf against name when set. It returns the
// leaf certificate for the subsequent AUTH-signature check.
func VerifyServerChain(certsDER [][]byte, roots *x509.CertPool, name PeerName, now time.Time) (*x509.Certificate, error) {
	if len(certsDER) == 0 {
		return nil, errors.New("auth: responder sent no certificate")
	}
	leaf, err := x509.ParseCertificate(certsDER[0])
	if err != nil {
		return nil, fmt.Errorf("auth: parse leaf certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, der := range certsDER[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("auth: parse intermediate certificate: %w", err)
		}
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots, // nil → system roots
		Intermediates: inter,
		CurrentTime:   now,
		// Chain building uses Any so a certificate carrying the IKE-intermediate EKU
		// (an OID the standard library cannot name in this list) is not rejected here;
		// the leaf's own EKU is then enforced explicitly below against a server-auth
		// allow-list, so a clientAuth-only sibling cert cannot impersonate the gateway.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("auth: certificate chain verification failed: %w", err)
	}
	if !leafUsableForServerAuth(leaf) {
		return nil, errors.New("auth: server certificate extended key usage does not permit IKE/TLS server authentication")
	}
	if err := matchName(leaf, name); err != nil {
		return nil, err
	}
	return leaf, nil
}

// oidExtKeyUsageIPSECIKE is id-kp-ipsecIKE (RFC 4945 §5.1.3.12), the EKU
// strongSwan and other IKE gateways mark on their server certificates. The Go
// standard library has no named x509.ExtKeyUsage for it, so it is matched against
// the leaf's UnknownExtKeyUsage list.
var oidExtKeyUsageIPSECIKE = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 17}

// leafUsableForServerAuth reports whether the leaf's extended key usage permits
// acting as an IKE/TLS gateway. A certificate with no EKU constraint is valid for
// any purpose (RFC 5280 §4.2.1.12); otherwise it must carry anyExtendedKeyUsage,
// serverAuth, one of the IPsec EKUs, or ipsecIKE.
func leafUsableForServerAuth(leaf *x509.Certificate) bool {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return true // unconstrained: valid for any purpose
	}
	for _, eku := range leaf.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny,
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageIPSECEndSystem,
			x509.ExtKeyUsageIPSECTunnel,
			x509.ExtKeyUsageIPSECUser:
			return true
		}
	}
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidExtKeyUsageIPSECIKE) {
			return true
		}
	}
	return false
}

// matchName checks the leaf certificate against the expected responder name.
func matchName(leaf *x509.Certificate, name PeerName) error {
	switch {
	case name.Unverifiable:
		// A RemoteID was configured but is of a type we cannot match against the
		// certificate. Fail closed rather than fall through to chain-only trust.
		return errors.New("auth: configured RemoteID type cannot be matched against the server certificate")
	case name.DNS != "":
		if err := leaf.VerifyHostname(name.DNS); err != nil {
			return fmt.Errorf("auth: server certificate does not match RemoteID %q: %w", name.DNS, err)
		}
	case name.IP.IsValid():
		if err := leaf.VerifyHostname(name.IP.String()); err != nil {
			return fmt.Errorf("auth: server certificate does not match RemoteID %s: %w", name.IP, err)
		}
	case name.Email != "":
		if !slices.Contains(leaf.EmailAddresses, name.Email) {
			return fmt.Errorf("auth: server certificate has no RFC822 SAN matching RemoteID %q", name.Email)
		}
	case len(name.DN) != 0:
		if !bytes.Equal(leaf.RawSubject, name.DN) {
			return errors.New("auth: server certificate subject does not match RemoteID DN")
		}
	}
	return nil
}
