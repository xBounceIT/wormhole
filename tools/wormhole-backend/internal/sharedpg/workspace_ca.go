package sharedpg

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// WrappedWorkspaceCA contains no plaintext private key. Its binding and the
// organisation signing pin must be supplied independently by the trusted key
// graph. The certificate is public; trusting it for connections additionally
// requires the signed workspace TLS trust bundle and its rollback floor.
type WrappedWorkspaceCA struct {
	CertificateDER []byte              `json:"certificateDer"`
	KeyCopy        vault.SignedKeyCopy `json:"keyCopy"`
}

// CreateWorkspaceCA creates a P-256, server-only issuing CA. Its scalar is HPKE
// wrapped to the organisation encryption key and the copy is signed using the
// organisation signing key. Nothing is written to disk or the OS trust store.
// The caller must authorize the operation (custodian-only for Hardened+), and
// provide authenticated workspace/key identities, hosts and validity policy.
func CreateWorkspaceCA(binding vault.KeyCopyBinding, organisationEncryptionPublic, organisationSigningSeed []byte, hosts []string, now, expires time.Time) (*WrappedWorkspaceCA, error) {
	dns, ips, err := serverCertificateNames(hosts)
	if err != nil || now.IsZero() || now.Year() < 1 || expires.Year() > 9999 {
		return nil, ErrServerCertificate
	}
	now, expires = now.UTC().Truncate(time.Second), expires.UTC().Truncate(time.Second)
	if !expires.After(now) {
		return nil, ErrServerCertificate
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrServerCertificate
	}
	defer wipeWorkspaceCAKey(key)
	raw, err := key.Bytes()
	if err != nil {
		return nil, ErrServerCertificate
	}
	defer vault.Wipe(raw)
	copy, err := vault.SealKeyCopy(raw, binding, organisationEncryptionPublic, organisationSigningSeed)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, ErrServerCertificate
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: binding.WorkspaceID.String() + " server CA"},
		NotBefore: now, NotAfter: expires, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: dns,
	}
	for _, ip := range ips {
		bits := len(ip) * 8
		template.PermittedIPRanges = append(template.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, ErrServerCertificate
	}
	return &WrappedWorkspaceCA{CertificateDER: der, KeyCopy: copy}, nil
}

// IssueServerCertificate borrows organisation key material only for this call.
// Callers must enforce current admin/custodian authority before opening the CA;
// possession of a historical key copy is not proof of current authorization.
func (ca *WrappedWorkspaceCA) IssueServerCertificate(binding vault.KeyCopyBinding, organisationEncryptionPrivate []byte, organisationSigningPublic ed25519.PublicKey, csrPEM []byte, approvedHosts []string, now time.Time, lifetime time.Duration) ([]byte, error) {
	if ca == nil {
		return nil, ErrServerCertificate
	}
	raw, err := vault.OpenKeyCopy(organisationEncryptionPrivate, binding, ca.KeyCopy, organisationSigningPublic)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(raw)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, ErrServerCertificate
	}
	defer wipeWorkspaceCAKey(key)
	return IssueWorkspaceServerCertificate(ca.CertificateDER, key, csrPEM, approvedHosts, now, lifetime)
}

// Best-effort cleanup of the exposed scalar; the standard crypto library may
// retain temporary internal copies until GC. No long-lived key owner is created.
func wipeWorkspaceCAKey(key *ecdsa.PrivateKey) {
	clear(key.D.Bits())
	key.D.SetInt64(0)
}
