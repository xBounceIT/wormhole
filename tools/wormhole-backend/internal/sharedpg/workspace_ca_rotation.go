package sharedpg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"net"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrWorkspaceCARotation = errors.New("shared_workspace_ca_rotation_unavailable")

// WorkspaceTLSCA names the issuing root and key copy in a signed version-2
// TLS bundle. During rotation both roots are trusted and ServerCertificate is
// the exact DER leaf that all configured endpoints must serve before retirement.
type WorkspaceTLSCA struct {
	Key               vault.KeyRef `json:"key"`
	IssuingCA         string       `json:"issuingCa"`
	PreviousCA        string       `json:"previousCa,omitempty"`
	ServerCertificate []byte       `json:"serverCertificate,omitempty"`
}

func certificateDigest(der []byte) string {
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func (b TLSTrustBundle) workspaceIssuer() []byte {
	if b.WorkspaceCA == nil {
		if len(b.CAs) == 1 {
			return b.CAs[0]
		}
		return nil
	}
	for _, der := range b.CAs {
		if certificateDigest(der) == b.WorkspaceCA.IssuingCA {
			return der
		}
	}
	return nil
}

func (b TLSTrustBundle) validateWorkspaceCA() error {
	authority := b.WorkspaceCA
	if authority.Key.ID == uuid.Nil || authority.Key.Version == 0 || authority.Key.Version > math.MaxInt32 {
		return vault.ErrFormat
	}
	issuerDER := b.workspaceIssuer()
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil || !validWorkspaceServerCA(issuer) || !workspaceCAHostSet(issuer, b.Hosts) {
		return vault.ErrFormat
	}
	if authority.PreviousCA == "" {
		if len(b.CAs) == 1 && len(authority.ServerCertificate) == 0 {
			return nil
		}
		return vault.ErrFormat
	}
	if len(b.CAs) != 2 || authority.PreviousCA == authority.IssuingCA ||
		!slices.ContainsFunc(b.CAs, func(der []byte) bool { return certificateDigest(der) == authority.PreviousCA }) {
		return vault.ErrFormat
	}
	return validatePendingWorkspaceServerCertificate(authority.ServerCertificate, issuer, b.Hosts)
}

func workspaceCAHostSet(ca *x509.Certificate, hosts []string) bool {
	dns, ips, err := serverCertificateNames(hosts)
	if err != nil || !slices.Equal(ca.PermittedDNSDomains, dns) || len(ca.PermittedIPRanges) != len(ips) {
		return false
	}
	for i, ip := range ips {
		ones, size := ca.PermittedIPRanges[i].Mask.Size()
		if ones != len(ip)*8 || size != ones || !ip.Equal(ca.PermittedIPRanges[i].IP) {
			return false
		}
	}
	return true
}

func validatePendingWorkspaceServerCertificate(raw []byte, ca *x509.Certificate, hosts []string) error {
	if len(raw) == 0 || len(raw) > 32*1024 {
		return vault.ErrFormat
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil || cert.IsCA || cert.PublicKeyAlgorithm == x509.Ed25519 || len(cert.ExtKeyUsage) != 1 ||
		cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(cert.UnknownExtKeyUsage) != 0 ||
		cert.NotAfter.Sub(cert.NotBefore) > MaxServerCertificateLifetime || !cert.NotAfter.After(cert.NotBefore) ||
		cert.NotAfter.After(ca.NotAfter) || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		return vault.ErrFormat
	}
	dns, ips, err := serverCertificateNames(hosts)
	if err != nil || !slices.Equal(cert.DNSNames, dns) ||
		!slices.EqualFunc(cert.IPAddresses, ips, func(a, b net.IP) bool { return a.Equal(b) }) {
		return vault.ErrFormat
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotBefore, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return vault.ErrAuthentication
	}
	return nil
}

type workspaceCARotation struct {
	overlap *VerifiedTLSBundle
	key     workspaceCAKeyCopy
}

func prepareWorkspaceCARotation(current *VerifiedTLSBundle, before workspaceCAKeyCopy, organisation vault.OrganisationRecoveryBinding, keys *vault.UserKeys, csr []byte, now time.Time) (*workspaceCARotation, error) {
	if current == nil || len(current.raw) == 0 || current.bundle.Sequence > math.MaxInt64-2 ||
		len(current.bundle.CAs) != 1 || keys == nil || organisation.WorkspaceID != current.pin.WorkspaceID ||
		organisation.Signing != current.pin.Signer || (current.bundle.WorkspaceCA != nil && before.Key != current.bundle.WorkspaceCA.Key) {
		return nil, ErrWorkspaceCARotation
	}
	public, err := keys.Public()
	if err != nil || !bytes.Equal(public.Signing, current.pin.Organisation) {
		return nil, vault.ErrAuthentication
	}
	previous := workspaceRecoveryCA{Certificate: current.bundle.CAs[0], Key: before}
	if !previous.matches(keys.EncryptionPrivate, organisation, public.Signing) {
		return nil, vault.ErrAuthentication
	}
	nextKey := workspaceCAKeyCopy{Key: vault.KeyRef{ID: uuid.New(), Version: 1}}
	binding := nextKey.binding(organisation)
	ca, err := CreateWorkspaceCA(binding, public.Encryption, keys.SigningSeed, current.bundle.Hosts, now, now.Add(workspaceCAValidity))
	if err != nil {
		return nil, err
	}
	nextKey.Copy = ca.KeyCopy
	leaf, err := ca.IssueServerCertificate(binding, keys.EncryptionPrivate, public.Signing, csr, current.bundle.Hosts, now, serverCertValidity)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(leaf)
	if block == nil {
		return nil, ErrServerCertificate
	}
	next := current.bundle
	next.FormatVersion = 2
	next.Sequence++
	next.CAs = [][]byte{previous.Certificate, ca.CertificateDER}
	slices.SortFunc(next.CAs, bytes.Compare)
	next.WorkspaceCA = &WorkspaceTLSCA{
		Key: nextKey.Key, IssuingCA: certificateDigest(ca.CertificateDER),
		PreviousCA: certificateDigest(previous.Certificate), ServerCertificate: block.Bytes,
	}
	overlap, err := current.signCAUpdate(next, keys.SigningSeed)
	if err != nil {
		return nil, err
	}
	return &workspaceCARotation{overlap: overlap, key: nextKey}, nil
}

// PendingServerCertificate returns only public PEM and can be used after
// restarting from the persisted overlap. It is empty for a stable bundle.
func (v *VerifiedTLSBundle) PendingServerCertificate() []byte {
	if v == nil || v.bundle.WorkspaceCA == nil || v.bundle.WorkspaceCA.PreviousCA == "" {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.bundle.WorkspaceCA.ServerCertificate})
}

func (v *VerifiedTLSBundle) signCAUpdate(next TLSTrustBundle, seed []byte) (*VerifiedTLSBundle, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, vault.ErrFormat
	}
	signer := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(signer)
	signed, err := SignTLSTrustBundle(next, signer)
	if err != nil {
		return nil, err
	}
	return v.Advance(signed)
}

// retirePreviousWorkspaceCA performs fresh PostgreSQL TLS handshakes against
// the signed pending leaf before signing the trust update which drops the old
// root. Settings are the device's authenticated workspace transport settings.
func (v *VerifiedTLSBundle) retirePreviousWorkspaceCA(ctx context.Context, settings Settings, orgSigningSeed []byte) (*VerifiedTLSBundle, error) {
	if ctx == nil || len(v.PendingServerCertificate()) == 0 || v.bundle.Sequence >= math.MaxInt64 {
		return nil, ErrWorkspaceCARotation
	}
	if err := v.verifyRotatedServerInstallation(ctx, settings); err != nil {
		return nil, err
	}
	next := v.bundle
	next.Sequence++
	next.CAs = [][]byte{v.bundle.workspaceIssuer()}
	next.WorkspaceCA = &WorkspaceTLSCA{Key: v.bundle.WorkspaceCA.Key, IssuingCA: v.bundle.WorkspaceCA.IssuingCA}
	return v.signCAUpdate(next, orgSigningSeed)
}
