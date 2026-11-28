package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxTLSTrustBundleBytes = 1024 * 1024

// TLSRevocation identifies a certificate by its issuer's SPKI digest and serial,
// not by a replaceable issuer certificate's fingerprint. Serial is positive,
// lowercase hexadecimal without leading zeros (at most 20 octets).
type TLSRevocation struct {
	IssuerSPKI string `json:"issuerSpki"`
	Serial     string `json:"serial"`
}

// TLSTrustBundle is untrusted until verified against independent enrollment
// identity and a durable sequence/digest floor. Lists have canonical sorted
// order: CA DER bytes, host strings, and issuer-SPKI/serial respectively.
type TLSTrustBundle struct {
	FormatVersion uint16          `json:"formatVersion"`
	WorkspaceID   uuid.UUID       `json:"workspaceId"`
	Signer        vault.KeyRef    `json:"signer"`
	Sequence      uint64          `json:"sequence"`
	CAs           [][]byte        `json:"cas"`
	Hosts         []string        `json:"hosts"`
	Revoked       []TLSRevocation `json:"revoked"`
	Signature     []byte          `json:"signature"`
	WorkspaceCA   *WorkspaceTLSCA `json:"workspaceCa,omitempty"`
}

type TLSTrustPin struct {
	WorkspaceID     uuid.UUID
	Signer          vault.KeyRef
	Organisation    ed25519.PublicKey
	MinimumSequence uint64
	// Digest is required when a document at MinimumSequence has been observed.
	// Nil is enrollment-only, for an independently pinned minimum sequence.
	Digest []byte
}

// VerifiedTLSBundle holds a private snapshot so caller mutations cannot change
// an authenticated bundle. Persist its canonical encoding and high-water mark
// durably before publishing it to connection owners. It does not prove freshness
// beyond the supplied independent floor or perform that persistence itself.
type VerifiedTLSBundle struct {
	bundle TLSTrustBundle
	pin    TLSTrustPin
	raw    []byte
}

func (b TLSTrustBundle) signingBytes() ([]byte, error) {
	if b.FormatVersion > 2 {
		return nil, vault.ErrNewerFormat
	}
	if b.FormatVersion == 0 || (b.FormatVersion == 2) != (b.WorkspaceCA != nil) || b.WorkspaceID == uuid.Nil || b.Signer.ID == uuid.Nil || b.Signer.Version == 0 || b.Signer.Version > math.MaxInt32 || b.Sequence == 0 || b.Sequence > math.MaxInt64 || len(b.CAs) == 0 || len(b.CAs) > 8 || len(b.Hosts) == 0 || len(b.Hosts) > 64 || b.Revoked == nil || len(b.Revoked) > 4096 {
		return nil, vault.ErrFormat
	}
	total := 0
	for i, raw := range b.CAs {
		total += len(raw)
		if len(raw) == 0 || len(raw) > 32*1024 || total > 128*1024 || (i > 0 && bytes.Compare(b.CAs[i-1], raw) >= 0) {
			return nil, vault.ErrFormat
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, vault.ErrFormat
		}
	}
	for i, host := range b.Hosts {
		dns, ips, err := serverCertificateNames([]string{host})
		if err != nil || (i > 0 && b.Hosts[i-1] >= host) {
			return nil, vault.ErrFormat
		}
		canonical := ""
		if len(dns) == 1 {
			canonical = dns[0]
		} else {
			canonical = ips[0].String()
		}
		if host != canonical {
			return nil, vault.ErrFormat
		}
	}
	previous := ""
	for _, r := range b.Revoked {
		if len(r.IssuerSPKI) != 64 {
			return nil, vault.ErrFormat
		}
		issuer, err := hex.DecodeString(r.IssuerSPKI)
		if err != nil || len(issuer) != sha256.Size || hex.EncodeToString(issuer) != r.IssuerSPKI || len(r.Serial) == 0 || len(r.Serial) > 40 || r.Serial[0] == '0' || strings.Trim(r.Serial, "0123456789abcdef") != "" {
			return nil, vault.ErrFormat
		}
		key := r.IssuerSPKI + ":" + r.Serial
		if key <= previous {
			return nil, vault.ErrFormat
		}
		previous = key
	}
	domain := "wormhole/v1/tls-trust\x00"
	if b.WorkspaceCA != nil {
		if err := b.validateWorkspaceCA(); err != nil {
			return nil, err
		}
		domain = "wormhole/v2/tls-trust\x00"
	}
	b.Signature = nil
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxTLSTrustBundleBytes-128 {
		return nil, vault.ErrFormat
	}
	return append([]byte(domain), raw...), nil
}

func SignTLSTrustBundle(b TLSTrustBundle, organisation ed25519.PrivateKey) (TLSTrustBundle, error) {
	if len(organisation) != ed25519.PrivateKeySize {
		return TLSTrustBundle{}, vault.ErrFormat
	}
	body, err := b.signingBytes()
	if err != nil {
		return TLSTrustBundle{}, err
	}
	b.Signature = ed25519.Sign(organisation, body)
	// Snapshot nested slices, including caller-owned certificates and lists.
	raw, err := EncodeTLSTrustBundle(b)
	if err != nil {
		return TLSTrustBundle{}, err
	}
	return DecodeTLSTrustBundle(raw)
}

func EncodeTLSTrustBundle(b TLSTrustBundle) ([]byte, error) {
	if len(b.Signature) != ed25519.SignatureSize {
		return nil, vault.ErrFormat
	}
	if _, err := b.signingBytes(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxTLSTrustBundleBytes {
		return nil, vault.ErrFormat
	}
	return raw, nil
}

func DecodeTLSTrustBundle(raw []byte) (TLSTrustBundle, error) {
	if len(raw) == 0 || len(raw) > MaxTLSTrustBundleBytes {
		return TLSTrustBundle{}, vault.ErrFormat
	}
	var b TLSTrustBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return TLSTrustBundle{}, vault.ErrFormat
	}
	canonical, err := EncodeTLSTrustBundle(b)
	if err != nil {
		return TLSTrustBundle{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return TLSTrustBundle{}, vault.ErrFormat
	}
	return b, nil
}

func VerifyTLSTrustBundle(b TLSTrustBundle, pin TLSTrustPin) (*VerifiedTLSBundle, error) {
	if pin.WorkspaceID == uuid.Nil || pin.Signer.ID == uuid.Nil || pin.Signer.Version == 0 || len(pin.Organisation) != ed25519.PublicKeySize || pin.MinimumSequence == 0 || pin.MinimumSequence > math.MaxInt64 || (len(pin.Digest) != 0 && len(pin.Digest) != sha256.Size) {
		return nil, vault.ErrFormat
	}
	body, err := b.signingBytes()
	if err != nil {
		return nil, err
	}
	if b.WorkspaceID != pin.WorkspaceID || b.Signer != pin.Signer || !ed25519.Verify(pin.Organisation, body, b.Signature) {
		return nil, vault.ErrAuthentication
	}
	if b.Sequence < pin.MinimumSequence {
		return nil, vault.ErrRollback
	}
	raw, err := EncodeTLSTrustBundle(b)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if b.Sequence == pin.MinimumSequence && len(pin.Digest) != 0 && !bytes.Equal(digest[:], pin.Digest) {
		return nil, vault.ErrRollback
	}
	snapshot, err := DecodeTLSTrustBundle(raw)
	if err != nil {
		return nil, err
	}
	pin.Organisation = bytes.Clone(pin.Organisation)
	pin.MinimumSequence, pin.Digest = b.Sequence, bytes.Clone(digest[:])
	return &VerifiedTLSBundle{bundle: snapshot, pin: pin, raw: raw}, nil
}

func (v *VerifiedTLSBundle) Advance(next TLSTrustBundle) (*VerifiedTLSBundle, error) {
	if v == nil || len(v.raw) == 0 {
		return nil, vault.ErrFormat
	}
	return VerifyTLSTrustBundle(next, v.pin)
}

func (v *VerifiedTLSBundle) Encode() []byte {
	if v == nil {
		return nil
	}
	return bytes.Clone(v.raw)
}

// Pin returns an independent copy for authenticated durable high-water storage.
func (v *VerifiedTLSBundle) Pin() TLSTrustPin {
	if v == nil {
		return TLSTrustPin{}
	}
	pin := v.pin
	pin.Organisation, pin.Digest = bytes.Clone(pin.Organisation), bytes.Clone(pin.Digest)
	return pin
}

// Config applies authenticated roots and exact endpoint membership to every pgx
// fallback. Revocations are checked after standard chain/hostname verification,
// including on resumed TLS sessions. Existing SCRAM/channel-binding rules apply.
func (v *VerifiedTLSBundle) Config(s Settings) (*pgconn.Config, error) {
	prepared, err := v.transportSettings(s)
	if err != nil {
		return nil, err
	}
	c, err := Config(prepared)
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]bool, len(v.bundle.Revoked))
	for _, r := range v.bundle.Revoked {
		revoked[r.IssuerSPKI+":"+r.Serial] = true
	}
	check := func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 {
			return vault.ErrAuthentication
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) == 0 {
				return vault.ErrAuthentication
			}
			if chain[0].PublicKeyAlgorithm == x509.Ed25519 {
				return vault.ErrAuthentication
			}
			for i, cert := range chain {
				issuer := cert
				if i+1 < len(chain) {
					issuer = chain[i+1]
				}
				fingerprint := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
				if revoked[hex.EncodeToString(fingerprint[:])+":"+cert.SerialNumber.Text(16)] {
					return vault.ErrAuthentication
				}
			}
		}
		return nil
	}
	c.TLSConfig.VerifyConnection = check
	for _, fallback := range c.Fallbacks {
		fallback.TLSConfig.VerifyConnection = check
	}
	return c, nil
}

// Pure coordinate/root preparation, also used during offline invitation parsing.
// Driver configuration remains in Config so parsing never reads driver settings.
func (v *VerifiedTLSBundle) transportSettings(s Settings) (Settings, error) {
	if v == nil || len(v.raw) == 0 || (s.TLSBundle != nil && s.TLSBundle != v) || s.TLS != TLSVerified || len(s.CAPEM) != 0 || len(s.Endpoints) == 0 || len(s.Endpoints) > 8 {
		return Settings{}, ErrConfiguration
	}
	s.TLSBundle = nil // The delegate builds the base config, without redispatch.
	s.Endpoints = append([]Endpoint(nil), s.Endpoints...)
	for i, endpoint := range s.Endpoints {
		dns, ips, err := serverCertificateNames([]string{endpoint.Host})
		if err != nil {
			return Settings{}, ErrConfiguration
		}
		if len(dns) == 1 {
			endpoint.Host = dns[0]
		} else {
			endpoint.Host = ips[0].String()
		}
		index := sort.SearchStrings(v.bundle.Hosts, endpoint.Host)
		if index == len(v.bundle.Hosts) || v.bundle.Hosts[index] != endpoint.Host {
			return Settings{}, ErrConfiguration
		}
		s.Endpoints[i] = endpoint
	}
	s.CAPEM = nil // Do not append into a caller-owned zero-length slice's capacity.
	for _, der := range v.bundle.CAs {
		s.CAPEM = append(s.CAPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return s, nil
}
