package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
)

const MaxInviteManifestBytes = 1024 * 1024

type InviteIssuer struct {
	Key    KeyRef `json:"key"`
	Public []byte `json:"public"`
}

// InviteManifest is an organisation-signed snapshot of the complete bootstrap
// copy set. Its revision must be checked against authoritative state at commit.
// The organisation public key is pinned independently, never carried here.
type InviteManifest struct {
	FormatVersion uint16           `json:"formatVersion"`
	Context       InviteContext    `json:"context"`
	Revision      uint64           `json:"revision"`
	ExpiresAt     int64            `json:"expiresAt"`
	Bootstrap     UserPublicKeys   `json:"bootstrap"`
	Copies        []KeyCopyBinding `json:"copies"`
	Issuers       []InviteIssuer   `json:"issuers"`
	Signature     []byte           `json:"signature"`
}

func (m InviteManifest) signingBytes() ([]byte, error) {
	if m.FormatVersion != 1 || m.Context.KeyVersion > math.MaxInt32 || m.Revision == 0 || m.Revision > math.MaxInt64 || m.ExpiresAt <= 0 || len(m.Copies) > MaxInviteKeyCopies || len(m.Issuers) > MaxInviteKeyCopies || len(m.Bootstrap.Signing) != ed25519.PublicKeySize {
		return nil, ErrFormat
	}
	if _, _, err := m.Context.binding(); err != nil {
		return nil, err
	}
	if err := validateX25519Public(m.Bootstrap.Encryption); err != nil {
		return nil, err
	}
	issuers := make(map[KeyRef]bool, len(m.Issuers))
	for _, issuer := range m.Issuers {
		if issuer.Key.ID == uuid.Nil || issuer.Key.Version == 0 || issuer.Key.Version > math.MaxInt32 || len(issuer.Public) != ed25519.PublicKeySize {
			return nil, ErrFormat
		}
		if _, exists := issuers[issuer.Key]; exists {
			return nil, ErrFormat
		}
		issuers[issuer.Key] = false
	}
	seen := make(map[KeyRef]bool, len(m.Copies))
	for _, b := range m.Copies {
		if _, err := b.info(); err != nil {
			return nil, err
		}
		if b.WorkspaceID != m.Context.WorkspaceID || b.Holder.ID != m.Context.KeyID || b.Holder.Version != m.Context.KeyVersion || seen[b.Key] {
			return nil, ErrFormat
		}
		seen[b.Key] = true
		if _, exists := issuers[b.Issuer]; !exists {
			return nil, ErrFormat
		}
		issuers[b.Issuer] = true
	}
	for _, used := range issuers {
		if !used {
			return nil, ErrFormat
		}
	}
	m.Signature = nil
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxInviteManifestBytes {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/invite-manifest", raw), nil
}

func SignInviteManifest(m InviteManifest, organisationSeed []byte) (InviteManifest, error) {
	if len(organisationSeed) != ed25519.SeedSize {
		return InviteManifest{}, ErrFormat
	}
	raw, err := m.signingBytes()
	if err != nil {
		return InviteManifest{}, err
	}
	key := ed25519.NewKeyFromSeed(organisationSeed)
	defer Wipe(key)
	m.Signature = ed25519.Sign(key, raw)
	return m, nil
}

func VerifyInviteManifest(m InviteManifest, expected InviteContext, organisation ed25519.PublicKey, minimumRevision uint64, expiresAt int64, now time.Time) error {
	if minimumRevision == 0 || minimumRevision > math.MaxInt64 {
		return ErrFormat
	}
	if m.Context != expected || m.ExpiresAt != expiresAt || len(organisation) != ed25519.PublicKeySize || len(m.Signature) != ed25519.SignatureSize {
		return ErrAuthentication
	}
	raw, err := m.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(organisation, raw, m.Signature) {
		return ErrAuthentication
	}
	if m.Revision < minimumRevision {
		return ErrRollback
	}
	if m.ExpiresAt <= now.Unix() {
		return ErrAuthentication
	}
	return nil
}

func EncodeInviteManifest(m InviteManifest) ([]byte, error) {
	if _, err := m.signingBytes(); err != nil {
		return nil, err
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxInviteManifestBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

func DecodeInviteManifest(raw []byte) (InviteManifest, error) {
	if len(raw) == 0 || len(raw) > MaxInviteManifestBytes {
		return InviteManifest{}, ErrFormat
	}
	var m InviteManifest
	if json.Unmarshal(raw, &m) != nil {
		return InviteManifest{}, ErrFormat
	}
	canonical, err := EncodeInviteManifest(m)
	if err != nil || !bytes.Equal(raw, canonical) {
		return InviteManifest{}, ErrFormat
	}
	return m, nil
}

// PrepareCertifiedInviteRewrap connects the authenticated bootstrap to the
// organisation-signed graph before using any server-supplied issuer key or list.
func PrepareCertifiedInviteRewrap(ctx context.Context, c InviteContext, b *InviteBootstrap, m InviteManifest, copies []SignedKeyCopy, minimumRevision uint64, expiresAt int64, now time.Time) (*InviteRewrapPlan, error) {
	if ctx == nil || b == nil {
		return nil, ErrFormat
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := VerifyInviteBootstrap(b, m, c, minimumRevision, expiresAt, now); err != nil {
		return nil, err
	}
	issuers := make(map[KeyRef]ed25519.PublicKey, len(m.Issuers))
	for _, issuer := range m.Issuers {
		issuers[issuer.Key] = issuer.Public
	}
	p, err := PrepareInviteRewrap(ctx, c, b, m.Copies, copies, issuers)
	if err != nil {
		return nil, err
	}
	raw, err := EncodeInviteManifest(m)
	if err != nil {
		p.Wipe()
		return nil, err
	}
	digest := sha256.Sum256(raw)
	p.SourceManifestRevision = m.Revision
	p.SourceManifestDigest = append([]byte(nil), digest[:]...)
	return p, nil
}

// VerifyInviteBootstrap binds a code-authenticated bootstrap to its signed graph.
// It is shared by initial download and final rewrap; it consumes no keys and
// grants no authority to an organisation key from unauthenticated server data.
func VerifyInviteBootstrap(b *InviteBootstrap, m InviteManifest, expected InviteContext, minimumRevision uint64, expiresAt int64, now time.Time) error {
	if b == nil {
		return ErrFormat
	}
	if err := VerifyInviteManifest(m, expected, b.OrganisationPublic, minimumRevision, expiresAt, now); err != nil {
		return err
	}
	pub, err := (&UserKeys{EncryptionPrivate: b.EncryptionPrivate, SigningSeed: b.SigningSeed}).Public()
	if err != nil {
		return err
	}
	if !bytes.Equal(pub.Encryption, m.Bootstrap.Encryption) || !bytes.Equal(pub.Signing, m.Bootstrap.Signing) {
		return ErrAuthentication
	}
	return nil
}
