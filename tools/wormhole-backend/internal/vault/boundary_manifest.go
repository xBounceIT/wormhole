package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/google/uuid"
)

const MaxBoundaryManifestBytes = 8192

// BoundaryKey names a 256-bit X25519 boundary seed without carrying the seed.
// The public half is pinned so key-copy/DEK recipients cannot be substituted.
type BoundaryKey struct {
	Key    KeyRef `json:"key"`
	Public []byte `json:"public"`
}

// BoundaryManifest is an organisation-signed selection, not a DB permission.
// Previous roots are explicit migration windows; no other old root is accepted.
// The application must persist manifest and root-version floors before use.
type BoundaryManifest struct {
	FormatVersion  uint16       `json:"formatVersion"`
	WorkspaceID    uuid.UUID    `json:"workspaceId"`
	BoundaryID     uuid.UUID    `json:"boundaryId"`
	Revision       uint64       `json:"revision"`
	OwnerUserID    uuid.UUID    `json:"ownerUserId"`
	OrgEscrow      bool         `json:"orgEscrow"`
	Active         bool         `json:"active"`
	View           BoundaryKey  `json:"view"`
	Secret         BoundaryKey  `json:"secret"`
	PreviousView   *BoundaryKey `json:"previousView"`
	PreviousSecret *BoundaryKey `json:"previousSecret"`
	Signer         KeyRef       `json:"signer"`
	Signature      []byte       `json:"signature"`
}

type BoundaryTrust struct {
	WorkspaceID, BoundaryID uuid.UUID
	Signer                  KeyRef
	Organisation            ed25519.PublicKey
	MinimumRevision         uint64
}

func (m BoundaryManifest) signingBytes() ([]byte, error) {
	if m.FormatVersion > FormatVersion {
		return nil, ErrNewerFormat
	}
	if m.FormatVersion != FormatVersion || m.WorkspaceID == uuid.Nil || m.BoundaryID == uuid.Nil || m.Revision == 0 || m.Revision > math.MaxInt64 || (m.OwnerUserID == uuid.Nil && !m.OrgEscrow) || m.Signer.ID == uuid.Nil || m.Signer.Version == 0 || m.Signer.Version > math.MaxInt32 {
		return nil, ErrFormat
	}
	roots := []BoundaryKey{m.View, m.Secret}
	for _, pair := range []struct {
		current  BoundaryKey
		previous *BoundaryKey
	}{{m.View, m.PreviousView}, {m.Secret, m.PreviousSecret}} {
		if pair.previous != nil {
			if pair.previous.Key.ID != pair.current.Key.ID || pair.previous.Key.Version >= pair.current.Key.Version {
				return nil, ErrFormat
			}
			roots = append(roots, *pair.previous)
		}
	}
	if m.View.Key.ID == m.Secret.Key.ID {
		return nil, ErrFormat
	}
	for i, root := range roots {
		if root.Key.ID == uuid.Nil || root.Key.ID == m.Signer.ID || root.Key.Version == 0 || root.Key.Version > math.MaxInt32 || validateX25519Public(root.Public) != nil {
			return nil, ErrFormat
		}
		for _, previous := range roots[:i] {
			if bytes.Equal(root.Public, previous.Public) {
				return nil, ErrFormat
			}
		}
	}
	m.Signature = nil
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/boundary-manifest", raw), nil
}

func SignBoundaryManifest(m BoundaryManifest, organisation ed25519.PrivateKey) (BoundaryManifest, error) {
	if len(organisation) != ed25519.PrivateKeySize {
		return BoundaryManifest{}, ErrFormat
	}
	raw, err := m.signingBytes()
	if err != nil {
		return BoundaryManifest{}, err
	}
	m.Signature = ed25519.Sign(organisation, raw)
	return m, nil
}

// VerifyBoundaryManifest authenticates inactive selections too. The owner must
// persist their revision before rejecting use; authentication alone grants no
// permission, escrow policy exception or decryption authority.
func VerifyBoundaryManifest(m BoundaryManifest, trust BoundaryTrust) error {
	if trust.MinimumRevision > math.MaxInt64 {
		return ErrFormat
	}
	raw, err := m.signingBytes()
	if err != nil {
		return err
	}
	if m.WorkspaceID != trust.WorkspaceID || m.BoundaryID != trust.BoundaryID || m.Signer != trust.Signer || len(trust.Organisation) != ed25519.PublicKeySize || !ed25519.Verify(trust.Organisation, raw, m.Signature) {
		return ErrAuthentication
	}
	if m.Revision < trust.MinimumRevision {
		return ErrRollback
	}
	return nil
}

func EncodeBoundaryManifest(m BoundaryManifest) ([]byte, error) {
	if _, err := m.signingBytes(); err != nil {
		return nil, err
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxBoundaryManifestBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

// DecodeBoundaryManifest accepts only bounded canonical encoding, rejecting
// duplicate/unknown/aliased fields, missing fields and alternative JSON forms.
// Decoding does not authenticate the organisation signature.
func DecodeBoundaryManifest(raw []byte) (BoundaryManifest, error) {
	if len(raw) == 0 || len(raw) > MaxBoundaryManifestBytes {
		return BoundaryManifest{}, ErrFormat
	}
	var m BoundaryManifest
	if json.Unmarshal(raw, &m) != nil {
		return BoundaryManifest{}, ErrFormat
	}
	encoded, err := EncodeBoundaryManifest(m)
	if err != nil {
		return BoundaryManifest{}, err
	}
	if !bytes.Equal(raw, encoded) {
		return BoundaryManifest{}, ErrFormat
	}
	return m, nil
}
