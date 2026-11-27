package vault

import (
	"crypto/ed25519"
	"encoding/binary"
	"math"

	"github.com/google/uuid"
)

// OrganisationRecoveryRecipient binds a workspace's escrow recipient to its
// independently pinned organisation signer. A database row alone does not
// authorize wrapping any account keys.
type OrganisationRecoveryRecipient struct {
	WorkspaceID uuid.UUID
	Encryption  KeyRef
	Signer      KeyRef
	PublicKey   []byte
}

func (r OrganisationRecoveryRecipient) signingBytes() ([]byte, error) {
	if r.WorkspaceID == uuid.Nil || r.Encryption.ID == uuid.Nil || r.Signer.ID == uuid.Nil ||
		r.Encryption.ID == r.Signer.ID || r.Encryption.Version == 0 || r.Encryption.Version > math.MaxInt32 ||
		r.Signer.Version == 0 || r.Signer.Version > math.MaxInt32 {
		return nil, ErrFormat
	}
	if err := validateX25519Public(r.PublicKey); err != nil {
		return nil, ErrFormat
	}
	return canonical("wormhole/v1/organisation-recovery-recipient",
		r.WorkspaceID[:], r.Encryption.ID[:], binary.BigEndian.AppendUint32(nil, r.Encryption.Version),
		r.Signer.ID[:], binary.BigEndian.AppendUint32(nil, r.Signer.Version), r.PublicKey), nil
}

func SignOrganisationRecoveryRecipient(recipient OrganisationRecoveryRecipient, signingSeed []byte) ([]byte, error) {
	if len(signingSeed) != ed25519.SeedSize {
		return nil, ErrFormat
	}
	body, err := recipient.signingBytes()
	if err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(signingSeed)
	defer Wipe(key)
	return ed25519.Sign(key, body), nil
}

func VerifyOrganisationRecoveryRecipient(recipient OrganisationRecoveryRecipient, signature []byte, workspace uuid.UUID, signer KeyRef, public ed25519.PublicKey) error {
	body, err := recipient.signingBytes()
	if err != nil {
		return err
	}
	if recipient.WorkspaceID != workspace || recipient.Signer != signer ||
		len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, body, signature) {
		return ErrAuthentication
	}
	return nil
}
