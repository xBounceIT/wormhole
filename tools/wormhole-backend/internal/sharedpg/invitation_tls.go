package sharedpg

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// InvitationTLSIdentity is public discovery material. Its key/fingerprint and
// signature are checked before connecting, but organisation authority is not
// established until the separately delivered code authenticates the bootstrap.
// Keep the bundle as canonical JSON, avoiding another base64 expansion.
type InvitationTLSIdentity struct {
	Organisation []byte          `json:"organisation"`
	Bundle       json.RawMessage `json:"bundle"`
}

func (i Invitation) invitationTLSHint() (*VerifiedTLSBundle, error) {
	identity := i.TLSIdentity
	if i.FormatVersion != 3 || i.TLS != TLSVerified || len(i.CAPEM) != 0 || identity == nil || len(identity.Organisation) != ed25519.PublicKeySize || len(identity.Bundle) == 0 || len(identity.Bundle) > MaxTLSTrustBundleBytes {
		return nil, ErrInvitation
	}
	fingerprint := sha256.Sum256(identity.Organisation)
	if !bytes.Equal(fingerprint[:], i.OrganisationFingerprint) {
		return nil, vault.ErrAuthentication
	}
	bundle, err := DecodeTLSTrustBundle(identity.Bundle)
	if err != nil {
		return nil, err
	}
	return VerifyTLSTrustBundle(bundle, TLSTrustPin{WorkspaceID: i.WorkspaceID, Signer: bundle.Signer, Organisation: identity.Organisation, MinimumSequence: 1})
}

// AuthenticatedTLSBundle promotes a v3 hint only under the code-authenticated
// organisation key and certified signer identity. Legacy explicit CA invitations
// remain readable and return nil. Persist the returned pin/cache with the pending
// enrollment before SQL; it grants no enrollment/device authorization itself.
func (i Invitation) AuthenticatedTLSBundle(organisation ed25519.PublicKey, signer vault.KeyRef) (*VerifiedTLSBundle, error) {
	if (i.FormatVersion == 1 || i.FormatVersion == 2) && i.TLSIdentity == nil {
		return nil, nil
	}
	bundle, err := i.invitationTLSHint()
	if err != nil {
		return nil, err
	}
	pin := bundle.Pin()
	if !bytes.Equal(organisation, pin.Organisation) || signer != pin.Signer {
		return nil, vault.ErrAuthentication
	}
	return bundle, nil
}

func invitationTransportSettings(s Settings) (Settings, error) {
	if s.TLSBundle != nil {
		return s.TLSBundle.transportSettings(s)
	}
	return s, nil
}

func (i Invitation) tlsBootstrapDigest() ([]byte, error) {
	if _, err := i.invitationTLSHint(); err != nil {
		return nil, err
	}
	digest := sha256.New()
	digest.Write([]byte("wormhole/v1/invite-tls"))
	digest.Write(i.TLSIdentity.Organisation) // fixed 32 bytes, followed by canonical JSON
	digest.Write(i.TLSIdentity.Bundle)
	return digest.Sum(nil), nil
}

// SealBootstrap provisions a fresh issuance with the version-appropriate AEAD
// binding. V3 always binds its signed TLS identity; never silently wrap it using
// the legacy primitive, even though both retain the frozen envelope shape.
func (i Invitation) SealBootstrap(code []byte, bootstrap *vault.InviteBootstrap, now time.Time) (vault.Envelope, error) {
	if _, err := i.EnrollmentRole(now); err != nil {
		return vault.Envelope{}, err
	}
	if i.FormatVersion == 3 {
		digest, err := i.tlsBootstrapDigest()
		if err != nil {
			return vault.Envelope{}, err
		}
		return vault.SealTLSInviteBootstrap(code, i.Enrollment.Context, bootstrap, digest)
	}
	return vault.SealInviteBootstrap(code, i.Enrollment.Context, bootstrap)
}
