package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const MaxUserEnrollmentCertificateBytes = MaxInviteManifestBytes + 16*1024

// UserEnrollmentCertificate carries the organisation-certified bootstrap and its
// signed transition to fresh user keys. It contains no private material. The
// organisation's current UserKeyState continues to select the bootstrap anchor;
// a later reset/revocation supersedes that anchor through its signed sequence.
type UserEnrollmentCertificate struct {
	FormatVersion       uint16             `json:"formatVersion"`
	Manifest            InviteManifest     `json:"manifest"`
	BootstrapEncryption UserKeyCertificate `json:"bootstrapEncryption"`
	BootstrapSigning    UserKeyCertificate `json:"bootstrapSigning"`
	Rekey               InviteRekeyProof   `json:"rekey"`
}

func (c UserEnrollmentCertificate) validShape() error {
	if c.FormatVersion != 1 {
		return ErrFormat
	}
	if _, err := EncodeInviteManifest(c.Manifest); err != nil {
		return err
	}
	for _, certificate := range []UserKeyCertificate{c.BootstrapEncryption, c.BootstrapSigning} {
		if _, err := certificate.signingBytes(); err != nil {
			return err
		}
		if len(certificate.Signature) != ed25519.SignatureSize {
			return ErrFormat
		}
	}
	if _, err := c.Rekey.signingBytes(c.Manifest.Context); err != nil {
		return err
	}
	if len(c.Rekey.Signature) != ed25519.SignatureSize {
		return ErrFormat
	}
	return nil
}

func EncodeUserEnrollmentCertificate(c UserEnrollmentCertificate) ([]byte, error) {
	if err := c.validShape(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > MaxUserEnrollmentCertificateBytes {
		return nil, ErrFormat
	}
	return raw, nil
}

func DecodeUserEnrollmentCertificate(raw []byte) (UserEnrollmentCertificate, error) {
	if len(raw) == 0 || len(raw) > MaxUserEnrollmentCertificateBytes {
		return UserEnrollmentCertificate{}, ErrFormat
	}
	var c UserEnrollmentCertificate
	if json.Unmarshal(raw, &c) != nil {
		return UserEnrollmentCertificate{}, ErrFormat
	}
	canonical, err := EncodeUserEnrollmentCertificate(c)
	if err != nil || !bytes.Equal(raw, canonical) {
		return UserEnrollmentCertificate{}, ErrFormat
	}
	return c, nil
}

// VerifyUserEnrollmentCertificate verifies historical certification, not a live
// invitation or device grant. It intentionally does not expire an already-enrolled
// account when its invitation expires. Join must separately enforce live expiry,
// single-use and the exact current manifest in its commit transaction.
// Current signed state and rollback floors must come from authenticated state.
func VerifyUserEnrollmentCertificate(c UserEnrollmentCertificate, state UserKeyState, trust UserKeyTrust, minimumManifestRevision uint64) error {
	if err := c.validShape(); err != nil {
		return err
	}
	if err := VerifyUserKeyState(state, trust); err != nil {
		return err
	}
	if !state.Active {
		return ErrPolicy
	}
	return verifyUserEnrollmentProof(c, state, trust, minimumManifestRevision)
}

// VerifyHistoricalUserEnrollmentCertificate verifies the organisation's past
// certification of this signing key for maintenance of already stored key
// copies. It confers no current membership, session, write or release authority.
func VerifyHistoricalUserEnrollmentCertificate(c UserEnrollmentCertificate, trust UserKeyTrust) error {
	if err := c.validShape(); err != nil {
		return err
	}
	bootstrap := UserKeyState{Encryption: c.BootstrapEncryption.Key, Signing: c.BootstrapSigning.Key}
	return verifyUserEnrollmentProof(c, bootstrap, trust, 1)
}

func verifyUserEnrollmentProof(c UserEnrollmentCertificate, state UserKeyState, trust UserKeyTrust, minimumManifestRevision uint64) error {
	context := c.Manifest.Context
	if context.WorkspaceID != trust.WorkspaceID || context.UserID != trust.UserID || state.Encryption != (KeyRef{ID: context.KeyID, Version: context.KeyVersion}) {
		return ErrAuthentication
	}
	if err := VerifyUserKeyCertificate(c.BootstrapEncryption, trust.WorkspaceID, trust.UserID, state.Encryption, "user-enc", trust.Signer, trust.Organisation, state.MinimumEncryptionCertificate); err != nil {
		return err
	}
	if err := VerifyUserKeyCertificate(c.BootstrapSigning, trust.WorkspaceID, trust.UserID, state.Signing, "user-sign", trust.Signer, trust.Organisation, state.MinimumSigningCertificate); err != nil {
		return err
	}
	if !bytes.Equal(c.Manifest.Bootstrap.Encryption, c.BootstrapEncryption.PublicKey) || !bytes.Equal(c.Manifest.Bootstrap.Signing, c.BootstrapSigning.PublicKey) {
		return ErrAuthentication
	}
	// The signature certifies this issuance permanently. Expiry is enforced at
	// enrollment, while subsequent account validity comes from the signed state.
	if err := VerifyInviteManifest(c.Manifest, context, trust.Organisation, minimumManifestRevision, c.Manifest.ExpiresAt, time.Unix(c.Manifest.ExpiresAt-1, 0)); err != nil {
		return err
	}
	for _, id := range []uuid.UUID{c.Rekey.EncryptionKeyID, c.Rekey.SigningKeyID} {
		if id == state.Encryption.ID || id == state.Signing.ID || id == trust.Signer.ID {
			return ErrAuthentication
		}
	}
	return VerifyInviteRekey(context, c.Rekey, c.Manifest.Bootstrap)
}

// PrepareUserEnrollmentCertificate additionally checks live expiry and exact
// issuance coordinates before snapshotting public certification for a join plan.
func PrepareUserEnrollmentCertificate(c UserEnrollmentCertificate, expected InviteContext, state UserKeyState, trust UserKeyTrust, minimumManifestRevision uint64, now time.Time) (UserEnrollmentCertificate, error) {
	if c.Manifest.Context != expected || c.Manifest.ExpiresAt <= now.Unix() {
		return UserEnrollmentCertificate{}, ErrAuthentication
	}
	if err := VerifyUserEnrollmentCertificate(c, state, trust, minimumManifestRevision); err != nil {
		return UserEnrollmentCertificate{}, err
	}
	raw, err := EncodeUserEnrollmentCertificate(c)
	if err != nil {
		return UserEnrollmentCertificate{}, err
	}
	return DecodeUserEnrollmentCertificate(raw)
}

// OpenEnrolledUserKeys authenticates the bootstrap-to-user chain before decrypting
// the account capsule. It does not grant database/device authorization. The caller
// must persist current-state floors and own/wipe the returned private keys.
func OpenEnrolledUserKeys(master []byte, binding UserKeyBinding, envelope Envelope, c UserEnrollmentCertificate, state UserKeyState, trust UserKeyTrust, minimumManifestRevision uint64) (*UserKeys, error) {
	if err := VerifyUserEnrollmentCertificate(c, state, trust, minimumManifestRevision); err != nil {
		return nil, err
	}
	if binding.WorkspaceID != trust.WorkspaceID || binding.UserID != trust.UserID || binding.Encryption != (KeyRef{ID: c.Rekey.EncryptionKeyID, Version: c.Rekey.KeyVersion}) || binding.Signing != (KeyRef{ID: c.Rekey.SigningKeyID, Version: c.Rekey.KeyVersion}) {
		return nil, ErrAuthentication
	}
	if binding.Revision < trust.MinimumWrappingRevision {
		return nil, ErrRollback
	}
	return OpenUserKeys(master, binding, envelope, c.Rekey.Public)
}
