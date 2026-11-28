package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// VerifiedEnrollment is native, ephemeral evidence bound to an exact protected
// pending record. It cannot be constructed through JSON or persisted as proof.
// It does not prove that confirmation or local trust publication is durable.
type VerifiedEnrollment struct {
	owner             *Session
	binding           TrustBinding
	pendingDigest     [32]byte
	certificateDigest [32]byte
	state             TrustState
}

func (v *VerifiedEnrollment) Activation(b TrustBinding, p PendingEnrollment) (TrustState, error) {
	if v == nil || v.binding != b || !p.valid(b) {
		return TrustState{}, ErrTrustState
	}
	raw, err := json.Marshal(p)
	if err != nil || sha256.Sum256(raw) != v.pendingDigest {
		return TrustState{}, ErrTrustState
	}
	return cloneTrustState(v.state), nil
}

func (v *VerifiedEnrollment) CertificateDigest() []byte {
	if v == nil {
		return nil
	}
	return bytes.Clone(v.certificateDigest[:])
}

// VerifyPendingEnrollment requires a fresh audited login for this exact device.
// The caller must first persist profile/account/TLS observations in p, then pass
// the material obtained through AccountEnrollmentMaterial. There is no fallback
// to a different pair, capsule, wrapping revision, account epoch or device.
func (s *Session) VerifyPendingEnrollment(ctx context.Context, b TrustBinding, p PendingEnrollment, master *AccountMaster, material *UnverifiedAccountKeys) (*VerifiedEnrollment, error) {
	if ctx == nil || !p.valid(b) || master == nil || master.WorkspaceID() != b.WorkspaceID || master.loginName != p.Certificate.Manifest.Context.LoginName {
		return nil, ErrConfiguration
	}
	if err := take(ctx, s.control); err != nil {
		return nil, err
	}
	defer give(s.control)
	if s.lifetime.Err() != nil || !s.ready.Load() {
		return nil, ErrSessionClosed
	}
	if s.capability == nil || s.authEpoch != 1 || s.admission.WorkspaceID != b.WorkspaceID || s.admission.UserID != b.UserID || s.admission.DeviceID != b.DeviceID {
		return nil, ErrAuthentication
	}
	current := p.ObservedTrust()
	if material == nil || material.State == nil || material.EnrollmentCertificate == nil || material.EncryptionCertificate != nil || material.SigningCertificate != nil || !reflect.DeepEqual(material.State, current.Account) || material.KDF != p.KDF || material.ASKRequired != p.ASKRequired || !bytes.Equal(enrollmentCapsuleDigest(material.Envelope), p.CapsuleDigest) {
		return nil, ErrAccountRevision
	}
	certificate, err := vault.EncodeUserEnrollmentCertificate(*material.EnrollmentCertificate)
	if err != nil {
		return nil, err
	}
	expected, err := vault.EncodeUserEnrollmentCertificate(p.Certificate)
	if err != nil || !bytes.Equal(certificate, expected) {
		return nil, ErrAccountRevision
	}
	expectedBinding := vault.UserKeyBinding{WorkspaceID: b.WorkspaceID, UserID: b.UserID, Encryption: vault.KeyRef{ID: p.Certificate.Rekey.EncryptionKeyID, Version: 1}, Signing: vault.KeyRef{ID: p.Certificate.Rekey.SigningKeyID, Version: 1}, Revision: 1}
	if material.Binding != expectedBinding {
		return nil, ErrAccountRevision
	}
	trust, err := current.AccountTrust()
	if err != nil {
		return nil, err
	}
	policy, err := current.Policy()
	if err != nil {
		return nil, err
	}
	if (policy.Profile == vault.Hardened || policy.Profile == vault.Paranoid) && (!master.Locked() || !s.capability.Locked()) {
		return nil, securemem.ErrUnavailable
	}
	err = master.Use(func(secret []byte, preset vault.KDFPreset, ask bool) error {
		if preset != p.KDF || ask != p.ASKRequired {
			return ErrAccountRevision
		}
		actual := policy
		actual.KDF, actual.ASKRequired = preset, ask
		if err := actual.Validate(); err != nil {
			return err
		}
		floor, _ := vault.Parameters(policy.KDF)
		selected, _ := vault.Parameters(preset)
		if selected.MemoryKiB < floor.MemoryKiB || selected.Iterations < floor.Iterations || (policy.ASKRequired && !ask) || (policy.Profile == vault.Hardened && s.administrator && !ask) {
			return vault.ErrPolicy
		}
		keys, err := vault.OpenEnrolledUserKeys(secret, material.Binding, material.Envelope, *material.EnrollmentCertificate, *material.State, trust, p.Certificate.Manifest.Revision)
		if keys != nil {
			keys.Wipe()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	next, err := current.AdvanceEnrollment(*material.EnrollmentCertificate, 1)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.lifetime.Err() != nil {
		return nil, ErrSessionClosed
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, ErrTrustState
	}
	return &VerifiedEnrollment{owner: s, binding: b, pendingDigest: sha256.Sum256(raw), certificateDigest: sha256.Sum256(certificate), state: next}, nil
}

// ConfirmedEnrollment is emitted only after the same verified device session has
// completed its audited permanent-login confirmation. Local publication remains
// a separate durable operation and must match the exact pending snapshot.
type ConfirmedEnrollment struct{ verified *VerifiedEnrollment }

func (c *ConfirmedEnrollment) ConfirmedActivation(b TrustBinding, p PendingEnrollment) (TrustState, error) {
	if c == nil {
		return TrustState{}, ErrTrustState
	}
	return c.verified.Activation(b, p)
}

func (s *Session) ConfirmVerifiedEnrollment(ctx context.Context, b TrustBinding, p PendingEnrollment, v *VerifiedEnrollment) (*ConfirmedEnrollment, error) {
	if v == nil || v.owner != s {
		return nil, ErrAuthentication
	}
	if _, err := v.Activation(b, p); err != nil {
		return nil, err
	}
	if err := s.ConfirmEnrollment(ctx, v.CertificateDigest()); err != nil {
		return nil, err
	}
	return &ConfirmedEnrollment{verified: v}, nil
}
