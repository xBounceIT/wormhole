package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// ConfirmAccountReset reconciles a committed reset from protected pending
// storage even if the commit reply was lost. The new device must prove its
// password/ASK, match the exact staged wrapper and receipt, and confirm its
// enrollment before the caller can persist this trust state as active.
func ConfirmAccountReset(ctx context.Context, pending PendingAccountReset, password, ask []byte,
	osFloor, userFloor vault.Profile, appVersion string) (TrustState, error) {
	if ctx == nil {
		return TrustState{}, ErrConfiguration
	}
	offer, settings, policy, derivation, err := resetConfirmationFacts(pending, osFloor, userFloor)
	if err != nil {
		return TrustState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	master, err := DeriveAccountMaster(ctx, derivation, policy, password, ask)
	if err != nil {
		return TrustState{}, err
	}
	defer master.Close()
	return confirmAccountResetMaster(ctx, pending, offer, settings, policy, master, appVersion)
}

// ConfirmPendingResetDevice borrows the already unlocked device master.
func ConfirmPendingResetDevice(ctx context.Context, pending PendingAccountReset, b TrustBinding, master *AccountMaster,
	osFloor, userFloor vault.Profile, appVersion string) (TrustState, error) {
	if ctx == nil || master == nil || b.DeviceID != pending.DeviceID {
		return TrustState{}, ErrConfiguration
	}
	offer, settings, policy, derivation, err := resetConfirmationFacts(pending, osFloor, userFloor)
	if err != nil {
		return TrustState{}, err
	}
	if offer.WorkspaceID != b.WorkspaceID || master.WorkspaceID() != b.WorkspaceID || offer.Subject.UserID != b.UserID ||
		master.LoginName() != offer.Subject.LoginName || master.preset != derivation.Preset || !master.askUsed {
		return TrustState{}, ErrTrustState
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return confirmAccountResetMaster(ctx, pending, offer, settings, policy, master, appVersion)
}

func resetConfirmationFacts(pending PendingAccountReset, osFloor, userFloor vault.Profile) (
	offer accountResetOffer, settings Settings, policy vault.Policy, derivation AccountDerivation, err error) {
	if pending.DeviceID == uuid.Nil || len(pending.CapsuleDigest) != sha256.Size {
		err = ErrConfiguration
		return
	}
	offer, err = parseAccountOffer(pending.Offer)
	if err != nil || offer.ExpiresAt <= 0 {
		err = ErrAccountRecovery
		return
	}
	// The device's PostgreSQL expiry governs access. A device confirmed just
	// before expiry can still reconcile a lost confirmation reply later.
	settings, policy, err = offer.transport(time.Unix(min(time.Now().Unix(), offer.ExpiresAt-1), 0))
	if err != nil {
		return
	}
	if _, _, err = resetRedemptionIdentity(offer, pending.Certificate); err != nil {
		return
	}
	derivation, err = resetDerivation(offer, policy, osFloor, userFloor)
	if err != nil {
		return
	}
	if derivation.Preset != pending.KDF {
		err = vault.ErrPolicy
		return
	}
	settings.DeviceRole = "wh_" + offer.RoleTag + "_d_" + pending.DeviceID.String()
	settings.Profile = derivation.EffectiveProfile
	return
}

func confirmAccountResetMaster(ctx context.Context, pending PendingAccountReset, offer accountResetOffer, settings Settings,
	policy vault.Policy, master *AccountMaster, appVersion string) (TrustState, error) {
	request := AdmissionRequest{WorkspaceID: offer.WorkspaceID, UserID: offer.Subject.UserID, DeviceID: pending.DeviceID,
		API: 1, AppVersion: appVersion, Source: "ui"}
	session := NewSession()
	defer session.Close(context.Background())
	var state TrustState
	err := master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		derived, err := vault.DeriveKey(secret, nil, vault.PurposeLogin)
		if err != nil {
			return err
		}
		defer vault.Wipe(derived)
		login, err := EncodeLoginSecret(derived)
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		if err := session.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
			return err
		}
		admission, err := session.AuthenticateSession(ctx, request, derived)
		if err != nil {
			return err
		}
		if admission == nil || !bytes.Equal(admission.SignedProfile, offer.SignedPolicy) {
			return vault.ErrAuthentication
		}
		state, err = NewTrustState(admission, request, PolicyTrust{WorkspaceID: offer.WorkspaceID,
			SignerKeyID: offer.Signer.ID.String(), SignerKeyVersion: offer.Signer.Version, PublicKey: offer.Organisation,
			MinimumSequence: policy.Sequence})
		if err != nil {
			return err
		}
		state, err = session.verifyResetActivation(ctx, offer, pending, state, settings.TLSBundle, secret)
		return err
	})
	if err != nil {
		return TrustState{}, err
	}
	if err := session.ConfirmEnrollment(ctx, pending.certificateDigest(offer)); err != nil {
		return TrustState{}, err
	}
	return state, nil
}

func (s *Session) verifyResetActivation(ctx context.Context, offer accountResetOffer, pending PendingAccountReset,
	state TrustState, tls *VerifiedTLSBundle, secret []byte) (TrustState, error) {
	binding, _, err := resetRedemptionIdentity(offer, pending.Certificate)
	if err != nil {
		return TrustState{}, err
	}
	digest := sha256.Sum256(pending.Offer)
	err = s.queryAuthenticated(ctx, accountResetReceiptSQL, [][]byte{[]byte(offer.ID.String()),
		hex.AppendEncode(nil, digest[:])}, 64, 2, func(rows [][][]byte, _ AdmissionRequest) error {
		if len(rows) != 1 {
			return ErrAccountRecovery
		}
		r, err := parseResetReceipt(rows[0], binding.Revision)
		if err != nil || r.AuthEpoch != s.authEpoch {
			return ErrAccountRevision
		}
		return nil
	})
	if err != nil {
		return TrustState{}, err
	}
	m, err := s.AccountEnrollmentMaterial(ctx)
	if err != nil {
		return TrustState{}, err
	}
	if m == nil || m.State == nil || m.EnrollmentCertificate == nil || m.Binding != binding || m.KDF != pending.KDF ||
		!m.ASKRequired || !bytes.Equal(enrollmentCapsuleDigest(m.Envelope), pending.CapsuleDigest) {
		return TrustState{}, ErrAccountRevision
	}
	rawState, err := vault.EncodeUserKeyState(*m.State)
	if err != nil {
		return TrustState{}, err
	}
	rawCert, err := vault.EncodeUserEnrollmentCertificate(*m.EnrollmentCertificate)
	if err != nil {
		return TrustState{}, err
	}
	stateDigest, certDigest := sha256.Sum256(rawState), sha256.Sum256(rawCert)
	expectedState := offer.Subject.StateDigest
	if offer.Replacement != nil {
		state, err := vault.EncodeUserKeyState(offer.Replacement.State)
		if err != nil {
			return TrustState{}, err
		}
		digest := sha256.Sum256(state)
		expectedState = digest[:]
	}
	if !bytes.Equal(stateDigest[:], expectedState) || !bytes.Equal(certDigest[:], pending.certificateDigest(offer)) ||
		m.EnrollmentCertificate.Manifest.Context.LoginName != offer.Subject.LoginName {
		return TrustState{}, vault.ErrAuthentication
	}
	state, err = state.AdvanceAccount(*m.State, binding.Revision)
	if err != nil {
		return TrustState{}, err
	}
	anchor, err := state.AccountTrust()
	if err != nil {
		return TrustState{}, err
	}
	keys, err := vault.OpenEnrolledUserKeys(secret, m.Binding, m.Envelope, *m.EnrollmentCertificate, *m.State, anchor, 1)
	if err != nil {
		return TrustState{}, err
	}
	keys.Wipe()
	state, err = state.AdvanceEnrollment(*m.EnrollmentCertificate, binding.Revision)
	if err != nil {
		return TrustState{}, err
	}
	state, err = state.AdvanceTLS(tls)
	if err != nil {
		return TrustState{}, err
	}
	serverTLS, err := s.TLSTrustBundle(ctx)
	if err != nil {
		return TrustState{}, err
	}
	if serverTLS == nil {
		return TrustState{}, ErrTLSMetadata
	}
	rawTLS, err := EncodeTLSTrustBundle(*serverTLS)
	if err != nil || !bytes.Equal(rawTLS, offer.TLSBundle) {
		return TrustState{}, ErrTLSMetadata
	}
	return state, nil
}

func (p PendingAccountReset) certificateDigest(offer accountResetOffer) []byte {
	if offer.Replacement == nil {
		return offer.Subject.CertificateDigest
	}
	digest := sha256.Sum256(p.Certificate)
	return digest[:]
}
