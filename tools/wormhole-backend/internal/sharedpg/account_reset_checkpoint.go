package sharedpg

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const MaxResetDeviceCheckpointBytes = 4*MaxAccountResetOfferBytes + 4096

// ResetDeviceCheckpoint contains the protected device file, connection
// settings and the exact reset request encrypted under the password/ASK root.
// The native application pins this bundle to its local workspace path before
// dispatching the PostgreSQL mutation.
type ResetDeviceCheckpoint struct {
	Binding    TrustBinding
	LoginName  string
	DeviceFile []byte
	Transport  []byte
	Pending    []byte
	TLS        *VerifiedTLSBundle
}

type resetDeviceRequest struct {
	Version  uint16              `json:"version"`
	Pending  PendingAccountReset `json:"pending"`
	Envelope vault.Envelope      `json:"envelope"`
	Verifier []byte              `json:"verifier"`
	Name     string              `json:"name"`
}

func (p *PreparedAccountResetRedemption) DeviceCheckpoint() (ResetDeviceCheckpoint, error) {
	if p == nil || p.secrets == nil || len(p.device.DeviceFile) == 0 {
		return ResetDeviceCheckpoint{}, ErrConfiguration
	}
	d := p.device
	d.DeviceFile, d.Transport, d.Pending = bytes.Clone(d.DeviceFile), bytes.Clone(d.Transport), bytes.Clone(d.Pending)
	return d, nil
}

func (p *PreparedAccountResetRedemption) prepareDeviceCheckpoint(ctx context.Context, master *AccountMaster, password, ask []byte,
	policy vault.Policy, profile, osFloor, userFloor vault.Profile) (result ResetDeviceCheckpoint, err error) {
	b := TrustBinding{WorkspaceID: p.offer.WorkspaceID, UserID: p.offer.Subject.UserID, DeviceID: p.pending.DeviceID,
		KeyID: uuid.New(), KeyVersion: 1}
	root, err := master.DeriveTrustRoot(ctx, b)
	if err != nil {
		return result, err
	}
	defer root.Close()
	// This policy-only pin lives in encrypted device metadata. It contains no
	// account state or enrollment authority; the reset receipt is checked online.
	policyDigest := sha256.Sum256(p.offer.SignedPolicy)
	trust := TrustState{FormatVersion: 2, Revision: 1, WorkspaceID: b.WorkspaceID, UserID: b.UserID, DeviceID: b.DeviceID,
		SignerKeyID: p.offer.Signer.ID.String(), SignerKeyVersion: p.offer.Signer.Version, PublicKey: p.offer.Organisation,
		PolicySequence: policy.Sequence, PolicyDigest: policyDigest[:], SignedProfile: p.offer.SignedPolicy}
	trust, err = trust.AdvanceTLS(p.settings.TLSBundle)
	if err != nil {
		return result, err
	}
	settings := p.settings
	settings.Profile = profile
	settings.DeviceRole = "wh_" + p.offer.RoleTag + "_d_" + b.DeviceID.String()
	settings.Changes.TransactionPooler = true
	result = ResetDeviceCheckpoint{Binding: b, LoginName: p.offer.Subject.LoginName, TLS: settings.TLSBundle}
	err = root.Use(func(key []byte) error {
		result.Transport, err = SealTransportSetup(key, b, settings, trust, osFloor, userFloor, 1)
		if err != nil {
			return err
		}
		request := resetDeviceRequest{Version: 1, Pending: p.pending, Envelope: p.envelope, Verifier: p.verifier, Name: p.name}
		result.Pending, err = sealResetDeviceRequest(key, b, request)
		return err
	})
	if err != nil {
		return result, err
	}
	storage, err := allocateDeviceStorage(false)
	if err != nil {
		return result, err
	}
	defer storage.Close()
	err = storage.With(func(key []byte) error {
		rand.Read(key)
		slots, err := newDevicePasswordSlots(ctx, key, password, ask, p.pending.KDF)
		if err != nil {
			return err
		}
		record := deviceEnrollmentRecord{FormatVersion: 1, SlotSequence: slots.Sequence, Binding: b, LoginName: result.LoginName,
			KDF: p.pending.KDF, ASKRequired: true, Trust: trust}
		enrollment, err := sealDeviceEnrollmentRecord(key, slots, record)
		if err != nil {
			return err
		}
		result.DeviceFile, err = EncodeDeviceEnrollmentFile(key, slots, enrollment)
		return err
	})
	return result, err
}

func resetRequestBinding(b TrustBinding) (vault.Binding, error) {
	location, err := b.binding()
	location.Table = "SharedAccountReset"
	location.Field += "/pending"
	return location, err
}

func sealResetDeviceRequest(root []byte, b TrustBinding, request resetDeviceRequest) ([]byte, error) {
	location, err := resetRequestBinding(b)
	if err != nil {
		return nil, err
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return nil, err
	}
	defer vault.Wipe(key)
	raw, err := json.Marshal(request)
	defer vault.Wipe(raw)
	if err != nil || len(raw) > MaxResetDeviceCheckpointBytes/2 {
		return nil, ErrTrustState
	}
	envelope, err := vault.Seal(key, location, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func openResetDeviceRequest(root []byte, b TrustBinding, ciphertext []byte) (resetDeviceRequest, error) {
	var request resetDeviceRequest
	location, err := resetRequestBinding(b)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > MaxResetDeviceCheckpointBytes {
		return request, ErrTrustState
	}
	var envelope vault.Envelope
	if json.Unmarshal(ciphertext, &envelope) != nil {
		return request, ErrTrustState
	}
	key, err := vault.DeriveKey(root, b.WorkspaceID[:], vault.PurposeSharedTrust)
	if err != nil {
		return request, err
	}
	defer vault.Wipe(key)
	raw, err := vault.Open(key, location, envelope)
	defer vault.Wipe(raw)
	if err != nil {
		return request, err
	}
	if json.Unmarshal(raw, &request) != nil || request.Version != 1 || request.Pending.DeviceID != b.DeviceID ||
		len(request.Pending.CapsuleDigest) != sha256.Size || !bytes.Equal(enrollmentCapsuleDigest(request.Envelope), request.Pending.CapsuleDigest) ||
		ValidateSCRAMVerifier(request.Verifier) != nil {
		vault.Wipe(request.Verifier)
		return resetDeviceRequest{}, ErrTrustState
	}
	return request, nil
}

// OpenPendingResetDevice returns the recovery proof from an authenticated local
// journal, while wiping the credential verifier used only for continuation.
func OpenPendingResetDevice(root []byte, b TrustBinding, raw []byte) (PendingAccountReset, error) {
	request, err := openResetDeviceRequest(root, b, raw)
	vault.Wipe(request.Verifier)
	return request.Pending, err
}

// ResumePreparedAccountReset reopens the exact prepared transaction with
// the staged device master and the re-entered reset code and ASK. Callers
// reconcile with the ordinary device first, before attempting continuation.
func ResumePreparedAccountReset(ctx context.Context, root []byte, b TrustBinding, raw []byte, master *AccountMaster,
	code, ask []byte, osFloor, userFloor vault.Profile) (result *PreparedAccountResetRedemption, err error) {
	if ctx == nil || master == nil || len(code) != vault.InviteCodeBytes || len(ask) != 32 {
		return nil, ErrConfiguration
	}
	request, err := openResetDeviceRequest(root, b, raw)
	if err != nil {
		return nil, err
	}
	p := &PreparedAccountResetRedemption{pending: request.Pending, envelope: request.Envelope, verifier: request.Verifier, name: request.Name}
	defer func() {
		if err != nil {
			if cleanup := p.Close(); cleanup != nil {
				result, err = p, errors.Join(err, cleanup)
			}
		}
	}()
	p.offer, err = parseAccountOffer(p.pending.Offer)
	if err != nil {
		return nil, err
	}
	var policy vault.Policy
	p.settings, policy, err = p.offer.transport(time.Now())
	if err != nil {
		return nil, err
	}
	derivation, err := resetDerivation(p.offer, policy, osFloor, userFloor)
	if err != nil {
		return nil, err
	}
	if p.offer.WorkspaceID != b.WorkspaceID || p.offer.Subject.UserID != b.UserID || master.WorkspaceID() != b.WorkspaceID ||
		master.LoginName() != p.offer.Subject.LoginName || derivation.Preset != p.pending.KDF {
		return nil, ErrTrustState
	}
	binding, public, err := resetRedemptionIdentity(p.offer, p.pending.Certificate)
	if err != nil {
		return nil, err
	}
	err = master.Use(func(secret []byte, preset vault.KDFPreset, askUsed bool) error {
		if !askUsed || preset != derivation.Preset {
			return ErrTrustState
		}
		keys, err := vault.OpenUserKeys(secret, binding, p.envelope, public)
		keys.Wipe()
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := p.bindResetFactors(ctx, code, ask); err != nil {
		return nil, err
	}
	return p, nil
}
