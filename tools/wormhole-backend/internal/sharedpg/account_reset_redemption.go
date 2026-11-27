package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var ErrAccountResetUncertain = errors.New("account reset outcome is uncertain; verify the staged device")

const redeemAccountResetSQL = `SELECT device_id::text,wrap_revision::text,auth_epoch::text
	FROM wormhole_api_v1.redeem_account_reset($1::uuid,pg_catalog.decode($2,'hex'),pg_catalog.decode($3,'hex'),
	$4::uuid,$5::text,$6::text,$7::text,pg_catalog.decode($8,'hex'),pg_catalog.decode($9,'hex'))`
const redeemAccountReenrollmentSQL = `SELECT device_id::text,wrap_revision::text,auth_epoch::text
	FROM wormhole_api_v1.redeem_account_reenrollment($1::uuid,pg_catalog.decode($2,'hex'),pg_catalog.decode($3,'hex'),
	$4::uuid,$5::text,$6::text,$7::text,pg_catalog.decode($8,'hex'),pg_catalog.decode($9,'hex'),
	pg_catalog.decode($10,'hex'))`
const accountResetReceiptSQL = `SELECT wrap_revision::text,auth_epoch::text
	FROM wormhole_api_v1.account_reset_receipt(pg_catalog.decode($1,'hex'),$2::uuid,pg_catalog.decode($3,'hex'))`

// PendingAccountReset records one proposed device and its exact encrypted
// wrapper. Native callers persist it in protected storage before submission.
// It carries neither account factors nor authority to confirm by itself.
type PendingAccountReset struct {
	Offer         []byte          `json:"offer"`
	DeviceID      uuid.UUID       `json:"deviceId"`
	KDF           vault.KDFPreset `json:"kdf"`
	CapsuleDigest []byte          `json:"capsuleDigest"`
	Certificate   []byte          `json:"certificate,omitempty"`
}

// PreparedAccountResetRedemption owns one staged mutation. Its native owner
// serializes calls and must Close on every exit. Persist the pending device
// before attempting Commit and retain it across uncertain responses.
type PreparedAccountResetRedemption struct {
	offer     accountResetOffer
	settings  Settings
	pending   PendingAccountReset
	envelope  vault.Envelope
	verifier  []byte
	secrets   *securemem.Buffer
	device    ResetDeviceCheckpoint
	name      string
	submitted bool
}

func (p *PreparedAccountResetRedemption) Close() error {
	if p == nil {
		return nil
	}
	vault.Wipe(p.verifier)
	p.verifier = nil
	if p.secrets == nil {
		return nil
	}
	if err := p.secrets.Close(); err != nil {
		return err
	}
	p.secrets = nil
	return nil
}

// PrepareAccountResetRedemption opens the handover with both factors and seals
// the account keys under the new password and ASK. A re-enrollment offer
// generates fresh final keys first. Preparation does not mutate the workspace.
func PrepareAccountResetRedemption(ctx context.Context, document, code, ask, password []byte, name string,
	osFloor, userFloor vault.Profile) (*PreparedAccountResetRedemption, error) {
	if ctx == nil || len(name) == 0 || len(name) > 4096 || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 ||
		len(password) == 0 || len(password) > 1024 {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	offer, err := parseAccountOffer(document)
	if err != nil {
		return nil, err
	}
	settings, policy, err := offer.transport(time.Now())
	if err != nil {
		return nil, err
	}
	derivation, err := resetDerivation(offer, policy, osFloor, userFloor)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(document)
	keys, err := openAccountReset(ctx, offer, settings, digest, code, ask)
	if err != nil {
		return nil, err
	}
	defer keys.Wipe()
	p := &PreparedAccountResetRedemption{offer: offer, settings: settings, name: name,
		pending: PendingAccountReset{Offer: bytes.Clone(document), DeviceID: uuid.New(), KDF: derivation.Preset}}
	if offer.Replacement != nil {
		replacement, err := prepareAccountReenrollmentKeys(ctx, offer, keys, time.Now())
		if err != nil {
			return nil, err
		}
		keys = replacement.Keys
		defer keys.Wipe()
		p.pending.Certificate, err = vault.EncodeUserEnrollmentCertificate(replacement.Certificate)
		if err != nil {
			return nil, err
		}
	}
	binding, _, err := resetRedemptionIdentity(offer, p.pending.Certificate)
	if err != nil {
		return nil, err
	}
	master, err := DeriveAccountMaster(ctx, derivation, policy, password, ask)
	if err != nil {
		return nil, err
	}
	defer master.Close()
	err = master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
		p.envelope, err = vault.SealUserKeys(secret, binding, keys)
		if err != nil {
			return err
		}
		derived, err := vault.DeriveKey(secret, nil, vault.PurposeLogin)
		if err != nil {
			return err
		}
		defer vault.Wipe(derived)
		p.verifier, err = NewSCRAMVerifier(derived)
		return err
	})
	if err != nil {
		return nil, err
	}
	p.pending.CapsuleDigest = enrollmentCapsuleDigest(p.envelope)
	p.device, err = p.prepareDeviceCheckpoint(ctx, master, password, ask, policy, derivation.EffectiveProfile, osFloor, userFloor)
	if err != nil {
		p.Close()
		return nil, err
	}
	if err := p.bindResetFactors(ctx, code, ask); err != nil {
		if cleanupErr := p.Close(); cleanupErr != nil {
			return p, errors.Join(err, cleanupErr)
		}
		return nil, err
	}
	return p, nil
}

func resetRedemptionIdentity(offer accountResetOffer, raw []byte) (vault.UserKeyBinding, vault.UserPublicKeys, error) {
	binding := offer.Subject.binding(offer.WorkspaceID)
	if offer.Version == 1 && len(raw) == 0 {
		return binding, offer.UserPublic, nil
	}
	if offer.Version != 2 || offer.Replacement == nil || len(raw) > maxAccountReenrollmentBootstrap {
		return binding, vault.UserPublicKeys{}, ErrAccountRecovery
	}
	certificate, err := vault.DecodeUserEnrollmentCertificate(raw)
	if err != nil {
		return binding, vault.UserPublicKeys{}, err
	}
	bootstrap := offer.Replacement
	expected := certificate
	expected.Manifest, expected.BootstrapEncryption, expected.BootstrapSigning = bootstrap.Manifest, bootstrap.Encryption, bootstrap.Signing
	encoded, err := vault.EncodeUserEnrollmentCertificate(expected)
	if err != nil || !bytes.Equal(encoded, raw) {
		return binding, vault.UserPublicKeys{}, vault.ErrAuthentication
	}
	pin := vault.UserKeyTrust{WorkspaceID: offer.WorkspaceID, UserID: offer.Subject.UserID, Signer: offer.Signer,
		Organisation: offer.Organisation, MinimumSequence: bootstrap.State.Sequence}
	if err := vault.VerifyUserEnrollmentCertificate(certificate, bootstrap.State, pin, 1); err != nil {
		return binding, vault.UserPublicKeys{}, err
	}
	final := certificate.Rekey
	binding.Encryption = vault.KeyRef{ID: final.EncryptionKeyID, Version: final.KeyVersion}
	binding.Signing = vault.KeyRef{ID: final.SigningKeyID, Version: final.KeyVersion}
	return binding, final.Public, nil
}

func (p *PreparedAccountResetRedemption) bindResetFactors(ctx context.Context, code, ask []byte) error {
	var err error
	p.secrets, err = securemem.New(64, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(p.pending.Offer)
	return p.secrets.With(func(secret []byte) error {
		login, err := vault.DeriveInviteLogin(code, p.offer.codeContext())
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		proof, err := accountResetKey(code, ask, digest, "wormhole/v1/account-reset-commit")
		if err != nil {
			return err
		}
		defer vault.Wipe(proof)
		copy(secret[:32], login)
		copy(secret[32:], proof)
		return ctx.Err()
	})
}

func resetDerivation(offer accountResetOffer, policy vault.Policy, osFloor, userFloor vault.Profile) (AccountDerivation, error) {
	profile := vault.EffectiveProfile(osFloor, policy.Profile, userFloor)
	if profile != vault.Default && profile != vault.Standard {
		return AccountDerivation{}, vault.ErrPolicy
	}
	workspace, err := vault.Parameters(policy.KDF)
	if err != nil {
		return AccountDerivation{}, err
	}
	previous, err := vault.Parameters(offer.Subject.MinimumKDF)
	if err != nil {
		return AccountDerivation{}, err
	}
	rank := []vault.KDFPreset{vault.KDFLow, vault.KDFV1, vault.KDFV2, vault.KDFV3}
	for _, preset := range rank {
		// Iteration and memory minima, not the server's unsignable proposed preset.
		selected, _ := vault.Parameters(preset)
		if (preset == vault.KDFLow && (profile != vault.Default || !policy.LowKDFApproved)) ||
			selected.MemoryKiB < max(workspace.MemoryKiB, previous.MemoryKiB) ||
			selected.Iterations < max(workspace.Iterations, previous.Iterations) {
			continue
		}
		return AccountDerivation{WorkspaceID: offer.WorkspaceID, LoginName: offer.Subject.LoginName,
			Preset: preset, ASKRequired: true, EffectiveProfile: profile}, nil
	}
	return AccountDerivation{}, vault.ErrPolicy
}

// Commit invokes stage before sending any write. The callback must durably
// save the native checkpoint and must not call methods on this owner.
func (p *PreparedAccountResetRedemption) Commit(ctx context.Context, stage func(PendingAccountReset) error) (PasswordChangeReceipt, error) {
	if ctx == nil || p == nil || stage == nil || p.secrets == nil || p.submitted || time.Now().Unix() >= p.offer.ExpiresAt {
		return PasswordChangeReceipt{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return PasswordChangeReceipt{}, err
	}
	pending := p.pending
	pending.Offer, pending.CapsuleDigest = bytes.Clone(pending.Offer), bytes.Clone(pending.CapsuleDigest)
	pending.Certificate = bytes.Clone(pending.Certificate)
	if err := stage(pending); err != nil {
		return PasswordChangeReceipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var receipt PasswordChangeReceipt
	err := p.secrets.With(func(secret []byte) error {
		login, err := EncodeLoginSecret(secret[:32])
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		conn, err := Connect(ctx, p.settings, login)
		if err != nil {
			return err
		}
		defer closeDeploymentConnection(conn)
		row, err := readAccountResetRow(ctx, conn, accountResetPublicationReadySQL, nil, 1, 8)
		if err != nil {
			return err
		}
		if string(row[0]) != "true" {
			return ErrAccountResetLogging
		}
		digest := sha256.Sum256(p.pending.Offer)
		proof := hex.AppendEncode(nil, secret[32:])
		defer vault.Wipe(proof)
		args := [][]byte{[]byte(p.offer.ID.String()), hex.AppendEncode(nil, digest[:]), proof, []byte(p.pending.DeviceID.String()),
			[]byte(p.name), p.verifier, []byte(p.pending.KDF), hex.AppendEncode(nil, p.envelope.Nonce),
			hex.AppendEncode(nil, p.envelope.Ciphertext)}
		statement := redeemAccountResetSQL
		if p.offer.Replacement != nil {
			statement = redeemAccountReenrollmentSQL
			args = append(args, hex.AppendEncode(nil, p.pending.Certificate))
		}
		p.submitted = true
		row, err = readAccountResetRow(ctx, conn, statement, args, 3, 36)
		if err != nil {
			if knownPasswordChangeRejection(err) || err == ErrAccountRecovery || err == ErrAccountResetLogging {
				p.submitted = false
				return err
			}
			return ErrAccountResetUncertain
		}
		if string(row[0]) != p.pending.DeviceID.String() {
			return ErrAccountResetUncertain
		}
		receipt, err = parseResetReceipt(row[1:], p.offer.Subject.WrapRevision+1)
		return err
	})
	return receipt, err
}

func parseResetReceipt(row [][]byte, expected uint64) (PasswordChangeReceipt, error) {
	if len(row) != 2 {
		return PasswordChangeReceipt{}, ErrAccountResetUncertain
	}
	revision, revisionOK := treeNumber(row[0], 2, math.MaxInt64)
	epoch, epochOK := treeNumber(row[1], 1, math.MaxInt64)
	if !revisionOK || !epochOK || revision != expected {
		return PasswordChangeReceipt{}, ErrAccountResetUncertain
	}
	return PasswordChangeReceipt{WrappingRevision: revision, AuthEpoch: epoch}, nil
}
