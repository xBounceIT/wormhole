package sharedpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

const accountReenrollmentReceiptSQL = `SELECT wrap_revision::text,auth_epoch::text,suspended::text
	FROM wormhole_api_v1.account_reenrollment_receipt($1::uuid,pg_catalog.decode($2,'hex'),$3::uuid,
	pg_catalog.decode($4,'hex'),pg_catalog.decode($5,'hex'))`

type AccountReenrollmentReceipt struct {
	PasswordChangeReceipt
	Suspended bool
}

// ReadPendingAccountReenrollmentReceipt reconciles the protected submission
// with the new device's SCRAM login. It does not create a workspace session.
func ReadPendingAccountReenrollmentReceipt(ctx context.Context, pending PendingAccountReset, b TrustBinding, master *AccountMaster,
	osFloor, userFloor vault.Profile) (receipt AccountReenrollmentReceipt, err error) {
	if ctx == nil || master == nil || b.DeviceID != pending.DeviceID {
		return receipt, ErrConfiguration
	}
	offer, settings, _, derivation, err := resetConfirmationFacts(pending, osFloor, userFloor)
	if err != nil {
		return receipt, err
	}
	if offer.Version != 2 || offer.WorkspaceID != b.WorkspaceID || offer.Subject.UserID != b.UserID ||
		master.WorkspaceID() != b.WorkspaceID || master.LoginName() != offer.Subject.LoginName ||
		master.preset != derivation.Preset || !master.askUsed {
		return receipt, ErrTrustState
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
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
		conn, err := Connect(ctx, settings, login)
		if err != nil {
			return err
		}
		defer closeDeploymentConnection(conn)
		digest := sha256.Sum256(pending.Offer)
		row, err := readAccountResetRow(ctx, conn, accountReenrollmentReceiptSQL, [][]byte{
			[]byte(offer.ID.String()), hex.AppendEncode(nil, digest[:]), []byte(b.DeviceID.String()),
			hex.AppendEncode(nil, pending.CapsuleDigest), hex.AppendEncode(nil, pending.certificateDigest(offer)),
		}, 3, 32)
		if err != nil {
			return err
		}
		switch string(row[2]) {
		case "true":
			receipt.Suspended = true
		case "false":
		default:
			return ErrAccountResetUncertain
		}
		receipt.PasswordChangeReceipt, err = parseResetReceipt(row[:2], offer.Subject.WrapRevision+1)
		return err
	})
	if err != nil {
		return AccountReenrollmentReceipt{}, err
	}
	return receipt, nil
}
