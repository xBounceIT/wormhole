package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkAccountResetRedemption(t *testing.T, ctx context.Context, dba *pgconn.PgConn, document, code, ask []byte) {
	t.Helper()
	newPassword := []byte("synthetic post-reset password")
	defer vault.Wipe(newPassword)
	plan, err := PrepareAccountResetRedemption(ctx, document, code, ask, newPassword, "new device", vault.Default, vault.Default)
	if plan != nil {
		defer func() {
			if err := plan.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal("could not prepare reset redemption", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := plan.Commit(canceled, func(PendingAccountReset) error { t.Fatal("canceled reset staged"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("reset lost pre-submission cancellation", err)
	}
	login, err := resetEnrollmentLogin(plan.offer, code)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := Connect(ctx, plan.settings, login)
	vault.Wipe(login)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	_, proofErr := readAccountResetRow(ctx, holder, redeemAccountResetSQL, [][]byte{[]byte(plan.offer.ID.String()),
		hex.AppendEncode(nil, digest[:]), hex.AppendEncode(nil, make([]byte, 32)), []byte(plan.pending.DeviceID.String()),
		[]byte(plan.name), nil, nil, nil, nil}, 3, 36)
	closeDeploymentConnection(holder)
	if !errors.Is(proofErr, ErrAccountRecovery) {
		t.Fatal("SCRAM login alone could enter the mutation", proofErr)
	}
	blocked := errors.New("synthetic staging failure")
	if receipt, err := plan.Commit(ctx, func(PendingAccountReset) error { return blocked }); !errors.Is(err, blocked) ||
		receipt != (PasswordChangeReceipt{}) {
		t.Fatal("a failed checkpoint could submit a reset", err)
	}
	checkpoint := filepath.Join(t.TempDir(), "pending-reset.json")
	stage := func(p PendingAccountReset) error {
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return os.WriteFile(checkpoint, raw, 0600)
	}
	// A role collision after the old device credentials have been touched must
	// roll the entire transaction back, including the offer and old role.
	role := pgx.Identifier{"wh_" + plan.offer.RoleTag + "_d_" + plan.pending.DeviceID.String()}.Sanitize()
	if _, err := dba.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN").ReadAll(); err != nil {
		t.Fatal("could not configure the synthetic collision", err)
	}
	if _, err := plan.Commit(ctx, stage); !errors.Is(err, ErrDeviceCredentials) {
		t.Fatal("existing device-role name was adopted", err)
	}
	row, err := readDeploymentRow(ctx, dba, `SELECT (
    NOT EXISTS(SELECT FROM wormhole_data.devices d JOIN pg_catalog.pg_roles r ON r.rolname=d.role_name
      WHERE d.status='active' AND NOT r.rolcanlogin)
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("failed reset disabled an already active device", err)
	}
	if _, err := dba.Exec(ctx, "DROP ROLE "+role).ReadAll(); err != nil {
		t.Fatal("could not retire the synthetic role", err)
	}
	if _, err := plan.Commit(ctx, stage); err != nil {
		t.Fatal("reset redemption did not commit", err)
	}
	if _, err := plan.Commit(ctx, stage); !errors.Is(err, ErrConfiguration) {
		t.Fatal("the same plan could redeem twice", err)
	}
	if keys, err := OpenAccountReset(ctx, document, code, ask); keys != nil || !errors.Is(err, ErrAuthentication) {
		t.Fatal("a spent reset code remained valid", err)
	}
	if err := plan.Close(); err != nil {
		t.Fatal(err)
	}
	// Discard the commit receipt and use only the local checkpoint plus new factors.
	persisted, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	var pending PendingAccountReset
	if err := json.Unmarshal(persisted, &pending); err != nil {
		t.Fatal(err)
	}
	wrongASK := bytes.Repeat([]byte{29}, 32)
	defer vault.Wipe(wrongASK)
	if _, err := ConfirmAccountReset(ctx, pending, newPassword, wrongASK, vault.Default, vault.Default, "2.4.3"); !errors.Is(err, ErrAuthentication) {
		t.Fatal("device confirmation did not require the new ASK", err)
	}
	altered := pending
	altered.CapsuleDigest = make([]byte, len(pending.CapsuleDigest))
	if _, err := ConfirmAccountReset(ctx, altered, newPassword, ask, vault.Default, vault.Default, "2.4.3"); !errors.Is(err, ErrAccountRevision) {
		t.Fatal("device confirmation accepted an altered pending wrapper", err)
	}
	for range 2 {
		confirmed, err := ConfirmAccountReset(ctx, pending, newPassword, ask, vault.Default, vault.Default, "2.4.3")
		if err != nil {
			t.Fatal("the staged device could not reconcile the committed reset", err)
		}
		if confirmed.DeviceID != pending.DeviceID || confirmed.WrappingRevision != plan.offer.Subject.WrapRevision+1 ||
			confirmed.Enrollment == nil || confirmed.Enrollment.Signing != plan.offer.Subject.Signing ||
			confirmed.Enrollment.Encryption != plan.offer.Subject.Encryption {
			t.Fatal("reset changed the account's original keys or bound the wrong device")
		}
	}
	if bytes.Contains(persisted, newPassword) || bytes.Contains(persisted, ask) {
		t.Fatal("pending reset leaked account factors")
	}
}

func TestAccountResetRedemptionInputAndReceipt(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"", "invalid\x00name"} {
		if p, err := PrepareAccountResetRedemption(ctx, nil, nil, nil, []byte("synthetic"), name,
			vault.Default, vault.Default); p != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid device name reached reset transport", err)
		}
	}
	if p, err := PrepareAccountResetRedemption(ctx, []byte("{}"), nil, nil, []byte("synthetic"), "device",
		vault.Default, vault.Default); p != nil || !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("invalid offer reached reset preparation", err)
	}
	if _, err := ConfirmAccountReset(ctx, PendingAccountReset{}, nil, nil, vault.Default, vault.Default, "2.4.3"); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing stage metadata reached confirmation", err)
	}
	if _, err := ConfirmAccountReset(ctx, PendingAccountReset{DeviceID: uuid.New(), CapsuleDigest: make([]byte, 32)},
		nil, nil, vault.Default, vault.Default, "2.4.3"); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("missing offer reached device authentication", err)
	}
	for _, reply := range [][][]byte{nil, {[]byte("2"), []byte("0")}, {[]byte("3"), []byte("1")}, {[]byte("02"), []byte("1")}} {
		if got, err := parseResetReceipt(reply, 2); got != (PasswordChangeReceipt{}) || !errors.Is(err, ErrAccountResetUncertain) {
			t.Fatal("untrusted receipt confirmed a reset", err)
		}
	}
}

func TestAccountResetDerivationPreservesBothFloors(t *testing.T) {
	o := accountResetOffer{WorkspaceID: uuid.New(),
		Subject: accountResetSubject{LoginName: "reset-test", MinimumKDF: vault.KDFLow}}
	policy := vault.Policy{KDF: vault.KDFLow, Profile: vault.Default, LowKDFApproved: true}
	d, err := resetDerivation(o, policy, vault.Standard, vault.Default)
	if err != nil || d.Preset != vault.KDFV1 || !d.ASKRequired || d.EffectiveProfile != vault.Standard {
		t.Fatal("reset bypassed the stronger native platform floor", d, err)
	}
	o.Subject.MinimumKDF = vault.KDFV2
	d, err = resetDerivation(o, policy, vault.Default, vault.Default)
	if err != nil || d.Preset != vault.KDFV2 || !d.ASKRequired {
		t.Fatal("reset weakened the previous account parameters", d, err)
	}
	if _, err := resetDerivation(o, policy, vault.Hardened, vault.Default); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("unsupported profile authorized reset", err)
	}
	policy.KDF = "unknown"
	if _, err := resetDerivation(o, policy, vault.Default, vault.Default); err == nil {
		t.Fatal("unknown policy KDF was accepted")
	}
}
