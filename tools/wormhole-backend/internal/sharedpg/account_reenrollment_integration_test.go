package sharedpg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkAccountReenrollmentHandover(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session, trust TrustState, tls *VerifiedTLSBundle,
	actor *vault.UserKeys, request PersonalRootRecoveryRequest, endpoint Endpoint,
	issue func(string) ([]byte, []byte, []byte)) (*AccountReenrollment, func(bool)) {
	t.Helper()
	endpoints := []Endpoint{endpoint}
	if supported, err := session.AccountReenrollmentSupported(ctx); err != nil || !supported {
		t.Fatal("the server did not advertise atomic re-enrollment", err)
	}
	if rejected, err := session.PrepareAccountReenrollment(ctx, trust, tls, endpoints, actor, request.AccountID, request.Suspension+1); rejected != nil || !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("a stale suspension produced a replacement offer", err)
	}
	prepared, err := session.PrepareAccountReenrollment(ctx, trust, tls, endpoints, actor, request.AccountID, request.Suspension)
	if err != nil {
		t.Fatal("custodian could not prepare a scoped replacement offer", err)
	}
	defer prepared.Close()
	if err := prepared.BorrowHandover(func([]byte, []byte, []byte) error { t.Fatal("unpublished factors escaped the custodian"); return nil }); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("unpublished replacement could be handed over", err)
	}
	for range 2 {
		if err := session.PublishAccountReset(ctx, trust, prepared); err != nil {
			t.Fatal("temporary replacement login publication did not reconcile", err)
		}
	}
	var replacement *AccountReenrollment
	var activate func(bool)
	if err := prepared.BorrowHandover(func(document, code, ask []byte) error {
		offer, err := parseAccountOffer(document)
		if err != nil || offer.Version != 2 || offer.Subject.UserID != request.AccountID || offer.Subject.Suspension != request.Suspension {
			t.Fatal("replacement offer lost its signed scope", err)
		}
		if !prepared.MatchesReenrollment(request.AccountID, offer.Subject.LoginName, request.Suspension) ||
			prepared.MatchesReenrollment(request.AccountID, "different-recipient", request.Suspension) ||
			prepared.MatchesReenrollment(request.AccountID, offer.Subject.LoginName, request.Suspension+1) {
			t.Fatal("handover could be displayed with a different recipient or suspension")
		}
		if keys, err := OpenAccountReset(ctx, document, code, ask); keys != nil || !errors.Is(err, ErrAccountRecovery) {
			t.Fatal("ordinary password reset accepted a replacement bootstrap", err)
		}
		if opened, err := OpenAccountReenrollment(ctx, document, code, bytes.Repeat([]byte{9}, 32)); opened != nil || err == nil {
			t.Fatal("opening a replacement without its ASK produced keys", err)
		}
		settings, _, err := offer.transport(time.Now())
		if err != nil {
			return err
		}
		login, err := resetEnrollmentLogin(offer, code)
		if err != nil {
			return err
		}
		defer vault.Wipe(login)
		conn, err := Connect(ctx, settings, login)
		if err != nil {
			return err
		}
		defer closeDeploymentConnection(conn)
		hash := sha256.Sum256(document)
		if raw, err := readAccountResetRow(ctx, conn, fetchAccountResetSQL,
			[][]byte{[]byte(offer.ID.String()), hex.AppendEncode(nil, hash[:])}, 1, 1024); raw != nil || err == nil {
			t.Fatal("replacement login fetched a capsule through the ordinary reset API", err)
		}
		if r := conn.ExecParams(ctx, `SELECT replacement FROM wormhole_data.account_reset_offers`, nil, nil, nil, nil).Read(); !hasSQLState(r.Err, "42501", 0) {
			t.Fatal("replacement login could read private offer storage", r.Err)
		}
		replacement, err = OpenAccountReenrollment(ctx, document, code, ask)
		if err != nil {
			return err
		}
		another, err := OpenAccountReenrollment(ctx, document, code, ask)
		if err != nil {
			return err
		}
		defer another.Keys.Wipe()
		selected := replacement.Certificate.Rekey
		if bytes.Equal(selected.Public.Encryption, offer.UserPublic.Encryption) || bytes.Equal(selected.Public.Signing, offer.UserPublic.Signing) ||
			bytes.Equal(selected.Public.Encryption, another.Certificate.Rekey.Public.Encryption) || bytes.Equal(selected.Public.Signing, another.Certificate.Rekey.Public.Signing) {
			t.Fatal("recipient did not generate a fresh key pair locally")
		}
		setIssuer := func(admin string) {
			t.Helper()
			if r := dba.ExecParams(ctx, `UPDATE wormhole_data.users SET is_admin=$2::boolean WHERE id=$1::uuid`,
				[][]byte{[]byte(trust.UserID.String()), []byte(admin)}, nil, nil, nil).Read(); r.Err != nil {
				t.Fatal(r.Err)
			}
		}
		setIssuer("false")
		blocked, err := OpenAccountReenrollment(ctx, document, code, ask)
		setIssuer("true")
		if blocked != nil || !errors.Is(err, ErrAccountRecovery) {
			t.Fatal("offer remained usable after its custodian lost authority", err)
		}
		replacement.Keys.Wipe()
		if issue != nil {
			document, code, ask := issue(offer.Subject.LoginName)
			defer vault.Wipe(code)
			defer vault.Wipe(ask)
			appOffer, err := parseAccountOffer(document)
			if err != nil || appOffer.Version != 2 || appOffer.Subject.UserID != offer.Subject.UserID ||
				appOffer.Subject.LoginName != offer.Subject.LoginName || appOffer.Subject.Suspension != offer.Subject.Suspension {
				t.Fatal("the protected offer lost the reviewed suspension", err)
			}
			replacement, activate = redeemAccountReenrollmentInElectron(t, ctx, dba, appOffer, document, code, ask, os.Getenv("WORMHOLE_TEST_REENROLLMENT_ELECTRON"))
		} else {
			replacement, activate = redeemAccountReenrollmentFixture(t, ctx, offer, document, code, ask)
		}
		return nil
	}); err != nil {
		t.Fatal("recipient could not open and rekey a published replacement", err)
	}
	return replacement, activate
}

func issueAccountReenrollmentInElectron(t *testing.T, ctx context.Context, recovery *PreparedWorkspaceRecovery,
	issuerASK []byte, login, electron string) (document, code, ask []byte) {
	t.Helper()
	fixture, err := filepath.Abs("../../../../tests/fixtures/vault-shared-reenrollment-issuer.cjs")
	if err != nil || os.Getenv("WORMHOLE_TEST_RESET_ELECTRON_NATIVE") == "" {
		t.Fatal("configure the Electron re-enrollment fixture and native backend", err)
	}
	dir := t.TempDir()
	var handover, diagnostics bytes.Buffer
	defer func() { vault.Wipe(handover.Bytes()) }()
	err = recovery.BorrowJoin(func(invitation Invitation, code []byte) error {
		token, err := EncodeInvitation(invitation, time.Now())
		if err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{"invitation": token, "code": code, "ask": issuerASK, "login": login})
		if err != nil {
			return err
		}
		defer vault.Wipe(payload)
		issuerCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		child := exec.CommandContext(issuerCtx, electron, fixture)
		hidePostgresTestProcess(child)
		child.Env = append(os.Environ(), "WORMHOLE_TEST_RESET_ELECTRON_DATA="+dir)
		child.Stdin, child.Stdout, child.Stderr = bytes.NewReader(payload), &handover, &diagnostics
		return child.Run()
	})
	prefix, factors, found := bytes.Cut(handover.Bytes(), []byte("WHRESET-FIXTURE-1:"))
	const factorBytes = vault.InviteCodeBytes + 32
	if err != nil || !found || len(bytes.TrimSpace(prefix)) != 0 || len(factors) < factorBytes ||
		len(bytes.TrimSpace(factors[factorBytes:])) != 0 {
		t.Fatalf("Electron could not issue a protected replacement offer (%d bytes): %v\n%s", handover.Len(), err, diagnostics.Bytes())
	}
	document, err = os.ReadFile(filepath.Join(dir, "replacement.whreset"))
	if err != nil {
		t.Fatal(err)
	}
	return document, bytes.Clone(factors[:vault.InviteCodeBytes]), bytes.Clone(factors[vault.InviteCodeBytes:factorBytes])
}

func redeemAccountReenrollmentInElectron(t *testing.T, ctx context.Context, dba *pgconn.PgConn, offer accountResetOffer,
	document, code, ask []byte, electron string) (*AccountReenrollment, func(bool)) {
	t.Helper()
	fixture, err := filepath.Abs("../../../../tests/fixtures/vault-shared-account-reset.cjs")
	if err != nil || os.Getenv("WORMHOLE_TEST_RESET_ELECTRON_NATIVE") == "" {
		t.Fatal("configure the Electron reset fixture and native backend", err)
	}
	directory := t.TempDir()
	savedASK := bytes.Clone(ask)
	t.Cleanup(func() { vault.Wipe(savedASK) })
	run := func(stage string, code, document []byte) {
		t.Helper()
		testCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		child := exec.CommandContext(testCtx, electron, fixture)
		hidePostgresTestProcess(child)
		child.Env = append(os.Environ(), "WORMHOLE_TEST_RESET_ELECTRON_DATA="+directory, "WORMHOLE_TEST_RESET_ELECTRON_STAGE="+stage)
		child.Stdin = io.MultiReader(bytes.NewReader(code), bytes.NewReader(savedASK), bytes.NewReader(document))
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("Electron re-enrollment %s: %v\n%s", stage, err, output)
		}
	}
	run("register", code, document)

	// Inspect the actual registered keys. The fixture opens only the ciphertext
	// already published by the application using its synthetic account factors.
	row, err := readAccountResetRow(ctx, dba, `SELECT encode(e.certificate,'hex'),encode(w.nonce,'hex'),encode(w.ciphertext,'hex')
        FROM wormhole_data.user_enrollments e JOIN wormhole_data.user_key_wraps w USING(user_id)
        WHERE e.user_id=$1::uuid`, [][]byte{[]byte(offer.Subject.UserID.String())}, 3, 65536)
	if err != nil {
		t.Fatal(err)
	}
	for i := range row {
		row[i], err = hex.AppendDecode(nil, row[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	binding, public, err := resetRedemptionIdentity(offer, row[0])
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := vault.DecodeUserEnrollmentCertificate(row[0])
	if err != nil {
		t.Fatal(err)
	}
	_, policy, err := offer.transport(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	derivation, err := resetDerivation(offer, policy, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	master, err := DeriveAccountMaster(ctx, derivation, policy, []byte("Synthetic protected-window reset password"), ask)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	var keys *vault.UserKeys
	err = master.Use(func(key []byte, _ vault.KDFPreset, _ bool) error {
		keys, err = vault.OpenUserKeys(key, binding, vault.Envelope{FormatVersion: vault.FormatVersion, SuiteID: vault.SuiteAES256GCM,
			KeyID: binding.Encryption.ID.String(), KeyVersion: binding.Encryption.Version, Nonce: row[1], Ciphertext: row[2]}, public)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Wipe)
	return &AccountReenrollment{Keys: keys, Certificate: certificate, State: offer.Replacement.State}, func(suspended bool) {
		if !suspended {
			run("activate", make([]byte, vault.InviteCodeBytes), []byte{'{', '}'})
		}
	}
}

func redeemAccountReenrollmentFixture(t *testing.T, ctx context.Context, offer accountResetOffer,
	document, code, ask []byte) (*AccountReenrollment, func(bool)) {
	t.Helper()
	password := []byte("replacement device fixture password")
	p, err := PrepareAccountResetRedemption(ctx, document, code, ask, password, "Replacement device", vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	device, err := p.DeviceCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit(ctx, func(PendingAccountReset) error { return errors.New("checkpoint write failed") }); err == nil || p.submitted {
		t.Fatal("redemption submitted before the checkpoint was durable", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	_, policy, err := offer.transport(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	derivation, err := resetDerivation(offer, policy, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	master, err := DeriveAccountMaster(ctx, derivation, policy, password, ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	root, err := master.DeriveTrustRoot(ctx, device.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var resumed *PreparedAccountResetRedemption
	var pending PendingAccountReset
	err = root.Use(func(key []byte) error {
		pending, err = OpenPendingResetDevice(key, device.Binding, device.Pending)
		if err != nil {
			return err
		}
		resumed, err = ResumePreparedAccountReset(ctx, key, device.Binding, device.Pending, master, code, ask, vault.Default, vault.Default)
		return err
	})
	if err != nil {
		t.Fatal("could not resume the staged transaction", err)
	}
	defer resumed.Close()
	staged := func(got PendingAccountReset) error {
		if got.DeviceID != pending.DeviceID || !bytes.Equal(got.CapsuleDigest, pending.CapsuleDigest) {
			t.Fatal("retry changed the staged device or envelope")
		}
		return nil
	}
	resumed.pending.Certificate = []byte(`null`)
	if _, err := resumed.Commit(ctx, staged); !errors.Is(err, ErrPasswordChangePayload) || resumed.submitted {
		t.Fatal("a malformed certificate reached a committed transaction", err)
	}
	resumed.pending.Certificate = pending.Certificate
	committed, err := resumed.Commit(ctx, staged)
	if err != nil {
		t.Fatal("unable to register the account and new device after rollback", err)
	}
	binding, public, err := resetRedemptionIdentity(offer, pending.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	var keys *vault.UserKeys
	err = master.Use(func(key []byte, _ vault.KDFPreset, _ bool) error {
		keys, err = vault.OpenUserKeys(key, binding, resumed.envelope, public)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Wipe)
	certificate, err := vault.DecodeUserEnrollmentCertificate(pending.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	wrongDevice := device.Binding
	wrongDevice.DeviceID = uuid.New()
	if _, err := ReadPendingAccountReenrollmentReceipt(ctx, pending, wrongDevice, master, vault.Default, vault.Default); !errors.Is(err, ErrConfiguration) {
		t.Fatal("receipt accepted the wrong local device", err)
	}
	wrongUser := device.Binding
	wrongUser.UserID = uuid.New()
	if _, err := ReadPendingAccountReenrollmentReceipt(ctx, pending, wrongUser, master, vault.Default, vault.Default); !errors.Is(err, ErrTrustState) {
		t.Fatal("receipt accepted the wrong local account", err)
	}
	withoutCertificate := pending
	withoutCertificate.Certificate = nil
	if _, err := ReadPendingAccountReenrollmentReceipt(ctx, withoutCertificate, device.Binding, master, vault.Default, vault.Default); !errors.Is(err, vault.ErrFormat) {
		t.Fatal("receipt accepted a journal without certified replacement keys", err)
	}
	tampered := pending
	tampered.CapsuleDigest = make([]byte, 32)
	if _, err := ReadPendingAccountReenrollmentReceipt(ctx, tampered, device.Binding, master, vault.Default, vault.Default); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("receipt accepted a different staged wrapper", err)
	}
	activate := func(suspended bool) {
		t.Helper()
		receipt, err := ReadPendingAccountReenrollmentReceipt(ctx, pending, device.Binding, master, vault.Default, vault.Default)
		if err != nil || receipt.Suspended != suspended || receipt.PasswordChangeReceipt != committed {
			t.Fatal("the replacement device could not reconcile its exact receipt", receipt, err)
		}
		state, err := ConfirmPendingResetDevice(ctx, pending, device.Binding, master, vault.Default, vault.Default, "2.4.3")
		if suspended {
			if !errors.Is(err, ErrIdentityUnavailable) {
				t.Fatal("the replacement device could open a session during suspension", err)
			}
		} else if err != nil || state.Enrollment.Encryption != binding.Encryption || state.Enrollment.Signing != binding.Signing {
			t.Fatal("the re-enabled device did not receive its certified keys", err)
		}
	}
	activate(true)
	return &AccountReenrollment{Keys: keys, Certificate: certificate, State: offer.Replacement.State}, activate
}
