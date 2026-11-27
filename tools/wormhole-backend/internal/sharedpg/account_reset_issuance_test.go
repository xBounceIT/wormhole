package sharedpg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func checkAccountResetIssuance(t *testing.T, ctx context.Context, dba *pgconn.PgConn, session *Session,
	trust TrustState, tls *VerifiedTLSBundle, actor *vault.UserKeys, endpoints []Endpoint, previous Invitation) {
	t.Helper()
	if _, err := session.PrepareAccountReset(ctx, trust, tls, endpoints, actor, "missing-account"); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("an unknown target produced a reset offer", err)
	}
	targetID := previous.Enrollment.Context.UserID
	if supported, err := session.AccountResetTargetsSupported(ctx); err != nil || !supported {
		t.Fatal("restored schema did not advertise the reset queue", err)
	}
	assertTarget := func(status string, offer uuid.UUID) {
		t.Helper()
		page, err := session.ReadAccountResetTargets(ctx, trust, tls, uuid.Nil)
		if err != nil || page.Next != nil {
			t.Fatal("could not read the restored reset queue", err)
		}
		for _, target := range page.Targets {
			if target.UserID != targetID {
				continue
			}
			if !target.Eligible || target.LoginName != previous.LoginName || target.Status != status ||
				(offer == uuid.Nil && target.OfferID != nil) ||
				(offer != uuid.Nil && (target.OfferID == nil || *target.OfferID != offer || target.ExpiresAt == 0)) {
				t.Fatalf("restored target has incorrect public handover state: %v", target)
			}
			return
		}
		t.Fatal("the original restored account is missing from the queue")
	}
	assertTarget("not-issued", uuid.Nil)
	for _, role := range []string{"false", "true"} {
		result := dba.ExecParams(ctx, "UPDATE wormhole_data.users SET is_admin=$1::boolean WHERE id=$2::uuid",
			[][]byte{[]byte(role), []byte(trust.UserID.String())}, nil, nil, nil).Read()
		if result.Err != nil || result.CommandTag.RowsAffected() != 1 {
			t.Fatal("could not change the restored administrator fixture", result.Err)
		}
		if role == "false" {
			if p, err := session.PrepareAccountReset(ctx, trust, tls, endpoints, actor, previous.LoginName); p != nil || !errors.Is(err, ErrAccountRecovery) {
				t.Fatal("an existing admitted session retained reset authority after demotion", err)
			}
			if _, err := session.ReadAccountResetTargets(ctx, trust, tls, uuid.Nil); !errors.Is(err, ErrAccountRecovery) {
				t.Fatal("a demoted custodian could read the reset queue", err)
			}
			if _, err := session.MarkAccountResetHandover(ctx, trust, tls, targetID, uuid.New()); !errors.Is(err, ErrAccountRecovery) {
				t.Fatal("a demoted custodian could change the reset queue", err)
			}
		}
	}
	prepare := func(t *testing.T, login string) *PreparedAccountReset {
		t.Helper()
		reset, err := session.PrepareAccountReset(ctx, trust, tls, endpoints, actor, login)
		if reset != nil {
			t.Cleanup(func() {
				if err := reset.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		if err != nil {
			t.Fatal("restored custodian could not prepare a reset", err)
		}
		return reset
	}
	first := prepare(t, previous.LoginName)
	device := pgx.Identifier{"wh_" + first.offer.RoleTag + "_d_" + trust.DeviceID.String()}.Sanitize()
	if _, err := dba.Exec(ctx, "GRANT SET ON PARAMETER log_parameter_max_length TO "+device).ReadAll(); err != nil {
		t.Fatal("could not set up the synthetic logging check", err)
	}
	if _, err := session.Query(ctx, "SET log_parameter_max_length=-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := session.PublishAccountReset(ctx, trust, first); !errors.Is(err, ErrAccountResetLogging) {
		t.Fatal("a reset publication reached a connection allowing statement parameter logging", err)
	}
	recipient, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	refused, issueErr := session.PublishAccountResetHandover(ctx, trust, first, recipient.PublicKey().Bytes(), uuid.New(), func([]byte) error {
		t.Fatal("logging preflight saved a file for an offer it could not issue")
		return nil
	})
	if !errors.Is(issueErr, ErrAccountResetLogging) || refused.OfferID != uuid.Nil {
		t.Fatal("logging preflight did not suppress the handover", issueErr)
	}
	if _, err := session.Query(ctx, "SET log_parameter_max_length=0", nil); err != nil {
		t.Fatal(err)
	}
	foreign := trust
	foreign.UserID = uuid.New()
	if err := session.PublishAccountReset(ctx, foreign, first); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("an offer could be published under a different issuer", err)
	}
	for _, delta := range []string{"1", "-1"} {
		changed := dba.ExecParams(ctx, "UPDATE wormhole_data.user_key_wraps SET wrap_revision=wrap_revision+$1::bigint WHERE user_id=$2::uuid",
			[][]byte{[]byte(delta), []byte(first.offer.Subject.UserID.String())}, nil, nil, nil).Read()
		if changed.Err != nil || changed.CommandTag.RowsAffected() != 1 {
			t.Fatal("could not set up the stale wrapping revision check", changed.Err)
		}
		if delta == "1" {
			if err := session.PublishAccountReset(ctx, trust, first); !errors.Is(err, ErrAccountRevision) {
				t.Fatal("an outdated account wrapper could be reset", err)
			}
		}
	}
	if err := first.BorrowHandover(func([]byte, []byte, []byte) error { t.Fatal("premature handover"); return nil }); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("unpublished offer became available", err)
	}
	for range 2 {
		if err := session.PublishAccountReset(ctx, trust, first); err != nil {
			t.Fatal("could not issue or reconcile an account reset", err)
		}
	}
	assertTarget("awaiting-handover", first.offer.ID)
	if _, err := session.MarkAccountResetHandover(ctx, trust, tls, uuid.New(), first.offer.ID); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("an offer could be recorded under a different account", err)
	}
	for range 2 {
		if status, err := session.MarkAccountResetHandover(ctx, trust, tls, targetID, first.offer.ID); err != nil || status != "handed-over" {
			t.Fatal("confirmed handover could not be recorded or retried", err)
		}
	}
	assertTarget("handed-over", first.offer.ID)
	var oldDocument, oldCode, oldASK []byte
	var oldConnection *pgconn.PgConn
	defer func() {
		if oldConnection != nil {
			closeDeploymentConnection(oldConnection)
		}
	}()
	defer func() { vault.Wipe(oldCode); vault.Wipe(oldASK) }()
	err := first.BorrowHandover(func(document, code, ask []byte) error {
		oldDocument, oldCode, oldASK = document, bytes.Clone(code), bytes.Clone(ask)
		var offer accountResetOffer
		if json.Unmarshal(document, &offer) != nil || offer.Subject.UserID != previous.Enrollment.Context.UserID ||
			offer.Subject.LoginName != previous.LoginName || offer.WorkspaceID != previous.WorkspaceID {
			t.Fatal("offer changed the original account identity")
		}
		placeholder := bytes.Repeat([]byte{27}, 32)
		defer vault.Wipe(placeholder)
		if keys, err := OpenAccountReset(ctx, document, code, placeholder); keys != nil || !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("the SCRAM role alone could open both original keys", err)
		}
		keys, err := OpenAccountReset(ctx, document, code, ask)
		if err != nil {
			return err
		}
		keys.Wipe()
		if keys, err := OpenAccountReset(ctx, document, make([]byte, vault.InviteCodeBytes+1), ask); keys != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("a malformed code reached PostgreSQL", err)
		}
		mutated := offer
		mutated.Subject.WrapRevision++
		bad, err := json.Marshal(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if keys, err := OpenAccountReset(ctx, bad, code, ask); keys != nil || !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("a modified offer authenticated", err)
		}
		settings, _, err := offer.transport(time.Now())
		if err != nil {
			return err
		}
		derived, err := vault.DeriveInviteLogin(code, offer.codeContext())
		if err != nil {
			return err
		}
		defer vault.Wipe(derived)
		password, err := EncodeLoginSecret(derived)
		if err != nil {
			return err
		}
		defer vault.Wipe(password)
		conn, err := Connect(ctx, settings, password)
		if err != nil {
			return err
		}
		oldConnection = conn
		params := [][]byte{[]byte(offer.ID.String())}
		ret := conn.ExecParams(ctx, "SELECT * FROM wormhole_api_v1.enrollment_bootstrap($1::uuid)", params, nil, nil, nil).Read()
		if !hasSQLState(ret.Err, "WH012", 0) {
			t.Fatal("reset role could consume ordinary enrollment material", ret.Err)
		}
		ret = conn.ExecParams(ctx, fetchAccountResetSQL, append(params, []byte(hex.EncodeToString(make([]byte, 32)))), nil, nil, nil).Read()
		if !hasSQLState(ret.Err, "WH023", 0) {
			t.Fatal("the reset role could request an unrelated capsule receipt", ret.Err)
		}
		return nil
	})
	if err != nil {
		t.Fatal("the reset handover could not recover the original account keys", err)
	}
	if err := first.BorrowHandover(func([]byte, []byte, []byte) error { t.Fatal("second handover"); return nil }); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("the single-use presentation was reopened", err)
	}
	next := prepare(t, previous.LoginName)
	if err := session.PublishAccountReset(ctx, trust, next); err != nil {
		t.Fatal("could not replace the previous reset issuance", err)
	}
	assertTarget("awaiting-handover", next.offer.ID)
	if _, err := session.MarkAccountResetHandover(ctx, trust, tls, targetID, first.offer.ID); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("a superseded offer changed the new offer's handover status", err)
	}
	if _, err := OpenAccountReset(ctx, oldDocument, oldCode, oldASK); !errors.Is(err, ErrAuthentication) {
		t.Fatal("a replaced reset login was still active", err)
	}
	digest := sha256.Sum256(oldDocument)
	retired := oldConnection.ExecParams(ctx, fetchAccountResetSQL, [][]byte{[]byte(first.offer.ID.String()),
		hex.AppendEncode(nil, digest[:])}, nil, nil, nil).Read()
	if !hasSQLState(retired.Err, "WH023", 0) {
		t.Fatal("an existing connection could fetch a retired offer", retired.Err)
	}
	if err := session.PublishAccountReset(ctx, trust, first); !errors.Is(err, ErrAccountRecovery) {
		t.Fatal("a retired offer could be issued again", err)
	}
	if err := next.BorrowHandover(func(document, code, ask []byte) error {
		if bytes.Equal(code, oldCode) || bytes.Equal(ask, oldASK) {
			t.Fatal("reissuing an account reset reused a factor")
		}
		keys, err := OpenAccountReset(ctx, document, code, ask)
		if keys != nil {
			keys.Wipe()
		}
		if err != nil {
			return err
		}
		checkAccountResetRedemption(t, ctx, dba, document, code, ask)
		return nil
	}); err != nil {
		t.Fatal("replacement reset was unusable", err)
	}
	rotation := prepare(t, previous.LoginName)
	if err := session.PublishAccountReset(ctx, trust, rotation); err != nil {
		t.Fatal("an account with working credentials could not be reset", err)
	}
	if err := rotation.BorrowHandover(func(document, code, ask []byte) error {
		checkAccountResetRedemption(t, ctx, dba, document, code, ask)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertTarget("redeemed", rotation.offer.ID)
	if status, err := session.MarkAccountResetHandover(ctx, trust, tls, targetID, rotation.offer.ID); err != nil || status != "redeemed" {
		t.Fatal("a handover racing with redemption failed to reconcile", err)
	}
	row, err := readDeploymentRow(ctx, dba, `SELECT (
    NOT EXISTS(SELECT FROM wormhole_data.account_reset_offers WHERE retired_at IS NULL)
    AND (SELECT count(*) FROM wormhole_data.account_reset_offers WHERE retired_at IS NOT NULL AND capsule IS NULL)=3
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='publish_account_reset' AND outcome='issued')=3
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='mark_account_reset_handover' AND outcome='handed_over')=1
    AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='redeem_account_reset' AND outcome='success')=2
    AND (SELECT count(*) FROM wormhole_data.account_reset_receipts r
      JOIN wormhole_data.device_confirmations c ON c.device_id=r.device_id)=2
    AND (SELECT count(*) FROM wormhole_data.account_reset_receipts q
      JOIN wormhole_data.devices d ON d.id=q.device_id JOIN pg_catalog.pg_roles r ON r.rolname=d.role_name
      WHERE d.status='revoked' AND NOT r.rolcanlogin AND q.auth_epoch=1)=1
    AND (SELECT count(*) FROM wormhole_data.account_reset_receipts q
      JOIN wormhole_data.devices d ON d.id=q.device_id JOIN pg_catalog.pg_roles r ON r.rolname=d.role_name
      WHERE d.status='active' AND r.rolcanlogin AND q.auth_epoch=2)=1
    AND NOT EXISTS(SELECT FROM wormhole_data.device_admissions a JOIN wormhole_data.devices d ON d.id=a.device_id
      WHERE d.status='revoked')
)::text`, 1)
	if err != nil || string(row[0]) != "true" {
		t.Fatal("resets did not consume each offer, revoke the old login and confirm the new devices", err)
	}
	if binary := os.Getenv("WORMHOLE_TEST_RESET_APP_BIN"); binary != "" {
		for _, mode := range []string{"direct", "before-submit", "after-submit"} {
			t.Run("app-"+mode, func(t *testing.T) {
				reset := prepare(t, previous.LoginName)
				if err := session.PublishAccountReset(ctx, trust, reset); err != nil {
					t.Fatal(err)
				}
				err := reset.BorrowHandover(func(document, code, ask []byte) error {
					payload, err := json.Marshal(map[string][]byte{"offer": document, "code": code, "ask": ask})
					if err != nil {
						return err
					}
					defer vault.Wipe(payload)
					args := []string{"-test.run=^TestVaultSharedAccountResetPostgresFixture$", "-test.v"}
					if cover := os.Getenv("WORMHOLE_TEST_RESET_APP_COVER"); cover != "" {
						args = append(args, "-test.coverprofile="+filepath.Join(cover, mode+".cover"))
					}
					child := exec.CommandContext(ctx, binary, args...)
					hidePostgresTestProcess(child)
					child.Env = append(os.Environ(), "WORMHOLE_TEST_RESET_APP_MODE="+mode)
					child.Stdin = bytes.NewReader(payload)
					output, err := child.CombinedOutput()
					if err != nil {
						t.Fatalf("native reset fixture failed: %v\n%s", err, output)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if executable := os.Getenv("WORMHOLE_TEST_RESET_ELECTRON"); executable != "" {
		t.Run("app-electron", func(t *testing.T) {
			fixture, err := filepath.Abs("../../../../tests/fixtures/vault-shared-account-reset.cjs")
			if err != nil || os.Getenv("WORMHOLE_TEST_RESET_ELECTRON_NATIVE") == "" {
				t.Fatal("configure the Electron reset fixture and native backend", err)
			}
			reset := prepare(t, previous.LoginName)
			if err := session.PublishAccountReset(ctx, trust, reset); err != nil {
				t.Fatal(err)
			}
			if err := reset.BorrowHandover(func(document, code, ask []byte) error {
				testCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
				defer cancel()
				child := exec.CommandContext(testCtx, executable, fixture)
				hidePostgresTestProcess(child)
				child.Env = append(os.Environ(), "WORMHOLE_TEST_RESET_ELECTRON_DATA="+t.TempDir())
				child.Stdin = io.MultiReader(bytes.NewReader(code), bytes.NewReader(ask), bytes.NewReader(document))
				if output, err := child.CombinedOutput(); err != nil {
					t.Fatalf("Electron reset fixture failed: %v\n%s", err, output)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("restored-batch", func(t *testing.T) {
		page, err := session.ReadAccountResetTargets(ctx, trust, tls, uuid.Nil)
		if err != nil || len(page.Targets) != 2 || page.Next != nil {
			t.Fatal("could not list both accounts on the restored cluster", err)
		}
		tail, err := session.ReadAccountResetTargets(ctx, trust, tls, page.Targets[0].UserID)
		if err != nil || len(tail.Targets) != 1 || tail.Targets[0].UserID != page.Targets[1].UserID {
			t.Fatal("the restored queue could not resume after the first account", err)
		}
		issued := make(map[uuid.UUID]uuid.UUID, len(page.Targets))
		for _, target := range page.Targets {
			if !target.Eligible {
				t.Fatal("the restored account or the new custodian did not have recovery keys")
			}
			reset := prepare(t, target.LoginName)
			if !reset.MatchesTarget(target.UserID) {
				t.Fatal("the listed account did not match the signed offer")
			}
			if err := session.PublishAccountReset(ctx, trust, reset); err != nil {
				t.Fatal("could not publish both accounts' offers on the restored cluster", err)
			}
			issued[target.UserID] = reset.offer.ID
		}
		for _, target := range page.Targets {
			if status, err := session.MarkAccountResetHandover(ctx, trust, tls, target.UserID, issued[target.UserID]); err != nil || status != "handed-over" {
				t.Fatal("could not record both handovers independently", err)
			}
		}
		page, err = session.ReadAccountResetTargets(ctx, trust, tls, uuid.Nil)
		if err != nil || len(page.Targets) != len(issued) {
			t.Fatal("could not reopen the restored account queue", err)
		}
		for _, target := range page.Targets {
			if target.OfferID == nil || *target.OfferID != issued[target.UserID] || target.Status != "handed-over" {
				t.Fatal("the restored queue did not retain the exact handover for each account")
			}
		}
	})
}

func TestAccountResetTargetRequiresCurrentCertifiedIdentity(t *testing.T) {
	_, binding, state, cert, _, _, _ := enrollmentTrustFixture(t)
	anchor, err := state.AccountTrust()
	if err != nil {
		t.Fatal(err)
	}
	rawState, err := vault.EncodeUserKeyState(*state.Account)
	if err != nil {
		t.Fatal(err)
	}
	rawCert, err := vault.EncodeUserEnrollmentCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, certDigest := sha256.Sum256(rawState), sha256.Sum256(rawCert)
	m := accountResetMaterial{SignedState: rawState, Enrollment: rawCert, Subject: accountResetSubject{
		UserID: binding.UserID, LoginName: cert.Manifest.Context.LoginName,
		Encryption:   vault.KeyRef{ID: cert.Rekey.EncryptionKeyID, Version: cert.Rekey.KeyVersion},
		Signing:      vault.KeyRef{ID: cert.Rekey.SigningKeyID, Version: cert.Rekey.KeyVersion},
		WrapRevision: state.WrappingRevision,
		StateDigest:  stateDigest[:], CertificateDigest: certDigest[:],
	}}
	if public, err := m.verifyTarget(state, anchor); err != nil || !bytes.Equal(public.Signing, cert.Rekey.Public.Signing) {
		t.Fatal("valid certified target was rejected", err)
	}
	future := state
	future.Catalog = map[string]CatalogFloor{"author/" + binding.UserID.String(): {Revision: state.Account.Sequence + 1, Digest: make([]byte, 32)}}
	if _, err := m.verifyTarget(future, anchor); !errors.Is(err, vault.ErrRollback) {
		t.Fatal("issuer ignored an observed account state floor", err)
	}
	for name, mutate := range map[string]func(*accountResetMaterial){
		"other user":    func(m *accountResetMaterial) { m.Subject.UserID = uuid.New() },
		"changed login": func(m *accountResetMaterial) { m.Subject.LoginName = "another-account" },
		"wrong key":     func(m *accountResetMaterial) { m.Subject.Encryption.ID = uuid.New() },
		"wrong digest":  func(m *accountResetMaterial) { m.Subject.StateDigest = make([]byte, 32) },
		"malformed state": func(m *accountResetMaterial) {
			m.SignedState = []byte("{}")
			next := sha256.Sum256(m.SignedState)
			m.Subject.StateDigest = next[:]
		},
		"malformed certificate": func(m *accountResetMaterial) {
			m.Enrollment = []byte("{}")
			next := sha256.Sum256(m.Enrollment)
			m.Subject.CertificateDigest = next[:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := m
			mutate(&changed)
			if _, err := changed.verifyTarget(state, anchor); err == nil {
				t.Fatal("substituted material authorized a reset")
			}
		})
	}
}

func TestAccountResetRejectsIncompleteKeyCustody(t *testing.T) {
	encryption := vault.KeyRef{ID: uuid.New(), Version: 1}
	signing := vault.KeyRef{ID: uuid.New(), Version: 1}
	encRow := workspaceAdminRecoveryCopy{KeyRef: encryption}
	signRow := workspaceAdminRecoveryCopy{KeyRef: signing}
	for _, rows := range [][]workspaceAdminRecoveryCopy{
		{encRow}, {encRow, encRow}, {signRow, {KeyRef: vault.KeyRef{ID: uuid.New(), Version: 1}}},
	} {
		if keys, err := openEscrowKeyPair(rows, encryption, signing, func(workspaceAdminRecoveryCopy) ([]byte, error) {
			return make([]byte, 32), nil
		}); keys != nil || !errors.Is(err, ErrAdmissionResponse) {
			t.Fatal("missing or duplicate copy formed a pair", err)
		}
	}
	if keys, err := openEscrowKeyPair([]workspaceAdminRecoveryCopy{encRow, signRow}, encryption, signing,
		func(workspaceAdminRecoveryCopy) ([]byte, error) {
			return nil, vault.ErrAuthentication
		}); keys != nil || !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("invalid copy released account material", err)
	}
	if err := verifyEscrowKeyPair(&vault.UserKeys{}, vault.UserPublicKeys{}); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("incomplete keys passed a public-pair check", err)
	}
}
