package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestPostgresInvitationContinuationAfterNativeOwnerRetirement(t *testing.T) {
	s, secret := postgresTestCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := Connect(ctx, s, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	i := seedInitialApplicationInvitation(t, ctx, admin, s)
	code, password := bytes.Repeat([]byte{31}, 16), []byte("continuation native password")
	defer vault.Wipe(code)
	defer vault.Wipe(password)
	preparing := NewSession()
	defer preparing.Close(context.Background())
	if err := preparing.OpenInitialInvitation(ctx, i, code, vault.Default, vault.Default, true); err != nil {
		t.Fatal(err)
	}
	initial, err := preparing.PrepareInitialEnrollment(ctx, i, code, password, nil, "interrupted before dispatch", vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer initial.Close()
	var sealed, deviceFile []byte
	var binding TrustBinding
	var pending PendingEnrollment
	if err := initial.Borrow(func(_ *AccountMaster, root *DeviceTrustRoot, p *PreparedInvitationCommit) error {
		binding = root.Binding()
		var err error
		pending, err = p.PendingEnrollment(binding)
		if err != nil {
			return err
		}
		return root.Use(func(key []byte) error { sealed, err = p.SealContinuation(key, binding, i); return err })
	}); err != nil {
		t.Fatal(err)
	}
	deviceFile = bytes.Clone(initial.deviceFile)
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	if err := preparing.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The original preparation, verifier and native roots are gone. Only encrypted
	// device/continuation files and authenticated public pending metadata survive.
	slots, _, err := DecodeDeviceEnrollmentFile(deviceFile)
	if err != nil {
		t.Fatal(err)
	}
	account, err := OpenDeviceAccount(ctx, deviceFile, DeviceUnlockSelection{VaultID: slots.VaultID, FileID: slots.FileID, SlotID: slots.Slots[0].ID, MinimumSequence: slots.Sequence}, password, nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer account.Close()
	assertSQL := func(query string) {
		t.Helper()
		r := admin.ExecParams(ctx, query, nil, nil, nil, nil).Read()
		if r.Err != nil || len(r.Rows) != 1 || string(r.Rows[0][0]) != "true" {
			t.Fatal("independent continuation assertion", r.Err)
		}
	}
	err = account.Borrow(func(master *AccountMaster, root *DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			r := admissionRequest()
			r.WorkspaceID, r.UserID, r.DeviceID = binding.WorkspaceID, binding.UserID, binding.DeviceID
			o := InvitationContinuationOptions{Request: r, Observed: pending, OSFloor: vault.Default, UserFloor: vault.Default, AcknowledgeTLSOff: true}
			first, second := NewSession(), NewSession()
			defer first.Close(context.Background())
			defer second.Close(context.Background())
			resume := func(session *Session) (*PreparedInvitationCommit, error) {
				c, err := OpenInvitationContinuation(key, binding, master, sealed)
				if err != nil {
					return nil, err
				}
				return session.ResumeInvitationContinuation(ctx, c, code, o, func(next PendingEnrollment) error {
					if err := o.Observed.ValidateObservationAdvance(binding, next); err != nil {
						return err
					}
					o.Observed = next
					return nil
				})
			}
			p1, err := resume(first)
			if err != nil {
				return err
			}
			defer p1.Wipe()
			p2, err := resume(second)
			if err != nil {
				return err
			}
			defer p2.Wipe()
			assertSQL(`SELECT (NOT EXISTS(SELECT 1 FROM wormhole_data.devices) AND NOT EXISTS(SELECT 1 FROM wormhole_data.user_enrollments) AND NOT EXISTS(SELECT 1 FROM wormhole_data.audit_log WHERE action='join_workspace') AND (SELECT used_at IS NULL FROM wormhole_data.invites))::text`)
			if p1.device != binding.DeviceID || p2.device != binding.DeviceID {
				return ErrTrustState
			}
			if err := first.CommitInvitation(ctx, p1); err != nil {
				return err
			}
			// Both callers passed fresh proof before either mutation. The one-use
			// server transaction must still reject the second prepared request.
			if err := second.CommitInvitation(ctx, p2); !errors.Is(err, ErrInvitation) {
				t.Fatal("duplicate continuation was not rejected", err)
			}
			if err := first.Close(context.Background()); err != nil {
				return err
			}
			if err := second.Close(context.Background()); err != nil {
				return err
			}
			third := NewSession()
			defer third.Close(context.Background())
			if p, err := resume(third); err == nil || p != nil {
				if p != nil {
					p.Wipe()
				}
				t.Fatal("consumed temporary login allowed another continuation")
			}
			var material, login []byte
			if err := master.Use(func(secret []byte, _ vault.KDFPreset, _ bool) error {
				var err error
				material, err = vault.DeriveKey(secret, nil, vault.PurposeLogin)
				return err
			}); err != nil {
				return err
			}
			defer vault.Wipe(material)
			login, err = EncodeLoginSecret(material)
			if err != nil {
				return err
			}
			defer vault.Wipe(login)
			settings := s
			settings.DeviceRole = p1.role
			native := NewSession()
			defer native.Close(context.Background())
			if err := native.Open(ctx, settings, login, ChangePolicy{TransactionPooler: true}); err != nil {
				return err
			}
			if _, err := native.AuthenticateSession(ctx, r, material); err != nil {
				return err
			}
			materialFromServer, err := native.AccountEnrollmentMaterial(ctx)
			if err != nil {
				return err
			}
			proof, err := native.VerifyPendingEnrollment(ctx, binding, o.Observed, master, materialFromServer)
			if err != nil {
				return err
			}
			if _, err := native.ConfirmVerifiedEnrollment(ctx, binding, o.Observed, proof); err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal("native continuation and independent device proof", err)
	}
	assertSQL(`SELECT ((SELECT count(*) FROM wormhole_data.devices)=1 AND (SELECT count(*) FROM wormhole_data.user_enrollments)=1 AND (SELECT count(*) FROM wormhole_data.device_confirmations)=1 AND (SELECT count(*) FROM wormhole_data.audit_log WHERE action='join_workspace')=1 AND (SELECT used_at IS NOT NULL AND bootstrap_envelope IS NULL FROM wormhole_data.invites))::text`)
}
