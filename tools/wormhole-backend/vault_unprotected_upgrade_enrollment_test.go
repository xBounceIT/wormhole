package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func upgradeEnrollmentSource(t *testing.T) (nativeRotationFixture, string, *vaultFoundationHandler) {
	t.Helper()
	f, path := nativeOSRotation(t)
	ctx := context.Background()
	p, err := f.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	if _, err := f.owner.PutLocalPolicy(ctx, p.Policy, vault.Standard, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.release()
	h := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return f, path, h
}

func startUpgradeEnrollment(t *testing.T, h *vaultFoundationHandler) (enrollmentResponse, []byte) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := vaultInput(t, map[string]any{"password": []byte("new isolated upgrade password"), "publicKey": private.PublicKey().Bytes()})
	defer vault.Wipe(input)
	raw, err := h.Handle(context.Background(), "rotation-upgrade-begin", input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("enrollment password frame retained")
	}
	var response enrollmentResponse
	if json.Unmarshal(raw, &response) != nil || response.EnrollmentID == "" {
		t.Fatal("bad upgrade enrollment response")
	}
	info := []byte("wormhole/v1/recovery-display")
	for _, field := range []string{response.VaultID, response.EnrollmentID} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(response.Bundle.Enc, key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	code, err := recipient.Open(nil, response.Bundle.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(code) })
	if bytes.Contains(raw, code) || bytes.Contains(raw, []byte("new isolated upgrade password")) {
		t.Fatal("upgrade factors escaped protected recipient")
	}
	return response, code
}

func TestUnprotectedUpgradeEnrollmentConfirmsBeforeReadingOldOSCustody(t *testing.T) {
	f, path, h := upgradeEnrollmentSource(t)
	ctx := context.Background()
	metadata, err := h.Handle(ctx, "rotation-upgrade-context", nil)
	if err != nil || !bytes.Contains(metadata, []byte(`"vaultId"`)) || bytes.Contains(metadata, []byte("slots")) {
		t.Fatal("upgrade context", err)
	}
	before, err := os.ReadFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Missing old custody cannot be read at begin: only confirmed groups may
	// open it. Restore this exact test fixture preimage before the commit.
	response, code := startUpgradeEnrollment(t, h)
	if h.owner != nil || h.enrollment == nil || !h.enrollment.unprotectedUpgrade || !h.enrollment.material.Locked() {
		t.Fatal("ordinary source owner admitted")
	}
	if _, err := os.Lstat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unconfirmed upgrade published journal", err)
	}
	if err := os.WriteFile(path, protected, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "rotation-upgrade-context", nil); err == nil {
		t.Fatal("pending upgrade allowed another source selection")
	}
	for _, operation := range []string{"unlock", "catalog", "rotation-setup-begin", "enrollment-confirm"} {
		if _, err := h.Handle(ctx, operation, nil); err == nil {
			t.Fatal("pending upgrade admitted ordinary operation", operation)
		}
	}
	if _, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); err != nil {
		t.Fatal("confirmed forward upgrade", err)
	}
	if !h.closed || h.owner != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace == nil {
		t.Fatal("prepared upgrade adopted/released source")
	}
	after, err := os.ReadFile(f.source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preparation changed source graph", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("OS custody retired before isolated resume", err)
	}
	if release, err := acquireWorkspaceOwnership(f.source, true); err == nil {
		release()
		t.Fatal("lease released before confirmed native exit")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	// A fresh handler must prove a NEW recovery factor, then retire the old OS
	// custody and adopt only the protected Standard target.
	journal, err := os.ReadFile(rootRotationJournalPath(f.source))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := decodeRootRotationCapsule(journal)
	if err != nil {
		t.Fatal(err)
	}
	resumed := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
	defer resumed.Close()
	payload := vaultInput(t, map[string]any{"vaultId": response.VaultID, "slotId": bootstrap.Document.Slots[1].ID, "recoveryCode": code})
	defer vault.Wipe(payload)
	if _, err := resumed.Handle(ctx, "rotation-resume", payload); err != nil {
		t.Fatal("new recovery factor could not resume", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old OS custody remains", err)
	}
	profile, err := resumed.owner.ReadSecurityProfile(ctx)
	if err != nil || profile.Effective != vault.Standard {
		t.Fatal("source policy lowered", err)
	}
	if err := resumed.owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
		if string(value) != "native root transition private value" {
			return vault.ErrAuthentication
		}
		return nil
	}); err != nil {
		t.Fatal("upgraded secret unavailable", err)
	}
}

func TestUnprotectedUpgradeEnrollmentCancelExpiryAndAttemptLimitPreserveSource(t *testing.T) {
	for _, mode := range []string{"cancel", "expired", "attempts", "source-changed"} {
		t.Run(mode, func(t *testing.T) {
			f, _, h := upgradeEnrollmentSource(t)
			response, code := startUpgradeEnrollment(t, h)
			ctx := context.Background()
			if mode == "expired" {
				h.enrollment.expires = time.Now().Add(-time.Second)
			}
			if mode == "source-changed" {
				doc, err := readVaultSlotFile(f.source)
				if err != nil {
					t.Fatal(err)
				}
				doc.Sequence++
				raw, err := vault.EncodeSlotFile(f.old, doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(vaultSlotPath(f.source), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "attempts" {
				for i := 0; i < 3; i++ {
					bad := vaultInput(t, map[string]any{"enrollmentId": response.EnrollmentID, "groups": []byte("!!!!!!!!!!")})
					if _, err := h.Handle(ctx, "rotation-setup-confirm", bad); err == nil {
						t.Fatal("wrong groups accepted")
					}
					vault.Wipe(bad)
				}
			}
			if mode != "cancel" {
				if _, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); err == nil {
					t.Fatal("expired, consumed or changed-source enrollment committed")
				}
			}
			if mode != "source-changed" {
				if _, err := h.Handle(ctx, "rotation-setup-cancel", nil); err != nil {
					t.Fatal(err)
				}
			}
			if h.owner != nil {
				t.Fatal("aborted upgrade adopted source")
			}
			if _, err := os.Lstat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("aborted upgrade published journal", err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			release, err := acquireWorkspaceOwnership(f.source, true)
			if err != nil {
				t.Fatal("aborted upgrade retained lease", err)
			}
			release()
		})
	}
}

func TestUnprotectedUpgradeEnrollmentRequiresNativeIsolationAndExactPayload(t *testing.T) {
	_, _, h := upgradeEnrollmentSource(t)
	ctx := context.Background()
	h.migrationQuiesced = false
	if _, err := h.Handle(ctx, "rotation-upgrade-context", nil); err != vaultwire.ErrProtocol {
		t.Fatal("ordinary launch admitted forward source", err)
	}
	h.migrationQuiesced = true
	if !h.ExitOnCancel("rotation-upgrade-begin") {
		t.Fatal("cancelled enrollment can leave a live source scope")
	}
	if _, err := h.Handle(ctx, "rotation-upgrade-context", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for _, input := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{' '}, 4097), vaultInput(t, map[string]any{"password": []byte("new password"), "publicKey": make([]byte, 31)}), vaultInput(t, map[string]any{"password": []byte("new password"), "publicKey": make([]byte, 32), "quiesced": true})} {
		if _, err := h.Handle(ctx, "rotation-upgrade-begin", input); err != vaultwire.ErrProtocol {
			t.Fatal("malformed enrollment admitted", err)
		}
		vault.Wipe(input)
	}
}

type upgradeAdmissionRaceContext struct {
	context.Context
	calls  int
	inject func()
}

func (c *upgradeAdmissionRaceContext) Err() error {
	c.calls++
	if c.calls == 2 {
		c.inject()
	}
	return c.Context.Err()
}

func TestUnprotectedUpgradeEnrollmentRechecksPendingJournalAfterLease(t *testing.T) {
	f, _, h := upgradeEnrollmentSource(t)
	ctx := &upgradeAdmissionRaceContext{Context: context.Background(), inject: func() {
		if err := os.WriteFile(rootRotationJournalPath(f.source), []byte("another process published preparation"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	input := vaultInput(t, map[string]any{"password": []byte("new isolated upgrade password"), "publicKey": bytes.Repeat([]byte{1}, 32)})
	defer vault.Wipe(input)
	if _, err := h.Handle(ctx, "rotation-upgrade-begin", input); err == nil {
		t.Fatal("new enrollment bypassed a journal published before lease acquisition")
	}
	if ctx.calls < 2 || h.enrollment != nil || h.owner != nil {
		t.Fatal("race fixture did not exercise fresh source admission")
	}
	if err := os.Remove(rootRotationJournalPath(f.source)); err != nil {
		t.Fatal(err)
	}
	release, err := acquireWorkspaceOwnership(f.source, true)
	if err != nil {
		t.Fatal("rejected admission retained lease", err)
	}
	release()
}

func TestUnprotectedUpgradeEnrollmentRejectsUnauthenticatedSourceAtCommit(t *testing.T) {
	f, path, h := upgradeEnrollmentSource(t)
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	doc.Authentication[0] ^= 1
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(f.source), raw, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	response, code := startUpgradeEnrollment(t, h)
	if _, err := h.Handle(context.Background(), "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); err == nil {
		t.Fatal("unauthenticated OS source committed")
	}
	if !h.closed || h.owner != nil {
		t.Fatal("failed source authentication adopted an ordinary owner")
	}
	after, err := os.ReadFile(f.source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unauthenticated source graph changed", err)
	}
	remaining, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(factor, remaining) {
		t.Fatal("unauthenticated source custody retired", err)
	}
	if _, err := os.Stat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad source published a journal", err)
	}
}

func TestUnprotectedUpgradeEnrollmentFailedPreparationReleasesItsLease(t *testing.T) {
	f, _, h := upgradeEnrollmentSource(t)
	input := vaultInput(t, map[string]any{"password": []byte("new isolated upgrade password"), "publicKey": make([]byte, 32)})
	defer vault.Wipe(input)
	if _, err := h.Handle(context.Background(), "rotation-upgrade-begin", input); err == nil {
		t.Fatal("invalid X25519 recipient accepted")
	}
	if h.enrollment != nil || h.owner != nil {
		t.Fatal("failed preparation retained active enrollment")
	}
	release, err := acquireWorkspaceOwnership(f.source, true)
	if err != nil {
		t.Fatal("failed preparation retained lease", err)
	}
	release()
}
