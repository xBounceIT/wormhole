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

func rootEnrollmentInput(t *testing.T, f nativeRotationFixture, public []byte) []byte {
	t.Helper()
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	auth := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x32}, 32)})
	defer vault.Wipe(auth)
	return vaultInput(t, map[string]any{"password": []byte("replacement protected root password"), "publicKey": public, "authentication": []byte(auth)})
}

func rootEnrollment(t *testing.T) (nativeRotationFixture, *vaultFoundationHandler, enrollmentResponse, []byte) {
	t.Helper()
	return rootEnrollmentMode(t, false, false)
}

func rootEnrollmentMode(t *testing.T, encrypted, convert bool) (nativeRotationFixture, *vaultFoundationHandler, enrollmentResponse, []byte) {
	t.Helper()
	f := nativeRootRotationMode(t, encrypted)
	h := &vaultFoundationHandler{databasePath: f.source, owner: f.owner, releaseWorkspace: f.release}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	metadata, err := h.Handle(ctx, "rotation-setup-context", nil)
	if err != nil {
		t.Fatal(err)
	}
	var hint struct {
		Slots vault.SlotFileDescriptor `json:"slots"`
	}
	if json.Unmarshal(metadata, &hint) != nil || hint.Slots.VaultID == "" || len(hint.Slots.Slots) != 1 || hint.Slots.Encrypted != encrypted {
		t.Fatal("missing current factor hint")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := rootEnrollmentInput(t, f, private.PublicKey().Bytes())
	defer vault.Wipe(input)
	operation := "rotation-setup-begin"
	if convert {
		operation = "rotation-encryption-begin"
	}
	raw, err := h.Handle(ctx, operation, input)
	if err != nil {
		t.Fatal("root enrollment", err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("current authentication retained after replacement preparation")
	}
	var response enrollmentResponse
	if json.Unmarshal(raw, &response) != nil || response.VaultID != hint.Slots.VaultID || response.Groups[0] == response.Groups[1] {
		t.Fatal("wrong root enrollment metadata")
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
	if bytes.Contains(raw, code) || bytes.Contains(raw, []byte("replacement protected root password")) {
		t.Fatal("new factor escaped display recipient")
	}
	if h.enrollment == nil || !h.enrollment.material.Locked() || h.enrollment.rotationSource == nil || h.enrollment.release != nil {
		t.Fatal("root enrollment ownership")
	}
	if h.enrollment.document.Encrypted != (encrypted || convert) {
		t.Fatal("root enrollment did not pin the intended storage mode")
	}
	for _, slot := range h.enrollment.document.Slots {
		if slot.WrappedKey.KeyVersion != 2 {
			t.Fatal("root wrap version was hardcoded to one")
		}
	}
	if _, err := os.Stat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unconfirmed enrollment published journal", err)
	}
	return f, h, response, code
}

func TestVaultRootEnrollmentConfirmsThenRequiresNewProcessResume(t *testing.T) {
	t.Run("field-encryption", func(t *testing.T) { verifyRootEnrollmentResumption(t, false, false) })
	t.Run("whole-file-encryption", func(t *testing.T) { verifyRootEnrollmentResumption(t, true, false) })
	t.Run("conversion", func(t *testing.T) { verifyRootEnrollmentResumption(t, false, true) })
}

func verifyRootEnrollmentResumption(t *testing.T, encrypted, convert bool) {
	t.Helper()
	f, h, response, code := rootEnrollmentMode(t, encrypted, convert)
	ctx := context.Background()
	pending := h.enrollment
	for _, operation := range []string{"catalog", "describe", "rotation-setup-context", "rotation-setup-begin", "enrollment-confirm", "enrollment-cancel", "fresh-action"} {
		if _, err := h.Handle(ctx, operation, nil); err == nil {
			t.Fatal("pending enrollment allowed ordinary mutation", operation)
		}
	}
	if _, err := h.Handle(ctx, "status", nil); err != nil {
		t.Fatal("public status blocked", err)
	}
	if _, err := h.Handle(ctx, "security", nil); err != nil {
		t.Fatal("native policy monitoring blocked", err)
	}
	result, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code))
	if err != nil || !h.closed || h.enrollment != nil {
		t.Fatal("confirmed root preparation", err)
	}
	var prepared struct {
		Prepared        bool   `json:"prepared"`
		RestartRequired bool   `json:"restartRequired"`
		VaultID         string `json:"vaultId"`
	}
	if json.Unmarshal(result, &prepared) != nil || !prepared.Prepared || !prepared.RestartRequired || prepared.VaultID != response.VaultID {
		t.Fatal("preparation claimed ordinary unlock")
	}
	if err := pending.material.With(func([]byte) error { t.Fatal("new material retained"); return nil }); err == nil {
		t.Fatal("retired enrollment reusable")
	}
	guard, err := readVaultSlotFile(f.source)
	if err != nil || guard.RootKeyVersion != 1 || guard.Rotation == nil || guard.Encrypted != encrypted {
		t.Fatal("prepared transition published prematurely", err)
	}
	if release, err := acquireWorkspaceOwnership(f.source, true); err == nil {
		release()
		t.Fatal("resident process released ownership before shutdown")
	}
	if _, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); err != vaultwire.ErrProtocol {
		t.Fatal("confirmed enrollment replayed", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	resumed := &vaultFoundationHandler{databasePath: f.source, migrationQuiesced: true}
	defer resumed.Close()
	payload := vaultInput(t, map[string]any{"vaultId": response.VaultID, "slotId": pending.document.Slots[0].ID, "password": []byte("replacement protected root password")})
	defer vault.Wipe(payload)
	if _, err := resumed.Handle(ctx, "rotation-resume", payload); err != nil {
		t.Fatal("confirmed root cannot resume", err)
	}
	final, err := readVaultSlotFile(f.source)
	if err != nil || final.Rotation != nil || final.Encrypted != (encrypted || convert) {
		t.Fatal("resumed enrollment changed the storage mode", err)
	}
	if err := resumed.owner.WithSecret(ctx, f.ref, 1, func(value []byte) error {
		if string(value) != "native root transition private value" {
			return vault.ErrAuthentication
		}
		return nil
	}); err != nil {
		t.Fatal("root change lost secret", err)
	}
}

func TestVaultRootEnrollmentRejectsConversionForEncryptedSource(t *testing.T) {
	f := nativeRootRotationMode(t, true)
	h := &vaultFoundationHandler{databasePath: f.source, owner: f.owner, releaseWorkspace: f.release}
	defer h.Close()
	input := rootEnrollmentInput(t, f, bytes.Repeat([]byte{3}, 32))
	if _, err := h.Handle(t.Context(), "rotation-encryption-begin", input); !errors.Is(err, vault.ErrPolicy) {
		t.Fatalf("an encrypted vault accepted another conversion: %v", err)
	}
	if !bytes.Equal(input, make([]byte, len(input))) || h.enrollment != nil {
		t.Fatal("declined conversion retained enrollment or factors")
	}
	if !h.ExitOnCancel("rotation-encryption-begin") {
		t.Fatal("cancelled conversion can leave a live service")
	}
}

func TestVaultRootEnrollmentCancelExpiryAndGroupLimitPreserveSource(t *testing.T) {
	for _, mode := range []string{"cancel", "expired", "attempts", "malformed", "changed-source", "cancelled-confirm"} {
		t.Run(mode, func(t *testing.T) {
			f, h, response, code := rootEnrollment(t)
			ctx := context.Background()
			p := h.enrollment
			before, err := os.ReadFile(f.source)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "changed-source" {
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
			} else if mode == "expired" {
				p.expires = time.Now().Add(-time.Second)
			}
			if mode == "cancelled-confirm" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			switch mode {
			case "attempts":
				wrong := vaultInput(t, map[string]any{"enrollmentId": response.EnrollmentID, "groups": []byte("!!!!!!!!!!")})
				defer vault.Wipe(wrong)
				for i := 0; i < 3; i++ {
					if _, err := h.Handle(ctx, "rotation-setup-confirm", wrong); !errors.Is(err, vault.ErrAuthentication) {
						t.Fatal(err)
					}
				}
				if _, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); !errors.Is(err, vault.ErrAuthentication) {
					t.Fatal("group attempt limit bypass", err)
				}
			case "malformed":
				if _, err := h.Handle(ctx, "rotation-setup-confirm", []byte(`{}`)); err != vaultwire.ErrProtocol {
					t.Fatal(err)
				}
			case "expired", "changed-source", "cancelled-confirm":
				if _, err := h.Handle(ctx, "rotation-setup-confirm", enrollmentConfirmation(t, response, code)); err == nil {
					t.Fatal("invalid commit accepted")
				}
			}
			if !h.closed {
				if _, err := h.Handle(context.Background(), "rotation-setup-cancel", nil); err != nil {
					t.Fatal(err)
				}
				if err := h.owner.WithSecret(context.Background(), f.ref, 1, func([]byte) error { return nil }); err != nil {
					t.Fatal("cancel retired original", err)
				}
			}
			after, err := os.ReadFile(f.source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("aborted enrollment changed source", err)
			}
			if _, err := os.Stat(rootRotationJournalPath(f.source)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("aborted enrollment created journal", err)
			}
		})
	}
}

func TestVaultRootEnrollmentRequiresCurrentFactorAndNativeOwnership(t *testing.T) {
	f := nativeRootRotation(t)
	ctx := context.Background()
	h := &vaultFoundationHandler{databasePath: f.source, owner: f.owner, releaseWorkspace: f.release}
	defer h.Close()
	if !h.ExitOnCancel("rotation-setup-begin") || !h.ExitOnCancel("rotation-setup-confirm") || h.ExitOnCancel("rotation-setup-cancel") {
		t.Fatal("root enrollment cancellation classification")
	}
	for _, payload := range [][]byte{nil, []byte(`{}`), bytes.Repeat([]byte{' '}, 16*1024+1)} {
		if _, err := h.Handle(ctx, "rotation-setup-begin", payload); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := h.rootRotationSetupContext(ctx, []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		doc, err := readVaultSlotFile(f.source)
		if err != nil {
			t.Fatal(err)
		}
		auth := vaultInput(t, map[string]any{"vaultId": doc.VaultID, "slotId": doc.Slots[0].ID, "recoveryKey": bytes.Repeat([]byte{0x47}, 32)})
		payload := vaultInput(t, map[string]any{"password": []byte("replacement protected root password"), "publicKey": bytes.Repeat([]byte{1}, 32), "authentication": []byte(auth)})
		_, err = h.Handle(ctx, "rotation-setup-begin", payload)
		vault.Wipe(payload)
		vault.Wipe(auth)
		if !errors.Is(err, vault.ErrAuthentication) {
			t.Fatal("wrong factor error", err)
		}
		if h.enrollment != nil {
			t.Fatal("wrong current factor prepared new material")
		}
	}
	if !h.closed {
		t.Fatal("current-factor attempt limit did not retire owner")
	}
	missing := &vaultFoundationHandler{databasePath: f.source}
	if _, err := missing.Handle(ctx, "rotation-setup-context", nil); err != vaultwire.ErrProtocol {
		t.Fatal("ownerless enrollment", err)
	}
}
