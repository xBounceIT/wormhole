package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func migrationEnrollmentFixture(t *testing.T) (*vaultFoundationHandler, enrollmentResponse, []byte) {
	t.Helper()
	db, source, _, _, _, _ := migrationStageFixture(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	root, _ := browserInventoryFixture(t)
	h := &vaultFoundationHandler{databasePath: source, userDataPath: root}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := vaultInput(t, map[string]any{"password": []byte("new migration password"), "publicKey": private.PublicKey().Bytes(), "legacyMethod": "none", "legacyFactor": []byte{}})
	raw, err := h.Handle(context.Background(), "migration-setup-begin", input)
	if err != nil {
		t.Fatal(err)
	}
	var response enrollmentResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	var code []byte
	if err := h.enrollment.material.With(func(storage []byte) error { code = bytes.Clone(storage[32:]); return nil }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(code) })
	if bytes.Contains(raw, code) || bytes.Contains(raw, []byte("new migration password")) || h.owner != nil {
		t.Fatal("migration exposed pending secret or owner")
	}
	return h, response, code
}

func TestVaultMigrationEnrollmentConfirmsRecoverableSetupWithoutCutover(t *testing.T) {
	h, response, code := migrationEnrollmentFixture(t)
	ctx := context.Background()
	before, err := os.ReadFile(h.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	pending := h.enrollment
	confirmation := enrollmentConfirmation(t, response, code)
	if _, err := h.Handle(ctx, "enrollment-confirm", confirmation); err != vaultwire.ErrProtocol {
		t.Fatal("generic confirmation admitted migration", err)
	}
	if release, err := acquireWorkspaceOwnership(h.databasePath, false); err == nil {
		release()
		t.Fatal("legacy entered recovery confirmation")
	}
	if _, err := os.Stat(legacyMigrationSetupPath(pending.migration.CanonicalSource, pending.document.FileID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup committed before confirmation", err)
	}
	raw, err := h.Handle(ctx, "migration-setup-confirm", confirmation)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Prepared, RestartRequired bool
		VaultID                   string
	}
	if json.Unmarshal(raw, &result) != nil || !result.Prepared || !result.RestartRequired || result.VaultID != response.VaultID {
		t.Fatal("invalid preparation result", string(raw))
	}
	if h.owner != nil || h.enrollment != nil || !pending.closed || pending.material.With(func([]byte) error { return nil }) != securemem.ErrClosed {
		t.Fatal("setup retained native key or published ordinary owner")
	}
	after, err := os.ReadFile(h.databasePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preparation changed original database", err)
	}
	if _, err := os.Stat(vaultSlotPath(h.databasePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup installed source cutover marker", err)
	}
	hint, err := discoverLegacyMigrationSetup(ctx, h.databasePath)
	if err != nil || hint == nil {
		t.Fatal("restart cannot discover confirmed setup", err)
	}
	recovery, err := vault.ParseRecoveryKey(code)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(recovery)
	for _, slot := range hint.Document.Slots {
		var key []byte
		if slot.Kind == vault.SlotRecovery {
			key, err = vault.OpenRecoverySlot(hint.Document.VaultID, slot, recovery)
		} else {
			key, err = vault.OpenPasswordSlot(ctx, hint.Document.VaultID, slot, []byte("new migration password"), nil)
		}
		if err != nil {
			t.Fatal("confirmed factor cannot resume", err)
		}
		setup, err := readLegacyMigrationSetup(ctx, hint.CanonicalSource, hint.Document, key)
		vault.Wipe(key)
		if err != nil || setup.Plan.WorkspaceID != response.VaultID || setup.UserData != h.userDataPath || setup.Initial.Initializing {
			t.Fatal("wrong confirmed setup", err)
		}
	}
	if requireLegacyWorkspace(h.databasePath) != errVaultOwnerRequired {
		t.Fatal("confirmed setup restored legacy access")
	}
	if _, err := h.Handle(ctx, "migration-setup-begin", vaultInput(t, map[string]any{"password": []byte("different"), "publicKey": make([]byte, 32), "legacyMethod": "none", "legacyFactor": []byte{}})); err == nil {
		t.Fatal("second migration setup accepted")
	}
}

func TestVaultMigrationEnrollmentCancelAndFailurePreserveLegacySource(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		h, response, code := migrationEnrollmentFixture(t)
		pending := h.enrollment
		if _, err := h.Handle(context.Background(), "enrollment-cancel", nil); err != nil {
			t.Fatal(err)
		}
		if h.enrollment != nil || !pending.closed {
			t.Fatal("cancel retained recovery")
		}
		if requireLegacyWorkspace(h.databasePath) != nil {
			t.Fatal("canceled setup quarantined original")
		}
		if _, err := h.Handle(context.Background(), "migration-setup-confirm", enrollmentConfirmation(t, response, code)); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	})
	t.Run("canceled commit", func(t *testing.T) {
		h, response, code := migrationEnrollmentFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := h.confirmMigrationEnrollment(ctx, enrollmentConfirmation(t, response, code)); !errors.Is(err, context.Canceled) || !h.closed {
			t.Fatal("canceled commit remained usable", err)
		}
		if requireLegacyWorkspace(h.databasePath) != nil {
			t.Fatal("canceled commit wrote setup")
		}
	})
	t.Run("authentication and shape", func(t *testing.T) {
		db, source, _, _, _, _ := migrationStageFixture(t)
		db.Close()
		h := &vaultFoundationHandler{databasePath: source, userDataPath: t.TempDir()}
		defer h.Close()
		private, _ := ecdh.X25519().GenerateKey(rand.Reader)
		for _, fields := range []map[string]any{
			{"legacyMethod": "pin", "legacyFactor": []byte("wrong")},
			{"legacyMethod": "none", "legacyFactor": []byte("unexpected")},
			{"legacyMethod": "none", "legacyFactor": nil},
			{"legacyMethod": "none", "legacyFactor": bytes.Repeat([]byte{1}, 1025)},
			{"legacyMethod": "none", "legacyFactor": []byte{}, "source": filepath.Dir(source)},
		} {
			fields["password"], fields["publicKey"] = []byte("new"), private.PublicKey().Bytes()
			if _, err := h.Handle(context.Background(), "migration-setup-begin", vaultInput(t, fields)); err == nil {
				t.Fatal("invalid migration begin accepted")
			}
			if h.owner != nil || h.enrollment != nil || requireLegacyWorkspace(source) != nil {
				t.Fatal("failed begin changed legacy authority")
			}
		}
	})
}
