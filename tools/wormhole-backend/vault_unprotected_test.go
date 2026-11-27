package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func unprotectedHandler(t *testing.T, path string) *vaultFoundationHandler {
	t.Helper()
	h := &vaultFoundationHandler{databasePath: path}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func TestUnprotectedOrdinaryCreateReopenAndAuthenticatedProtection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace.db")
	h := unprotectedHandler(t, path)
	if _, err := h.Handle(ctx, "protection", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "unprotected-create", nil); err != nil {
		t.Fatal(err)
	}
	doc, err := readVaultSlotFile(path)
	if err != nil || doc.Initializing || doc.FormatVersion != 3 || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected {
		t.Fatal("bad OS creation", err)
	}
	raw, err := h.Handle(ctx, "protection", nil)
	if err != nil || string(raw) != `{"protected":false}` {
		t.Fatal("unauthenticated protection", string(raw), err)
	}
	if _, err := h.Handle(ctx, "protection", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "unprotected-open", nil); err != vaultwire.ErrProtocol {
		t.Fatal("second owner admitted", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	next := unprotectedHandler(t, path)
	if _, err := next.Handle(ctx, "unprotected-open", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Handle(ctx, "workspace", nil); err != nil {
		t.Fatal(err)
	}
	if next.owner == nil || !next.owner.LockedMemory() {
		t.Fatal("unlocked native root")
	}
	if _, err := openVaultUnlockFactor(ctx, doc, &vaultUnlockInput{VaultID: doc.VaultID, SlotID: doc.Slots[0].ID}); err != vault.ErrPolicy {
		t.Fatal("ordinary factor accepts OS slot", err)
	}
	protected := vaultCredentialFixture(t)
	raw, err = protected.Handle(ctx, "protection", nil)
	if err != nil || string(raw) != `{"protected":true}` {
		t.Fatal(string(raw), err)
	}
}

func TestUnprotectedOrdinaryNeverRepairsCustodyOrFallsBack(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"missing", "corrupt", "wrong-mac", "protected", "shared", "rotation", "migration", "invalid-database", "new-over-existing"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			h := unprotectedHandler(t, path)
			if _, err := h.Handle(ctx, "unprotected-create", nil); err != nil {
				t.Fatal(err)
			}
			doc, err := readVaultSlotFile(path)
			if err != nil {
				t.Fatal(err)
			}
			custody, _, err := vaultUnprotectedKeyIdentity(path, doc.VaultID, doc.Slots[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "shared":
				if err := os.Mkdir(sharedWorkspaceDirectory(path), 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(custody); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(custody, []byte("invalid OS blob"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-mac":
				doc.Authentication[0] ^= 1
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(vaultSlotPath(path), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "protected":
				other, key := localSlotFixture(t)
				defer vault.Wipe(key)
				raw, err := vault.EncodeSlotFile(key, other)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(vaultSlotPath(path), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "rotation":
				if err := os.WriteFile(rootRotationJournalPath(path), []byte("invalid journal"), 0600); err != nil {
					t.Fatal(err)
				}
			case "migration":
				if err := os.WriteFile(path+".migrating-sentinel.setup", []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-database":
				if err := os.WriteFile(path, []byte("not SQLite"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			beforeSlots, _ := os.ReadFile(vaultSlotPath(path))
			beforeCustody, custodyErr := os.ReadFile(custody)
			next := unprotectedHandler(t, path)
			op := "unprotected-open"
			if change == "new-over-existing" {
				op = "unprotected-create"
			}
			if _, err := next.Handle(ctx, op, nil); err == nil {
				t.Fatal("corrupt source opened")
			}
			after, _ := os.ReadFile(path)
			afterSlots, _ := os.ReadFile(vaultSlotPath(path))
			afterCustody, afterErr := os.ReadFile(custody)
			if !bytes.Equal(before, after) || !bytes.Equal(beforeSlots, afterSlots) || !bytes.Equal(beforeCustody, afterCustody) || errors.Is(custodyErr, os.ErrNotExist) != errors.Is(afterErr, os.ErrNotExist) {
				t.Fatal("source was repaired or changed")
			}
			if change == "invalid-database" && (!next.closed || next.releaseWorkspace == nil) {
				t.Fatal("uncertain native open did not retain exclusion")
			}
		})
	}
}

func TestUnprotectedOrdinaryResumesAuthenticatedInitialization(t *testing.T) {
	ctx := context.Background()
	for _, markerOnly := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "workspace.db")
		h := unprotectedHandler(t, path)
		if _, err := h.Handle(ctx, "unprotected-create", nil); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		doc, err := readVaultSlotFile(path)
		if err != nil {
			t.Fatal(err)
		}
		factor, err := openVaultUnprotectedKey(ctx, path, doc.VaultID, doc.Slots[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		key, err := vault.OpenUnprotectedSlot(doc.VaultID, doc.Slots[0], factor)
		vault.Wipe(factor)
		if err != nil {
			t.Fatal(err)
		}
		doc.Initializing, doc.Sequence, doc.ProfileSequence = true, 1, 0
		raw, err := vault.EncodeSlotFile(key, doc)
		vault.Wipe(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vaultSlotPath(path), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if markerOnly {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		next := unprotectedHandler(t, path)
		if _, err := next.Handle(ctx, "unprotected-open", nil); err != nil {
			t.Fatal("initialization not resumed", err)
		}
		final, err := readVaultSlotFile(path)
		if err != nil || final.Initializing || final.Sequence != 2 {
			t.Fatal("marker not finalized", err)
		}
	}
}

func TestUnprotectedProtectionRetiresOnAuthenticatedPolicyUpgrade(t *testing.T) {
	ctx := context.Background()
	h := unprotectedHandler(t, filepath.Join(t.TempDir(), "workspace.db"))
	if _, err := h.Handle(ctx, "unprotected-create", nil); err != nil {
		t.Fatal(err)
	}
	p, err := h.owner.ReadLocalPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy.Sequence++
	if _, err := h.owner.PutLocalPolicy(ctx, p.Policy, vault.Standard, p.Policy.Sequence-1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "protection", nil); !errors.Is(err, vaultwire.ErrRetired) {
		t.Fatal("stale unprotected assurance returned", err)
	}
	if !h.closed {
		t.Fatal("owner still admitted")
	}
}

func TestUnprotectedOrdinaryRejectsMaintenanceAndStoredHigherFloor(t *testing.T) {
	ctx := context.Background()
	f, _, _ := upgradeEnrollmentSource(t)
	h := unprotectedHandler(t, f.source)
	for _, operation := range []string{"unprotected-create", "unprotected-open"} {
		if !h.ExitOnCancel(operation) {
			t.Fatal("cancellation did not retire native open", operation)
		}
	}
	if _, err := h.Handle(ctx, "unprotected-open", nil); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("ordinary owner bypassed stored Standard floor", err)
	}
	if h.owner != nil || !h.closed || h.releaseWorkspace == nil {
		t.Fatal("failed source owner adopted or lease lost")
	}
	for _, change := range []string{"maintenance", "enrollment", "retirement", "lease", "no-path", "payload", "cancelled", "held-workspace"} {
		t.Run(change, func(t *testing.T) {
			next := unprotectedHandler(t, filepath.Join(t.TempDir(), "workspace.db"))
			var payload []byte
			requestCtx := ctx
			switch change {
			case "maintenance":
				next.migrationQuiesced = true
			case "enrollment":
				next.enrollment = &vaultEnrollment{}
			case "retirement":
				next.rotationMaterial = &uncertainRotationRelease{}
			case "lease":
				next.releaseWorkspace = func() {}
			case "no-path":
				next.databasePath = ""
			case "payload":
				payload = []byte(`{"vaultId":"caller-selected"}`)
			case "cancelled":
				var cancel context.CancelFunc
				requestCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "held-workspace":
				release, err := acquireWorkspaceOwnership(next.databasePath, true)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			}
			if _, err := next.Handle(requestCtx, "unprotected-create", payload); err == nil {
				t.Fatal("invalid source admitted")
			}
			// Synthetic guard states own no native enrollment resources.
			next.enrollment, next.rotationMaterial = nil, nil
		})
	}
}
