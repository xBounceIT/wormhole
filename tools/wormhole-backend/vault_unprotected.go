package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This ordinary path has no upgrade admission. Both OS custody and the stored
// source policy must independently permit Default before an owner is adopted.
func (h *vaultFoundationHandler) requireUnprotectedOpen(ctx context.Context) error {
	if h.databasePath == "" || h.owner != nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil || h.migrationQuiesced {
		return vaultwire.ErrProtocol
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return err
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return err
	}
	if floor != vault.Default {
		return vault.ErrPolicy
	}
	return ctx.Err()
}

func (h *vaultFoundationHandler) openUnprotected(ctx context.Context, create bool, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if err := h.requireUnprotectedOpen(ctx); err != nil {
		return nil, err
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	// Repeat admission after the lease: a predecessor may have left a journal
	// before publishing its slot barrier.
	if err := h.requireUnprotectedOpen(ctx); err != nil {
		return nil, err
	}
	var doc vault.SlotFile
	var key []byte
	defer func() { vault.Wipe(key) }()
	if create {
		if err := requireNewVaultWorkspace(h.databasePath); err != nil {
			return nil, err
		}
		doc = vault.SlotFile{FormatVersion: vault.SlotFileFormatVersion, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(), RootKeyVersion: 1, Initializing: true, Sequence: 1, FileEpoch: 1}
		slotID := uuid.NewString()
		factor, err := createVaultUnprotectedKey(ctx, h.databasePath, doc.VaultID, slotID)
		defer vault.Wipe(factor)
		if err != nil {
			return nil, err
		}
		key = vault.NewRecoveryKey()
		slot, err := vault.CreateUnprotectedSlot(doc.VaultID, slotID, doc.RootKeyVersion, key, factor)
		if err != nil {
			return nil, err
		}
		vault.Wipe(factor)
		doc.Slots = []vault.Slot{slot}
		// OS storage may have blocked while the configured floor changed.
		if err := h.requireUnprotectedOpen(ctx); err != nil {
			return nil, err
		}
		// From first publication onward, uncertain cleanup retains the lease
		// until native Close/process retirement, even if Open returns no owner.
		h.releaseWorkspace, retained = release, true
		h.owner, err = initializeVaultFiles(ctx, h.databasePath, doc, key)
		if err != nil {
			return nil, h.retire(err)
		}
	} else {
		doc, err = readVaultSlotFile(h.databasePath)
		if err != nil {
			return nil, err
		}
		if doc.Encrypted || doc.Migration != nil || doc.Rotation != nil || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected {
			return nil, vault.ErrPolicy
		}
		factor, err := openVaultUnprotectedKey(ctx, h.databasePath, doc.VaultID, doc.Slots[0].ID)
		defer vault.Wipe(factor)
		if err != nil {
			return nil, err
		}
		key, err = vault.OpenUnprotectedSlot(doc.VaultID, doc.Slots[0], factor)
		vault.Wipe(factor)
		if err != nil {
			return nil, err
		}
		// Verify before opening SQLite or resuming authenticated initialization.
		if err := vault.VerifySlotFile(key, doc, doc.VaultID, doc.FileID, doc.Sequence); err != nil {
			return nil, err
		}
		current, err := readVaultSlotFile(h.databasePath)
		if err != nil {
			return nil, err
		}
		if !sameRootRotationDocument(current, doc) {
			return nil, errVaultSlotConflict
		}
		if err := h.requireUnprotectedOpen(ctx); err != nil {
			return nil, err
		}
		h.releaseWorkspace, retained = release, true
		h.owner, err = openVaultFiles(ctx, h.databasePath, doc, key)
		if err != nil {
			return nil, h.retire(err)
		}
	}
	// Ordinary Open authenticated the stored policy. Re-read it and the machine
	// floor immediately before returning the native owner acknowledgement.
	protected, err := h.owner.ReadProtection(ctx)
	if err != nil {
		return nil, h.retire(err)
	}
	if protected {
		return nil, h.retire(vault.ErrPolicy)
	}
	identity, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		Unlocked     bool   `json:"unlocked"`
		LockedMemory bool   `json:"lockedMemory"`
		VaultID      string `json:"vaultId"`
	}{true, h.owner.LockedMemory(), identity})
}

func (h *vaultFoundationHandler) protection(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if len(payload) != 0 || h.owner == nil || h.shared != nil {
		return nil, vaultwire.ErrProtocol
	}
	protected, err := h.owner.ReadProtection(ctx)
	if err != nil {
		return h.rejectLocalPolicy(ctx, err)
	}
	return json.Marshal(struct {
		Protected bool `json:"protected"`
	}{protected})
}
