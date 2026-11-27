package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) requireOSMigration(ctx context.Context) error {
	if h.owner != nil || h.shared != nil || h.enrollment != nil || h.rotationMaterial != nil || h.releaseWorkspace != nil || !filepath.IsAbs(h.databasePath) || filepath.Clean(h.databasePath) != h.databasePath || !legacyPublicationFilename(filepath.Base(h.databasePath)) || !filepath.IsAbs(h.userDataPath) || filepath.Clean(h.userDataPath) != h.userDataPath {
		return vaultwire.ErrProtocol
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return err
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return err
	}
	floor, err := ospolicy.ReadFloor(ctx)
	if err != nil {
		return err
	}
	if floor != vault.Default {
		return vault.ErrPolicy
	}
	return nil
}

// Prepare only an encrypted retry capsule. Legacy source files and SQLite are
// never retired in this original Chromium process. Old PIN/password proof is
// verified natively; no new user factor or recovery recipient is appropriate.
func (h *vaultFoundationHandler) prepareOSMigration(ctx context.Context, payload []byte) (_ json.RawMessage, resultErr error) {
	defer vault.Wipe(payload)
	if len(payload) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	if err := h.requireOSMigration(ctx); err != nil {
		return nil, err
	}
	if err := requireLegacyWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	var method string
	var raw json.RawMessage
	defer func() { vault.Wipe(raw); vault.Wipe(payload) }()
	if decodeVaultObject(payload, map[string]any{"legacyMethod": &method, "legacyFactor": &raw}, "legacyMethod", "legacyFactor") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var factor []byte
	defer func() { vault.Wipe(factor) }()
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &factor) != nil || len(factor) > 1024 {
		return nil, vaultwire.ErrProtocol
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
	if err := h.requireOSMigration(ctx); err != nil {
		return nil, err
	}
	if err := requireLegacyWorkspace(h.databasePath); err != nil {
		return nil, err
	}
	canonical, _, err := canonicalLegacyVaultSource(h.databasePath)
	if err != nil {
		return nil, err
	}
	if err := verifyLegacyMigrationFactor(ctx, h.databasePath, method, factor); err != nil {
		return nil, err
	}
	vault.Wipe(factor)
	vault.Wipe(raw)
	vault.Wipe(payload)
	document := vault.SlotFile{FormatVersion: vault.SlotFileFormatVersion, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(), RootKeyVersion: 1, Sequence: 1, FileEpoch: 1}
	database, err := openLegacyMigrationSource(canonical)
	if err != nil {
		return nil, err
	}
	plan, planErr := prepareLegacyResolverMigration(ctx, database, document.VaultID)
	if err := errors.Join(planErr, database.Close()); err != nil {
		return nil, err
	}
	material, err := securemem.New(32, true)
	if err != nil {
		return nil, err
	}
	h.rotationMaterial = material
	h.releaseWorkspace = release
	retained = true
	defer func() {
		closeErr := material.Close()
		if closeErr == nil {
			h.rotationMaterial = nil
		} else {
			resultErr = h.retire(errors.Join(resultErr, closeErr))
		}
		if !h.closed && closeErr == nil {
			release()
			h.releaseWorkspace = nil
		}
	}()
	err = material.With(func(root []byte) error {
		if _, err := rand.Read(root); err != nil {
			return err
		}
		slotID := uuid.NewString()
		platform, err := createVaultUnprotectedKey(ctx, canonical, document.VaultID, slotID)
		defer vault.Wipe(platform)
		if err != nil {
			return err
		}
		slot, err := vault.CreateUnprotectedSlot(document.VaultID, slotID, document.RootKeyVersion, root, platform)
		if err != nil {
			return err
		}
		document.Slots = []vault.Slot{slot}
		encoded, err := vault.EncodeSlotFile(root, document)
		if err != nil {
			return err
		}
		document, err = vault.DecodeSlotFile(encoded)
		if err != nil {
			return err
		}
		floor, err := ospolicy.ReadFloor(ctx)
		if err != nil {
			return err
		}
		if floor != vault.Default {
			return vault.ErrPolicy
		}
		// Any publication attempt retires this handler, including an uncertain
		// file-sync outcome. Hold the lease until acknowledged native exit.
		h.closed = true
		return saveLegacyMigrationSetup(ctx, legacyMigrationSetup{Version: 1, LogicalSource: h.databasePath, CanonicalSource: canonical, UserData: h.userDataPath, Initial: document, Plan: plan}, root)
	})
	if err != nil {
		if h.closed {
			return nil, h.retire(err)
		}
		return nil, err
	}
	return json.Marshal(struct {
		Prepared        bool   `json:"prepared"`
		RestartRequired bool   `json:"restartRequired"`
		VaultID         string `json:"vaultId"`
	}{true, true, document.VaultID})
}

func (h *vaultFoundationHandler) resumeOSMigration(ctx context.Context, payload []byte) (_ json.RawMessage, resultErr error) {
	defer vault.Wipe(payload)
	if len(payload) != 0 || !h.migrationQuiesced {
		return nil, vaultwire.ErrProtocol
	}
	if err := h.requireOSMigration(ctx); err != nil {
		return nil, err
	}
	hint, err := discoverLegacyMigrationSetup(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	if hint == nil || hint.Document.FormatVersion != vault.SlotFileUnprotectedMigrationVersion || len(hint.Document.Slots) != 1 || hint.Document.Slots[0].Kind != vault.SlotUnprotected {
		return nil, vault.ErrPolicy
	}
	platform, err := openVaultUnprotectedKey(ctx, hint.CanonicalSource, hint.Document.VaultID, hint.Document.Slots[0].ID)
	defer vault.Wipe(platform)
	if err != nil {
		return nil, err
	}
	key, err := vault.OpenUnprotectedSlot(hint.Document.VaultID, hint.Document.Slots[0], platform)
	defer vault.Wipe(key)
	vault.Wipe(platform)
	if err != nil {
		return nil, err
	}
	if err := vault.VerifySlotFile(key, hint.Document, hint.Document.VaultID, hint.Document.FileID, 1); err != nil {
		return nil, err
	}
	material, err := securemem.New(32, true)
	if err != nil {
		return nil, err
	}
	h.rotationMaterial = material
	defer func() {
		if closeErr := material.Close(); closeErr != nil {
			resultErr = h.retire(errors.Join(resultErr, closeErr))
		} else {
			h.rotationMaterial = nil
		}
	}()
	err = material.With(func(root []byte) error {
		copy(root, key)
		vault.Wipe(key)
		custody := func() error {
			platform, err := openVaultUnprotectedKey(ctx, hint.CanonicalSource, hint.Document.VaultID, hint.Document.Slots[0].ID)
			defer vault.Wipe(platform)
			if err != nil {
				return err
			}
			current, err := vault.OpenUnprotectedSlot(hint.Document.VaultID, hint.Document.Slots[0], platform)
			defer vault.Wipe(current)
			if err != nil {
				return err
			}
			if subtle.ConstantTimeCompare(current, root) != 1 {
				return vault.ErrAuthentication
			}
			return ctx.Err()
		}
		return h.resumeMigrationKeyGuarded(ctx, hint, root, custody)
	})
	if err != nil {
		return nil, err
	}
	protected, err := h.owner.ReadProtection(ctx)
	if err != nil {
		return h.rejectLocalPolicy(ctx, err)
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
