package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultStartupCosmetics struct {
	Theme applicationTheme `json:"theme"`
}
type vaultStartupMetadata struct {
	Slots              *vault.SlotFileDescriptor `json:"slots"`
	Cosmetics          vaultStartupCosmetics     `json:"cosmetics"`
	NewWorkspace       bool                      `json:"newWorkspace"`
	Shared             *vaultSharedStartupHints  `json:"shared,omitempty"`
	SharedJoin         *vaultSharedStartupHints  `json:"sharedJoin,omitempty"`
	Migration          *vaultMigrationStartup    `json:"migration,omitempty"`
	Rotation           *vaultMigrationStartup    `json:"rotation,omitempty"`
	Upgrade            *vaultUpgradeStartup      `json:"upgrade,omitempty"`
	Unprotected        *vaultUpgradeStartup      `json:"unprotected,omitempty"`
	UnprotectedAllowed bool                      `json:"unprotectedAllowed,omitempty"`
	OSMigration        *vaultUpgradeStartup      `json:"osMigration,omitempty"`
	Legacy             *vaultLegacyStartup       `json:"legacy,omitempty"`
}

type vaultLegacyStartup struct {
	UnprotectedAllowed bool `json:"unprotectedAllowed"`
}

type vaultMigrationStartup struct {
	Pending bool `json:"pending"`
}

// An untrusted routing hint only; no factor access or policy authority.
type vaultUpgradeStartup struct {
	VaultID string `json:"vaultId"`
}

// startup reads only public slot hints and a cosmetic preference. It never opens
// SQLite, invokes legacy migrations, or derives policy from
// settings.json. A missing descriptor is not an authorization to open a database.
func (h *vaultFoundationHandler) startup(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.databasePath == "" || len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := requireNoLocalBackupInstall(h.databasePath); err != nil {
		return nil, err
	}
	if h.sharedSelection != nil {
		slots, shared, err := h.describeSharedStartup(ctx)
		if err != nil || slots == nil || shared == nil {
			return nil, errSharedTrustStorage
		}
		return json.Marshal(vaultStartupMetadata{Slots: slots, Shared: shared, Cosmetics: readVaultStartupCosmetics(h.databasePath)})
	}
	rotation, err := discoverRootRotation(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	if rotation != nil {
		descriptor := rotation.document.Descriptor()
		return json.Marshal(vaultStartupMetadata{Slots: &descriptor, Cosmetics: readVaultStartupCosmetics(h.databasePath), Rotation: &vaultMigrationStartup{Pending: true}})
	}
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return nil, err
	}
	hint, err := discoverLegacyMigrationSetup(ctx, h.databasePath)
	if err != nil {
		return nil, err
	}
	if hint != nil {
		if hint.Document.FormatVersion == vault.SlotFileUnprotectedMigrationVersion {
			return json.Marshal(vaultStartupMetadata{Cosmetics: readVaultStartupCosmetics(h.databasePath), OSMigration: &vaultUpgradeStartup{VaultID: hint.Document.VaultID}})
		}
		// A setup takes precedence over shared selection, even in the temporary
		// missing-source window. This is display metadata, never unlock authority.
		descriptor := hint.Document.Descriptor()
		return json.Marshal(vaultStartupMetadata{Slots: &descriptor, Cosmetics: readVaultStartupCosmetics(h.databasePath), Migration: &vaultMigrationStartup{Pending: true}})
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return nil, err
	}
	joiningSlots, joining, err := h.describeSharedJoinStartup(ctx)
	if err != nil {
		return nil, err
	}
	if joining != nil {
		if !joining.AccountReset {
			if info, err := os.Lstat(sharedAdminRecoveryPath(h.databasePath)); err == nil && info.Mode().IsRegular() {
				joining.AdminRecovery = true
			}
		}
		return json.Marshal(vaultStartupMetadata{Slots: joiningSlots, SharedJoin: joining, Cosmetics: readVaultStartupCosmetics(h.databasePath)})
	}
	slots, shared, err := h.describeSharedStartup(ctx)
	if err != nil {
		return nil, err
	}
	if shared == nil {
		slots, err = describeVaultSlots(h.databasePath)
		if err != nil {
			return nil, err
		}
	}
	result := vaultStartupMetadata{Slots: slots, Shared: shared, Cosmetics: readVaultStartupCosmetics(h.databasePath)}
	if shared == nil && slots != nil && len(slots.Slots) == 1 && slots.Slots[0].Kind == vault.SlotUnprotected {
		doc, err := readVaultSlotFile(h.databasePath)
		if err != nil {
			return nil, err
		}
		if doc.VaultID != slots.VaultID || len(doc.Slots) != 1 || doc.Slots[0].Kind != vault.SlotUnprotected || doc.Encrypted || doc.Migration != nil || doc.Rotation != nil {
			return nil, vault.ErrPolicy
		}
		result.Slots = nil
		floor, err := ospolicy.ReadFloor(ctx)
		if err != nil {
			return nil, err
		}
		if floor == vault.Default {
			result.Unprotected = &vaultUpgradeStartup{VaultID: slots.VaultID}
		} else {
			if doc.Initializing {
				return nil, vault.ErrPolicy
			}
			result.Upgrade = &vaultUpgradeStartup{VaultID: slots.VaultID}
		}
	}
	if slots == nil && shared == nil {
		info, err := os.Lstat(h.databasePath)
		if errors.Is(err, os.ErrNotExist) {
			result.NewWorkspace = true
			floor, err := ospolicy.ReadFloor(ctx)
			if err != nil {
				return nil, err
			}
			result.UnprotectedAllowed = floor == vault.Default
		} else if err != nil {
			return nil, errVaultSlotStorage
		} else {
			if !info.Mode().IsRegular() {
				return nil, errVaultSlotStorage
			}
			floor, err := ospolicy.ReadFloor(ctx)
			if err != nil {
				return nil, err
			}
			result.Legacy = &vaultLegacyStartup{UnprotectedAllowed: floor == vault.Default}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func readVaultStartupCosmetics(databasePath string) vaultStartupCosmetics {
	result := vaultStartupCosmetics{Theme: applicationThemeSystem}
	_, path := authPaths(databasePath)
	// Cosmetic failures must not prevent recovery/unlock. Ignore unsafe file types
	// rather than following a settings link or reading an unbounded device stream.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return result
	}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return result
	}
	raw, err := io.ReadAll(io.LimitReader(file, authMaxSettingsBytes+1))
	defer vault.Wipe(raw)
	if err != nil || len(raw) > authMaxSettingsBytes {
		return result
	}
	// Decode only the allowlisted field. Do not run the legacy settings transform
	// (which also handles authentication/provider preferences), or write defaults.
	var document struct {
		Theme json.RawMessage `json:"Theme"`
	}
	err = json.Unmarshal(raw, &document)
	defer vault.Wipe(document.Theme)
	if err != nil {
		return result
	}
	if theme, ok := readApplicationTheme(document.Theme); ok {
		result.Theme = theme
	}
	return result
}
