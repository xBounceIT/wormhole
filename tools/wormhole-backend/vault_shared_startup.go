package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

type vaultSharedStartupHints struct {
	LastLoginName     string `json:"lastLoginName"`
	ServerDisplayName string `json:"serverDisplayName"`
	CanContinue       bool   `json:"canContinue,omitempty"`
	AdminRecovery     bool   `json:"adminRecovery,omitempty"`
	AccountReset      bool   `json:"accountReset,omitempty"`
}

// Only slot hints, display strings and continuation availability cross the
// pre-unlock boundary. Availability never establishes an unused remote invite. Slot
// contents remain untrusted; native unlock rechecks identity/MAC/envelope/journal.
// A malformed shared marker never causes a local/legacy fallback.
func (h *vaultFoundationHandler) describeSharedStartup(ctx context.Context) (*vault.SlotFileDescriptor, *vaultSharedStartupHints, error) {
	if ctx == nil || !filepath.IsAbs(h.databasePath) {
		return nil, nil, sharedpg.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(sharedWorkspaceDirectory(h.databasePath))
	if errors.Is(err, os.ErrNotExist) {
		if h.shared != nil || h.sharedSelection != nil {
			return nil, nil, errSharedTrustStorage
		}
		return nil, nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errVaultOwnerRequired
	}
	for _, path := range []string{h.databasePath, vaultSlotPath(h.databasePath)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errVaultOwnerRequired
		}
	}
	path := sharedWorkspaceTrustPath(h.databasePath)
	release, err := tryAcquireSharedFileLock(path + ".lock")
	if err != nil {
		return nil, nil, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedPendingEnrollment(path); err != nil {
		return nil, nil, err
	}
	a, err := readSharedStartupAnchor(path, h.startupProtection())
	if err != nil {
		return nil, nil, err
	}
	if h.sharedSelection != nil && !h.sharedSelection.matches(a) {
		return nil, nil, sharedpg.ErrTrustState
	}
	var raw []byte
	if err := requireNoSharedTrustTransition(path); err == nil {
		raw, err = readSharedTrustBytes(sharedDeviceEnrollmentPath(path), sharedpg.MaxDeviceEnrollmentFileBytes)
		if err != nil {
			return nil, nil, err
		}
	} else if errors.Is(err, errSharedTrustTransitionPending) {
		journal, err := readSharedTrustBytes(sharedTrustTransitionPath(path), sharedpg.MaxTrustRootTransitionBytes)
		if err != nil {
			return nil, nil, err
		}
		raw, err = sharedpg.UnverifiedTransitionDevice(journal)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, err
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(raw)
	if err != nil {
		return nil, nil, err
	}
	if slots.VaultID != a.VaultID || slots.FileID != a.FileID || slots.Sequence < a.MinimumSequence {
		return nil, nil, sharedpg.ErrTrustState
	}
	// Encrypted refers to shared device/account storage, not the local SQLite
	// migration flag on the reusable slot container. No account keys are opened.
	descriptor := slots.Descriptor()
	descriptor.Encrypted = true
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return &descriptor, &vaultSharedStartupHints{LastLoginName: a.LoginName, ServerDisplayName: a.DisplayName}, nil
}
