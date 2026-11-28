package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

// A separate initial-join route has priority over an ordinary shared unlock.
// Reading OS-protected public selection/ciphertext never derives account keys,
// contacts PostgreSQL, recreates files or authorizes a local/legacy fallback.
func (h *vaultFoundationHandler) describeSharedJoinStartup(ctx context.Context) (*vault.SlotFileDescriptor, *vaultSharedStartupHints, error) {
	if ctx == nil || !filepath.IsAbs(h.databasePath) {
		return nil, nil, errSharedTrustStorage
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	path := sharedWorkspaceTrustPath(h.databasePath)
	if err := requireNoSharedJoinStartup(path); err == nil {
		return nil, nil, nil
	} else if !errors.Is(err, errSharedTrustConflict) {
		return nil, nil, err
	}
	info, err := os.Lstat(sharedWorkspaceDirectory(h.databasePath))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errSharedTrustStorage
	}
	for _, source := range []string{h.databasePath, vaultSlotPath(h.databasePath)} {
		if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errVaultOwnerRequired
		}
	}
	release, err := tryAcquireSharedFileLock(path + ".lock")
	if err != nil {
		return nil, nil, errSharedTrustConflict
	}
	defer release()
	if err := requireNoSharedTrustTransition(path); err != nil {
		return nil, nil, err
	}
	p, err := readSharedJoinStartup(path, h.startupProtection())
	if err != nil {
		return nil, nil, err
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(p.DeviceFile)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	descriptor := slots.Descriptor()
	descriptor.Encrypted = true
	return &descriptor, &vaultSharedStartupHints{LastLoginName: p.LoginName, ServerDisplayName: p.Binding.WorkspaceID.String(),
		CanContinue:  (p.FormatVersion == 3 && len(p.Continuation) != 0) || p.FormatVersion == 4,
		AccountReset: p.FormatVersion == 4}, nil
}
