package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// No paths or package IDs are accepted from the caller. The authenticated owner
// supplies retired IDs under its exclusion lock; only the scoped root is eligible.
func (h *vaultFoundationHandler) cleanupBitwardenInstallations(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var workspace, expected string
	if decodeVaultObject(raw, map[string]any{"workspaceId": &workspace, "expectedRevision": &expected}, "workspaceId", "expectedRevision") != nil || !vaultCredentialID(workspace) {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(expected, true)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	actual, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	if actual != workspace {
		return nil, vaultwire.ErrProtocol
	}
	// Do not reconcile files for a stale authorized request.
	_, current, err := h.owner.ReadBitwardenInstallation(ctx, revision)
	if err != nil {
		return nil, err
	}
	if current != revision {
		return nil, errVaultExtensionCleanup
	}
	if err = recoverVaultBitwardenIntent(ctx, h.owner, h.databasePath); err != nil {
		return nil, err
	}
	var base *os.Root
	defer func() {
		if base != nil {
			base.Close()
		}
	}()
	next, err := h.owner.CleanupBitwardenInstallations(ctx, revision, func(ctx context.Context, id string) error {
		if base == nil {
			base, err = openVaultBitwardenInstallRoot(h.databasePath, 1, true)
			if err != nil {
				return errVaultExtensionCleanup
			}
		}
		return removeVaultBitwardenRetiredPackage(ctx, base, id)
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		WorkspaceID string `json:"workspaceId"`
		Revision    string `json:"revision"`
	}{workspace, strconv.FormatUint(next, 10)})
}

func removeVaultBitwardenRetiredPackage(ctx context.Context, base *os.Root, id string) error {
	if ctx.Err() != nil || base == nil || !vaultCredentialID(id) {
		return errVaultExtensionCleanup
	}
	info, err := base.Lstat(id)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errVaultExtensionCleanup
		}
		// os.Root confines traversal, and RemoveAll does not follow child symlinks.
		if base.RemoveAll(id) != nil {
			return errVaultExtensionCleanup
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errVaultExtensionCleanup
	}
	// A retry must sync even if an earlier attempt removed the directory but did
	// not confirm durability. Absence alone cannot acknowledge that earlier delete.
	if syncPrivateFileDirectory(base.Name()) != nil || ctx.Err() != nil {
		return errVaultExtensionCleanup
	}
	return nil
}
