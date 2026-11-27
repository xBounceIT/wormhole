package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
)

// A basename namespace separates databases in the same directory without tying
// packages to an absolute parent path. Renames require package repair; there is
// deliberately no search or fallback into another database's namespace.
func vaultBitwardenDatabaseDirectory(database string) string {
	return "db-" + vaultBitwardenDatabaseNamespace(database)
}

func vaultBitwardenDatabaseNamespace(database string) string {
	sum := sha256.Sum256([]byte(filepath.Base(database)))
	return hex.EncodeToString(sum[:])
}

func openVaultBitwardenInstallRoot(database string, layout int, create bool) (*os.Root, error) {
	if !filepath.IsAbs(database) || layout < 0 || layout > 1 || create && layout != 1 {
		return nil, errVaultExtensionFiles
	}
	directory := filepath.Join(filepath.Dir(database), vaultBitwardenInstallDirectory)
	if create {
		if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errVaultExtensionFiles
		}
		if syncPrivateFileDirectory(filepath.Dir(directory)) != nil {
			return nil, errVaultExtensionFiles
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errVaultExtensionFiles
	}
	base, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errVaultExtensionFiles
	}
	if layout == 0 {
		return base, nil
	}
	defer base.Close()
	name := vaultBitwardenDatabaseDirectory(database)
	if create {
		if err = base.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errVaultExtensionFiles
		}
		if syncPrivateFileDirectory(base.Name()) != nil {
			return nil, errVaultExtensionFiles
		}
	}
	info, err = base.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errVaultExtensionFiles
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		return nil, errVaultExtensionFiles
	}
	return root, nil
}

// Only the service that opened the scoped root uses this adapter. Low-level
// legacy package verification remains usable with version-one records.
type scopedVaultBitwardenInstaller struct {
	*localvault.Owner
	namespace      string
	intent         localvault.BitwardenInstallationIntent
	intentRevision uint64
}

func (o scopedVaultBitwardenInstaller) SaveBitwardenInstallation(ctx context.Context, value localvault.BitwardenInstallation, expected uint64) (uint64, error) {
	value.Layout = 1
	return o.Owner.SaveBitwardenInstallation(ctx, value, expected)
}
