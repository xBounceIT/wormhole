package ospolicy

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/updateauth"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

var (
	ErrInstallationLocation  = errors.New("vault_installation_location_untrusted")
	ErrInstallationSignature = errors.New("vault_installation_signature_untrusted")
)

// Walk trusted parents from the filesystem root down. WalkDir calls inspect
// on each directory before listing or descending into its contents.
func walkInstallationTree(ctx context.Context, root string, inspect func(string, fs.FileMode, bool) error) error {
	var ancestors []string
	for ancestor := filepath.Dir(root); ; ancestor = filepath.Dir(ancestor) {
		ancestors = append(ancestors, ancestor)
		if filepath.Dir(ancestor) == ancestor {
			break
		}
	}
	for _, ancestor := range slices.Backward(ancestors) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := inspect(ancestor, fs.ModeDir, filepath.Dir(ancestor) == ancestor); err != nil {
			return err
		}
	}
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if path != root {
			entries++
		}
		if walkErr != nil || entries > updateauth.MaxInstallationEntries {
			return ErrInstallationLocation
		}
		return inspect(path, entry.Type(), false)
	})
}

// CheckInstallationFloor applies the installation-location prerequisite of the
// OS security floor. Workspace-profile admission has additional requirements.
func CheckInstallationFloor(ctx context.Context, floor vault.Profile, releaseKeyPin string) error {
	return checkInstallationFloor(ctx, floor, releaseKeyPin, checkNativeInstallation)
}

func checkInstallationFloor(ctx context.Context, floor vault.Profile, releaseKeyPin string, native func(context.Context) (string, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch floor {
	case vault.Default, vault.Standard:
		return nil
	case vault.Hardened, vault.Paranoid:
	default:
		return vault.ErrPolicy
	}
	root, err := native(ctx)
	if err != nil || floor == vault.Hardened {
		return err
	}
	key, err := updateauth.ParsePublicKey(releaseKeyPin)
	if err != nil {
		return ErrInstallationSignature
	}
	target := updateauth.InstallationTarget(runtime.GOOS, runtime.GOARCH)
	if _, err := updateauth.VerifyInstalledTree(ctx, root, target, key); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInstallationSignature
	}
	return nil
}
