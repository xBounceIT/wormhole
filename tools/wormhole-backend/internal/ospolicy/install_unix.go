//go:build linux || darwin

package ospolicy

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func checkUnixInstallation(ctx context.Context, frontend, backend string) (string, error) {
	root, err := unixInstallationRoot(runtime.GOOS, frontend, backend)
	if err != nil {
		return "", err
	}
	if err := checkUnixInstallationTree(ctx, root, frontend, backend, inspectUnixInstallationEntry); err != nil {
		return "", err
	}
	return root, nil
}

func checkUnixInstallationTree(ctx context.Context, root, frontend, backend string, inspect func(string, fs.FileMode) (uint32, error)) error {
	var confined *os.Root
	defer func() {
		if confined != nil {
			confined.Close()
		}
	}()
	var frontendFound, backendFound bool
	err := walkInstallationTree(ctx, root, func(path string, kind fs.FileMode, _ bool) error {
		mode, err := inspect(path, kind)
		if err != nil {
			return err
		}
		if kind == fs.ModeSymlink {
			// A framework link may refer to a sibling under Versions. Restrict
			// every resolution to the validated physical bundle tree.
			if confined == nil {
				confined, err = os.OpenRoot(root)
				if err != nil {
					return ErrInstallationLocation
				}
			}
			relative, err := filepath.Rel(root, path)
			if err != nil || !filepath.IsLocal(relative) {
				return ErrInstallationLocation
			}
			target, err := confined.Stat(relative)
			if err != nil || (!target.IsDir() && !target.Mode().IsRegular()) {
				return ErrInstallationLocation
			}
		}
		if kind == 0 && mode&0111 != 0 {
			frontendFound = frontendFound || path == frontend
			backendFound = backendFound || path == backend
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !frontendFound || !backendFound {
		return ErrInstallationLocation
	}
	return ctx.Err()
}

func inspectUnixInstallationEntry(path string, kind fs.FileMode) (uint32, error) {
	var nativeType uint32
	switch kind {
	case 0:
		nativeType = unix.S_IFREG
	case fs.ModeDir:
		nativeType = unix.S_IFDIR
	case fs.ModeSymlink:
		nativeType = unix.S_IFLNK
	default:
		return 0, ErrInstallationLocation
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || uint32(st.Mode)&unix.S_IFMT != nativeType || st.Uid != 0 ||
		!protectedUnixEntry(path, kind, uint32(st.Mode), st.Gid) {
		return 0, ErrInstallationLocation
	}
	return uint32(st.Mode), nil
}
