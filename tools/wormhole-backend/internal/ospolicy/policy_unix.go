//go:build linux || darwin

package ospolicy

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"golang.org/x/sys/unix"
)

const managedLinuxUpdateDirectory = "/var/lib/wormhole/updates"

func readFloor(ctx context.Context) (vault.Profile, error) {
	components := []string{"etc", "wormhole", "policy.json"}
	parse := parseJSON
	if runtime.GOOS == "darwin" {
		components = []string{"Library", "Managed Preferences", "com.xbounceit.wormhole.plist"}
		parse = parsePlist
	}
	return readRootPolicy(ctx, components, vault.Default, parse)
}

func readManagedUpdate(ctx context.Context) (ManagedUpdate, error) {
	components := []string{"etc", "wormhole", "managed-update.sha256"}
	dir := managedLinuxUpdateDirectory
	if runtime.GOOS == "darwin" {
		components = []string{"Library", "Managed Preferences", "com.xbounceit.wormhole.update.sha256"}
		dir = "/Library/Application Support/Wormhole/Updates"
	}
	digest, err := readRootPolicy(ctx, components, "", parseManagedUpdateDigest)
	return ManagedUpdate{Directory: dir, Digest: digest}, err
}

func readRootPolicy[T ~string](ctx context.Context, components []string, absent T, parse func([]byte) (T, error)) (T, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", vault.ErrPolicy
	}
	return readProtectedPolicyAt(ctx, fd, components, 0, absent, parse)
}

func readProtectedPolicyAt[T ~string](ctx context.Context, fd int, components []string, uid uint32, absent T, parse func([]byte) (T, error)) (T, error) {
	file, err := openProtectedFileAt(ctx, fd, components, uid)
	if errors.Is(err, unix.ENOENT) {
		return absent, nil
	}
	if err != nil {
		return "", err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > maxPolicyBytes {
		file.Close()
		return "", vault.ErrPolicy
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) < 1 || len(raw) > maxPolicyBytes {
		return "", vault.ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return parse(raw)
}

// Consumes fd. Open every component relative to a verified parent. O_NONBLOCK
// prevents an unexpected special file from blocking before its type is checked.
func openProtectedFileAt(ctx context.Context, fd int, components []string, uid uint32) (*os.File, error) {
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	for i := 0; ; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != uid || stat.Mode&0022 != 0 {
			return nil, vault.ErrPolicy
		}
		if i == len(components) {
			if stat.Mode&unix.S_IFMT != unix.S_IFREG {
				return nil, vault.ErrPolicy
			}
			file := os.NewFile(uintptr(fd), "machine-managed file")
			fd = -1
			return file, nil
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || components[i] == "" || components[i] == "." || components[i] == ".." || strings.ContainsAny(components[i], "/\x00") {
			return nil, vault.ErrPolicy
		}
		// Mode bits alone do not describe macOS ACLs. A non-root process must not
		// be able to change a root-owned policy or any of its parent directories.
		if uid == 0 && unix.Geteuid() != 0 {
			if i == 0 && unix.Faccessat(fd, ".", unix.W_OK, unix.AT_EACCESS) == nil {
				return nil, vault.ErrPolicy
			}
			accessErr := unix.Faccessat(fd, components[i], unix.W_OK, unix.AT_EACCESS)
			if accessErr == nil || (!errors.Is(accessErr, unix.EACCES) && !errors.Is(accessErr, unix.ENOENT)) {
				return nil, vault.ErrPolicy
			}
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i+1 < len(components) {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, components[i], flags, 0)
		if errors.Is(err, unix.ENOENT) {
			return nil, unix.ENOENT
		}
		if err != nil {
			return nil, vault.ErrPolicy
		}
		unix.Close(fd)
		fd = next
	}
}
