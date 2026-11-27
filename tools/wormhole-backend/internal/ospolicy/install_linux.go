//go:build linux

package ospolicy

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenManagedSystemPackage opens the file the administrator will install. Its
// directories and the file itself must remain under root's control.
func OpenManagedSystemPackage(path string) (*os.File, error) {
	if filepath.Dir(path) != managedLinuxUpdateDirectory || filepath.Clean(path) != path {
		return nil, ErrInstallationLocation
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInstallationLocation
	}
	return openProtectedFileAt(context.Background(), fd, strings.Split(strings.TrimPrefix(path, "/"), "/"), 0)
}

func checkNativeInstallation(ctx context.Context) (string, error) {
	proc, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", ErrInstallationLocation
	}
	defer unix.Close(proc)
	if !initialLinuxUserNamespace(proc) {
		return "", ErrInstallationLocation
	}
	parent := os.Getppid()
	if parent <= 1 {
		return "", ErrInstallationLocation
	}
	parentImage := strconv.Itoa(parent) + "/exe"
	frontend, err := readLinuxProcessImage(proc, parentImage)
	if err != nil {
		return "", err
	}
	backend, err := readLinuxProcessImage(proc, "self/exe")
	if err != nil {
		return "", err
	}
	root, err := checkUnixInstallation(ctx, frontend, backend)
	if err != nil {
		return "", err
	}
	if os.Getppid() != parent || !sameLinuxProcessImage(proc, parentImage, frontend) || !sameLinuxProcessImage(proc, "self/exe", backend) {
		return "", ErrInstallationLocation
	}
	return root, ctx.Err()
}

func initialLinuxUserNamespace(proc int) bool {
	var filesystem unix.Statfs_t
	if unix.Fstatfs(proc, &filesystem) != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		return false
	}
	// A process in another user namespace can have a private mount tree. Read
	// its live kernel map only from the original proc mount, without crossing
	// bind mounts (including bind mounts of other proc entries).
	fd, err := unix.Openat2(proc, "self/uid_map", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), "uid_map")
	defer file.Close()
	if unix.Fstatfs(fd, &filesystem) != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	return err == nil && isInitialLinuxUIDMap(raw)
}

func isInitialLinuxUIDMap(raw []byte) bool {
	if len(raw) > 128 {
		return false
	}
	fields := strings.Fields(string(raw))
	return len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

func readLinuxProcessImage(proc int, entry string) (string, error) {
	var path [4096]byte
	n, err := unix.Readlinkat(proc, entry, path[:])
	if err != nil || n <= 0 || n >= len(path) {
		return "", ErrInstallationLocation
	}
	return string(path[:n]), nil
}

func sameLinuxProcessImage(proc int, entry, path string) bool {
	var running, installed unix.Stat_t
	return unix.Fstatat(proc, entry, &running, 0) == nil && unix.Lstat(path, &installed) == nil &&
		installed.Mode&unix.S_IFMT == unix.S_IFREG && running.Dev == installed.Dev && running.Ino == installed.Ino
}

func protectedUnixEntry(path string, kind fs.FileMode, mode, _ uint32) bool {
	if kind == fs.ModeSymlink {
		return true // The containing directory controls changes to a symbolic link.
	}
	if mode&0022 != 0 { // Linux ACL group class also appears in these mode bits.
		return false
	}
	var filesystem unix.Statfs_t
	if unix.Statfs(path, &filesystem) != nil {
		return false
	}
	// Filesystems with caller-controlled or synthesized ownership cannot prove
	// that UID 0 represents the authority controlling an installed file.
	switch filesystem.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return true
	default:
		return false
	}
}
