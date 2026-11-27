//go:build darwin

package ospolicy

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func checkNativeInstallation(ctx context.Context) (string, error) {
	parent := os.Getppid()
	if parent <= 1 {
		return "", ErrInstallationLocation
	}
	frontend, err := darwinProcessImage(parent)
	if err != nil {
		return "", err
	}
	backend, err := darwinProcessImage(os.Getpid())
	if err != nil {
		return "", err
	}
	root, err := checkUnixInstallation(ctx, frontend, backend)
	if err != nil {
		return "", err
	}
	if current, err := darwinProcessImage(parent); err != nil || current != frontend || os.Getppid() != parent {
		return "", ErrInstallationLocation
	}
	if current, err := darwinProcessImage(os.Getpid()); err != nil || current != backend {
		return "", ErrInstallationLocation
	}
	return root, ctx.Err()
}

func darwinProcessImage(pid int) (string, error) {
	// The operation behind libproc's proc_pidpath queries the text vnode,
	// whereas kern.procargs2 exposes the process's writable argument area.
	const procInfoCallPIDInfo, procPIDPathInfo = 2, 11
	var path [4096]byte
	_, _, errno := syscall.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if end := bytes.IndexByte(path[:], 0); errno == 0 && end > 0 {
		return string(path[:end]), nil
	}
	return "", ErrInstallationLocation
}

func protectedUnixEntry(path string, kind fs.FileMode, mode, gid uint32) bool {
	if kind != fs.ModeSymlink {
		// /Applications may grant writes to the built-in admin group. POSIX
		// writes for other groups or for everyone cannot protect this path.
		const adminGroup = 80
		if mode&0002 != 0 || (mode&0020 != 0 && gid != adminGroup) {
			return false
		}
		var filesystem unix.Statfs_t
		if unix.Statfs(path, &filesystem) != nil || filesystem.Flags&unix.MNT_LOCAL == 0 || filesystem.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 {
			return false
		}
		name := unix.ByteSliceToString(filesystem.Fstypename[:])
		if name != "apfs" && name != "hfs" {
			return false
		}
	}
	return checkDarwinACL(path)
}

func checkDarwinACL(path string) bool {
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return false
	}
	attrs := struct {
		count, reserved uint16
		common          uint32
		other           [4]uint32
	}{count: unix.ATTR_BIT_MAP_COUNT, common: unix.ATTR_CMN_EXTENDED_SECURITY}
	var data [4096]byte // length, attrreference, filesec and up to 128 ACEs
	_, _, errno := syscall.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), unix.FSOPT_NOFOLLOW|unix.FSOPT_REPORT_FULLSIZE, 0)
	return errno == 0 && protectedDarwinACL(data[:])
}
