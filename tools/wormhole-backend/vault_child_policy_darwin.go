package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func enforceVaultChildProcessPolicy() bool {
	// XNU applies RLIMIT_NPROC to fork and posix_spawn. The limit is
	// checked against the current process and does not affect siblings.
	// A root UID is exempt and can raise the hard limit.
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return false
	}
	limit := unix.Rlimit{}
	if unix.Setrlimit(unix.RLIMIT_NPROC, &limit) != nil {
		return false
	}
	return unix.Getrlimit(unix.RLIMIT_NPROC, &limit) == nil && limit.Cur == 0 && limit.Max == 0
}
