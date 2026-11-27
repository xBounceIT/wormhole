package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func enforceVaultChildProcessPolicy() bool {
	abi := vaultLinuxProcessABI{
		clone: unix.SYS_CLONE, clone3: unix.SYS_CLONE3,
		execOrFork: []uint32{unix.SYS_EXECVE, unix.SYS_EXECVEAT},
	}
	switch runtime.GOARCH {
	case "amd64":
		abi.arch = unix.AUDIT_ARCH_X86_64
		abi.execOrFork = append(abi.execOrFork, 57, 58) // Linux amd64 fork, vfork.
	case "arm64":
		abi.arch = unix.AUDIT_ARCH_AARCH64
	default:
		return false
	}
	raw, err := vaultLinuxChildProcessFilter(abi)
	if err != nil {
		return false
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, instruction := range raw {
		filter[i] = unix.SockFilter{
			Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K,
		}
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// no_new_privs belongs to the current OS thread. TSYNC installs the
	// filter across existing Go threads and makes later threads inherit it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return false
	}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	// TSYNC can return the ID of an unsynchronized thread with no errno.
	return errno == 0 && result == 0
}
