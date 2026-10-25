//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func acquireExclusiveFileLock(lockPath string) (func(), error) {
	return lockExclusiveFile(lockPath, false)
}

func tryAcquireExclusiveFileLock(lockPath string) (func(), error) {
	return lockExclusiveFile(lockPath, true)
}

func lockExclusiveFile(lockPath string, nonblocking bool) (func(), error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the Wormhole data lock: %w", err)
	}
	overlapped := new(windows.Overlapped)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonblocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		flags,
		0,
		1,
		0,
		overlapped,
	); err != nil {
		_ = file.Close()
		if nonblocking && errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errExclusiveFileLockBusy
		}
		return nil, fmt.Errorf("cannot lock Wormhole data: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
		_ = file.Close()
	}, nil
}
