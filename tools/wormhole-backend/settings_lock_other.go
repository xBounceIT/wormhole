//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
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
	flags := syscall.LOCK_EX
	if nonblocking {
		flags |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), flags); err != nil {
		_ = file.Close()
		if nonblocking && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)) {
			return nil, errExclusiveFileLockBusy
		}
		return nil, fmt.Errorf("cannot lock Wormhole data: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
