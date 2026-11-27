package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var errWorkspaceInUse = errors.New("workspace_owner_unavailable")

// Cache files and protected keys are shared by databases in a data directory.
// Keep the guard for the entire legacy CLI lifetime, including worker cleanup.
// Metadata-only vault requests do not acquire it. Never unlink the lock file:
// another process may already hold a handle to the same native lock.
func acquireWorkspaceOwnership(databasePath string, exclusive bool) (func(), error) {
	if databasePath == "" {
		return nil, errWorkspaceInUse
	}
	if info, err := os.Lstat(databasePath); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errWorkspaceInUse
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errWorkspaceInUse
	}
	directory := filepath.Dir(databasePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errWorkspaceInUse
	}
	path := filepath.Join(directory, ".workspace-owner.lock")
	var release func()
	var err error
	if exclusive {
		release, err = tryAcquireExclusiveFileLock(path)
	} else {
		release, err = tryAcquireSharedFileLock(path)
	}
	if err != nil {
		return nil, errWorkspaceInUse
	}
	return sync.OnceFunc(release), nil
}
