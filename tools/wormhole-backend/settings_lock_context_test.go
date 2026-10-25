package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCancellableNativeFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := acquireExclusiveFileLockContext(ctx, path); release != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already cancelled lock: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled lock created a file")
	}
	if release, err := acquireExclusiveFileLockContext(context.Background(), t.TempDir()); release != nil || err == nil {
		t.Fatal("directory was accepted as a lock file")
	}
	owner, err := acquireExclusiveFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	releaseOwner := func() { once.Do(owner) }
	defer releaseOwner()
	fallback := time.AfterFunc(time.Second, releaseOwner)
	defer fallback.Stop()
	waiting, cancelWaiting := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelWaiting()
	started := time.Now()
	if release, err := acquireExclusiveFileLockContext(waiting, path); release != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy lock ignored cancellation: %v", err)
	}
	if time.Since(started) >= 500*time.Millisecond {
		t.Fatal("cancellation waited for the native owner to release")
	}
	released := make(chan struct{})
	resume := time.AfterFunc(50*time.Millisecond, func() { close(released); releaseOwner() })
	defer resume.Stop()
	waiting, cancelWaiting = context.WithTimeout(context.Background(), time.Second)
	defer cancelWaiting()
	release, err := acquireExclusiveFileLockContext(waiting, path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	select {
	case <-released:
	default:
		t.Fatal("second handle acquired the lock before the owner released it")
	}
}

func TestTunnelConfigurationLockBoundsAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "workspace.db")
	release, err := acquireTunnelConfigurationLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unlock := func() { once.Do(release) }
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if next, err := acquireTunnelConfigurationLock(ctx, path); next != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configuration lock ignored cancellation: %v", err)
	}
	unlock()
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if next, err := acquireTunnelConfigurationLock(ctx, path); next != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled configuration lock: %v", err)
	}
	if next, err := acquireTunnelConfigurationLock(context.Background(), ""); next != nil || err == nil {
		t.Fatal("empty database path accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if next, err := acquireTunnelConfigurationLock(context.Background(), filepath.Join(file, "db")); next != nil || err == nil {
		t.Fatal("invalid parent path accepted")
	}
	blocked := filepath.Join(t.TempDir(), "db")
	if err := os.Mkdir(tunnelConfigurationLockPath(blocked), 0o700); err != nil {
		t.Fatal(err)
	}
	if next, err := acquireTunnelConfigurationLock(context.Background(), blocked); next != nil || err == nil {
		t.Fatal("invalid native lock file accepted")
	}
}
