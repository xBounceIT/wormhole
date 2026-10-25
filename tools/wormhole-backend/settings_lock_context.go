package main

import (
	"context"
	"errors"
	"time"
)

var errExclusiveFileLockBusy = errors.New("Wormhole data lock is busy")

// Use nonblocking native attempts so cancellation never strands an acquisition goroutine
// or a tunnel lease behind another backend process's settings transaction.
func acquireExclusiveFileLockContext(ctx context.Context, path string) (func(), error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		release, err := tryAcquireExclusiveFileLock(path)
		if err == nil {
			if err := ctx.Err(); err != nil {
				release()
				return nil, err
			}
			return release, nil
		}
		if !errors.Is(err, errExclusiveFileLockBusy) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
