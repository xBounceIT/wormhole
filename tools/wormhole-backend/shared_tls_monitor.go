package main

import (
	"context"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
)

func newSharedTLSTicks(interval time.Duration) (<-chan time.Time, func()) {
	ticker := time.NewTicker(interval)
	return ticker.C, ticker.Stop
}

// The authenticated poll runs with or without LISTEN. The one-second clock
// coalesces hints, and the periodic check covers connections that miss hints.
func (c *sharedAdmissionController) monitorWorkspaceAuthority(notifications bool) {
	ctx, cancel := context.WithCancel(c.lifetime)
	defer cancel()
	interval := 30 * time.Second
	if notifications {
		interval = time.Second
	}
	nextPoll := time.Now().Add(30 * time.Second)
	ticks, stop := c.tlsTicks(interval)
	defer stop()
	hints := make(chan struct{}, 1)
	failed := make(chan struct{})
	if notifications {
		done := make(chan struct{})
		go func() { defer close(done); c.readTLSHints(ctx, hints, failed) }()
		defer func() { cancel(); <-done }()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-failed:
			_ = c.Close(context.Background())
			return
		case now, ok := <-ticks:
			if !ok {
				_ = c.Close(context.Background())
				return
			}
			pending := false
			select {
			case <-hints:
				pending = true
			default:
			}
			if pending || !now.Before(nextPoll) {
				if err := c.refreshWorkspaceAuthority(ctx); err != nil {
					_ = c.Close(context.Background())
					return
				}
				if c.catalogDirty.Swap(false) && c.Unlocked() && c.catalogChanged != nil {
					c.catalogChanged()
				}
				nextPoll = now.Add(30 * time.Second)
			}
		}
	}
}

func (c *sharedAdmissionController) refreshWorkspaceAuthority(ctx context.Context) error {
	if c.Unlocked() {
		return c.withCatalogOperation(ctx, func(context.Context, sharedpg.TrustState, *sharedpg.TrustState) error {
			return nil
		}, func(ctx context.Context, _ sharedpg.TrustState) error {
			return c.reconcileWebViewGenerations(ctx)
		}, true)
	}
	if c.tlsManaged {
		return c.RefreshTLS(ctx)
	}
	return nil
}

func (c *sharedAdmissionController) readTLSHints(ctx context.Context, hints chan<- struct{}, failed chan<- struct{}) {
	for ctx.Err() == nil {
		id, err := c.session.NextChangeHint(ctx)
		if err != nil {
			if ctx.Err() == nil {
				close(failed)
			}
			return
		}
		if id != c.trustBinding.WorkspaceID.String() {
			continue
		}
		c.catalogDirty.Store(true)
		select {
		case <-ctx.Done():
			return
		case hints <- struct{}{}:
		}
	}
}
