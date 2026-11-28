package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedCatalogEventCoalescing(t *testing.T) {
	h := &vaultFoundationHandler{catalogEvents: make(chan struct{}, 1)}
	for i := 0; i < 100; i++ {
		h.notifySharedCatalog()
	}
	if len(h.catalogEvents) != 1 || h.SharedCatalogEvents() != h.catalogEvents {
		t.Fatal("unbounded invalidations")
	}
	(&vaultFoundationHandler{}).notifySharedCatalog()
}

func TestSharedCatalogNotificationMonitor(t *testing.T) {
	ticks := make(chan time.Time)
	started, stopped := make(chan struct{}), make(chan struct{})
	events := make(chan string)
	waiting := make(chan struct{}, 8)
	notified := make(chan struct{}, 1)
	var accountReads atomic.Int32
	c, _, o, _, master, _, _ := sharedUnlockFixtureWithPolicy(t, vault.Standard, vault.KDFV1, false,
		func(c *sharedAdmissionController, p *sharedAdmissionProbe, options *sharedAdmissionOptions) {
			options.Settings.Changes.TransactionPooler = false
			c.tlsTicks = func(interval time.Duration) (<-chan time.Time, func()) {
				if interval != time.Second {
					t.Error(interval)
				}
				close(started)
				return ticks, func() { close(stopped) }
			}
			p.hint = func(ctx context.Context) (string, error) {
				waiting <- struct{}{}
				select {
				case id := <-events:
					return id, nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}
			read := p.accountState
			p.accountState = func(ctx context.Context) (*vault.UserKeyState, error) {
				accountReads.Add(1)
				return read(ctx)
			}
			c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error { return nil }
			c.catalogChanged = func() { notified <- struct{}{} }
		})
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	awaitTLSMonitor(t, started)
	awaitTLSMonitor(t, waiting)
	baseline := accountReads.Load()
	events <- uuid.NewString()
	awaitTLSMonitor(t, waiting)
	ticks <- time.Now()
	ticks <- time.Now()
	select {
	case <-notified:
		t.Fatal("foreign workspace hint")
	default:
	}
	if accountReads.Load() != baseline {
		t.Fatal("foreign workspace hint requested account state")
	}
	events <- o.Binding.WorkspaceID.String()
	awaitTLSMonitor(t, waiting)
	ticks <- time.Now()
	awaitTLSMonitor(t, notified)
	if accountReads.Load() != baseline+1 {
		t.Fatal("hint was published without authenticated account state")
	}
	c.unlocked.Store(false)
	events <- o.Binding.WorkspaceID.String()
	awaitTLSMonitor(t, waiting)
	ticks <- time.Now()
	ticks <- time.Now()
	select {
	case <-notified:
		t.Fatal("locked owner emitted")
	default:
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitTLSMonitor(t, stopped)
}
