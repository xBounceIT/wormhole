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

func awaitTLSMonitor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS monitor did not complete")
	}
}

func TestSharedAuthorityPollWithoutNotifications(t *testing.T) {
	for _, signedRevocation := range []bool{false, true} {
		name := "withdrawn admission"
		if signedRevocation {
			name = "signed account revocation"
		}
		t.Run(name, func(t *testing.T) {
			ticks := make(chan time.Time)
			started, checked, stopped := make(chan struct{}), make(chan struct{}, 2), make(chan struct{})
			var lost atomic.Bool
			var replacement atomic.Pointer[vault.UserKeyState]
			c, _, options, root, master, account, org := sharedUnlockFixtureWithPolicy(t, vault.Default, vault.KDFV1, false,
				func(c *sharedAdmissionController, p *sharedAdmissionProbe, opts *sharedAdmissionOptions) {
					opts.OSFloor, opts.Settings.TLS, opts.Settings.CAPEM = vault.Default, sharedpg.TLSOff, nil
					c.tlsTicks = func(interval time.Duration) (<-chan time.Time, func()) {
						if interval != 30*time.Second {
							t.Error("unexpected polling interval", interval)
						}
						close(started)
						return ticks, func() { close(stopped) }
					}
					p.subscribe = func(context.Context) error {
						t.Error("transaction pooler attempted LISTEN")
						return sharedpg.ErrNotifications
					}
					verify := p.accountState
					p.accountState = func(ctx context.Context) (*vault.UserKeyState, error) {
						if state := replacement.Load(); state != nil {
							return state, nil
						}
						if lost.Load() {
							return nil, sharedpg.ErrIdentityUnavailable
						}
						return verify(ctx)
					}
					c.catalogAnchor = func(context.Context, string, []byte, sharedpg.TrustBinding, sharedpg.TrustState) error {
						checked <- struct{}{}
						return nil
					}
				})
			if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
				t.Fatal(err)
			}
			awaitTLSMonitor(t, started)
			owner := c.privateKeys
			now := time.Now().Add(31 * time.Second)
			ticks <- now
			awaitTLSMonitor(t, checked)
			if !c.Unlocked() {
				t.Fatal("a healthy idle account lost its session")
			}
			if signedRevocation {
				state := *account.State
				state.Active = false
				state.Sequence++
				state, err := vault.SignUserKeyState(state, org)
				if err != nil {
					t.Fatal(err)
				}
				replacement.Store(&state)
			} else {
				lost.Store(true)
			}
			ticks <- now.Add(30 * time.Second)
			awaitTLSMonitor(t, stopped)
			if c.Unlocked() || owner.With(func([]byte) error { return nil }) == nil {
				t.Fatal("background revocation retained private keys")
			}
			if signedRevocation {
				trust, err := readSharedTrustFile(options.TrustPath, root, options.Binding, 1)
				if err != nil || trust.Account == nil || trust.Account.Active || trust.Account.Sequence != account.State.Sequence+1 {
					t.Fatal("the verified signed revocation was not retained", err)
				}
			}
		})
	}
}

func TestSharedTLSMonitor(t *testing.T) {
	for _, mode := range []string{"poll-change", "listen-periodic", "hint-change", "hint-unchanged", "stream-failure", "clock-closed", "close", "subscribe-failure"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, _, org := sharedTLSRefreshFixture(t)
			if mode == "poll-change" {
				o.Settings.Changes.TransactionPooler = true
			}
			ticks := make(chan time.Time)
			started, stopped := make(chan struct{}), make(chan struct{})
			c.tlsTicks = func(interval time.Duration) (<-chan time.Time, func()) {
				want := time.Second
				if mode == "poll-change" {
					want = 30 * time.Second
				}
				if interval != want {
					t.Error("incorrect monitor interval", interval)
				}
				close(started)
				return ticks, func() { close(stopped) }
			}
			var calls, subscribed atomic.Int32
			var updated atomic.Bool
			initial, e := sharedpg.DecodeTLSTrustBundle(o.Settings.TLSBundle.Encode())
			if e != nil {
				t.Fatal(e)
			}
			state, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if e != nil {
				t.Fatal(e)
			}
			newOptions := o
			newBundle := sharedTLSFixture(t, &newOptions, state, org, 4)
			newDocument, e := sharedpg.DecodeTLSTrustBundle(newBundle.Encode())
			if e != nil {
				t.Fatal(e)
			}
			reads := make(chan struct{}, 8)
			p.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
				calls.Add(1)
				reads <- struct{}{}
				if updated.Load() {
					return &newDocument, nil
				}
				return &initial, nil
			}
			p.subscribe = func(context.Context) error {
				subscribed.Add(1)
				if calls.Load() != 0 {
					t.Error("read before LISTEN subscription")
				}
				if mode == "subscribe-failure" {
					return sharedpg.ErrNotifications
				}
				return nil
			}
			events := make(chan error)
			waiting := make(chan struct{}, 8)
			p.hint = func(ctx context.Context) (string, error) {
				waiting <- struct{}{}
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				case err := <-events:
					return o.Binding.WorkspaceID.String(), err
				}
			}
			err := c.Open(context.Background(), o, root, p.loginMaterial)
			if mode == "subscribe-failure" {
				if err != sharedpg.ErrNotifications || c.Admitted() || calls.Load() != 0 {
					t.Fatal("subscription failure admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			awaitTLSMonitor(t, reads)
			awaitTLSMonitor(t, started)
			if mode == "poll-change" {
				if subscribed.Load() != 0 {
					t.Fatal("transaction pooler subscribed")
				}
			} else {
				awaitTLSMonitor(t, waiting)
				if subscribed.Load() != 1 {
					t.Fatal("missing subscription")
				}
			}
			updated.Store(mode != "hint-unchanged")
			switch mode {
			case "close":
				if err := c.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "clock-closed":
				close(ticks)
			case "stream-failure":
				events <- sharedpg.ErrNotifications
			case "hint-change", "hint-unchanged":
				events <- nil
				// Entering the next receive proves the prior hint was queued.
				awaitTLSMonitor(t, waiting)
				if calls.Load() != 1 {
					t.Fatal("hint bypassed rate limit")
				}
				ticks <- time.Now()
			default:
				ticks <- time.Now() // No hint and polling deadline has not elapsed.
				ticks <- time.Now().Add(31 * time.Second)
			}
			if mode == "hint-unchanged" {
				awaitTLSMonitor(t, reads)
				if !c.Admitted() {
					t.Fatal("unchanged hint retired owner")
				}
				if err := c.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			awaitTLSMonitor(t, stopped)
			if c.Admitted() {
				t.Fatal("monitor exit retained admission")
			}
			saved, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(3)
			if mode == "poll-change" || mode == "listen-periodic" || mode == "hint-change" {
				want = 4
			}
			if saved.TLSSequence != want {
				t.Fatal("wrong monitored floor", saved.TLSSequence)
			}
		})
	}
}

func TestSharedTLSMonitorTickSource(t *testing.T) {
	ticks, stop := newSharedTLSTicks(time.Second)
	if ticks == nil || stop == nil {
		t.Fatal("missing monitor clock")
	}
	stop()
	stop()
}

func TestSharedTLSHintBackpressure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	second := make(chan struct{})
	workspace := uuid.MustParse("12345678-1234-4234-8234-123456789abc")
	p := &sharedAdmissionProbe{hint: func(context.Context) (string, error) {
		if calls.Add(1) == 2 {
			close(second)
		}
		return workspace.String(), nil
	}}
	c := &sharedAdmissionController{session: p}
	c.trustBinding.WorkspaceID = workspace
	hints, failed, done := make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	go func() { defer close(done); c.readTLSHints(ctx, hints, failed) }()
	awaitTLSMonitor(t, second)
	cancel()
	awaitTLSMonitor(t, done)
	if calls.Load() != 2 || len(hints) != 1 {
		t.Fatal("hint stream not bounded", calls.Load())
	}
	select {
	case <-failed:
		t.Fatal("intentional cancellation treated as stream failure")
	default:
	}
}

func TestSharedTLSHintCancellationWithUnrelatedNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	p := &sharedAdmissionProbe{hint: func(context.Context) (string, error) {
		calls.Add(1)
		cancel()
		return "12345678-1234-4234-8234-123456789abc", nil
	}}
	c := &sharedAdmissionController{session: p}
	hints := make(chan struct{}, 1)
	failed, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); c.readTLSHints(ctx, hints, failed) }()
	awaitTLSMonitor(t, done)
	if calls.Load() != 1 || len(hints) != 0 || c.catalogDirty.Load() {
		t.Fatal("unrelated notification was published or stream kept reading after cancellation")
	}
	select {
	case <-failed:
		t.Fatal("intentional cancellation treated as stream failure")
	default:
	}
}
