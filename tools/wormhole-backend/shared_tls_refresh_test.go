package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedTLSRefreshFixture(t *testing.T) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, ed25519.PrivateKey) {
	t.Helper()
	old, p, o, root, master, _, org := sharedUnlockFixture(t)
	o.Settings.Changes = sharedpg.ChangePolicy{}
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p = &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: p.response, loginMaterial: p.loginMaterial, accountState: p.accountState, accountMaterial: p.accountMaterial}
	c := newSharedAdmissionControllerWithSession(p)
	// Refresh tests drive checks explicitly; monitor tests supply their own clock.
	c.tlsTicks = func(time.Duration) (<-chan time.Time, func()) { return nil, func() {} }
	t.Cleanup(func() {
		p.closeFailure.Store(false)
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	sharedTLSFixture(t, &o, state, org, 3)
	return c, p, o, root, master, org
}

func TestSharedTLSRefresh(t *testing.T) {
	for _, mode := range []string{"same", "new", "opening-new", "signature", "rollback", "equivocation", "nil", "query", "malformed", "storage", "conflict", "cleanup", "cancel-during-read"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, root, _, org := sharedTLSRefreshFixture(t)
			if mode != "opening-new" {
				if err := c.Open(context.Background(), o, root, p.loginMaterial); err != nil {
					t.Fatal(err)
				}
			}
			state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			seq := uint64(4)
			if mode == "rollback" {
				seq = 2
			}
			if mode == "equivocation" {
				seq = 3
			}
			newOptions := o
			v := sharedTLSFixture(t, &newOptions, state, org, seq)
			b, err := sharedpg.DecodeTLSTrustBundle(v.Encode())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode != "same" {
				p.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
					switch mode {
					case "nil":
						return nil, nil
					case "query":
						return nil, sharedpg.ErrQuery
					case "cancel-during-read":
						cancel()
					}
					return &b, nil
				}
			}
			if mode == "signature" {
				b.Signature[0] ^= 1
			}
			if mode == "malformed" {
				b.FormatVersion = 0
			}
			if mode == "cleanup" {
				p.closeFailure.Store(true)
			}
			if mode == "storage" {
				original := privateFileDirectorySync
				privateFileDirectorySync = func(string) error { return os.ErrPermission }
				t.Cleanup(func() { privateFileDirectorySync = original })
			}
			if mode == "conflict" {
				if _, err := acceptSharedTLSBundle(newOptions, root, state); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "opening-new" {
				err = c.Open(ctx, o, root, p.loginMaterial)
			} else {
				err = c.RefreshTLS(ctx)
			}
			if mode == "same" {
				if err != nil || !c.Admitted() {
					t.Fatal("unchanged transport retired", err)
				}
				return
			}
			if err == nil || c.Admitted() {
				t.Fatal("failed/obsolete transport retained", err)
			}
			want := map[string]error{"new": errSharedTLSChanged, "opening-new": errSharedTLSChanged, "signature": vault.ErrAuthentication, "rollback": vault.ErrRollback, "equivocation": vault.ErrRollback, "nil": sharedpg.ErrAdmissionResponse, "query": sharedpg.ErrQuery, "conflict": errSharedTrustConflict, "cleanup": errSharedAdmissionCleanup, "cancel-during-read": context.Canceled}[mode]
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("error %v, want %v", err, want)
			}
			saved, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if e != nil {
				t.Fatal(e)
			}
			wantSeq := uint64(3)
			if mode == "new" || mode == "opening-new" || mode == "cleanup" || mode == "conflict" {
				wantSeq = 4
			}
			if saved.TLSSequence != wantSeq {
				t.Fatal("incorrect durable TLS floor", saved.TLSSequence, wantSeq)
			}
			if wantSeq == 4 {
				cache, e := readSharedTLSCache(o.TrustPath, saved)
				if e != nil || cache == nil {
					t.Fatal("missing committed cache", e)
				}
			}
			if mode == "new" {
				lifetime, stop := context.WithCancel(context.Background())
				probe := &sharedAdmissionProbe{ctx: lifetime, cancel: stop, response: p.response, loginMaterial: p.loginMaterial, tlsRead: p.tlsRead}
				fresh := newSharedAdmissionControllerWithSession(probe)
				t.Cleanup(func() {
					if err := fresh.Close(context.Background()); err != nil {
						t.Error(err)
					}
				})
				o.Settings.TLSBundle = nil
				probe.open = func(_ context.Context, s sharedpg.Settings) error {
					if s.TLSBundle == nil || s.TLSBundle.Pin().MinimumSequence != 4 {
						t.Fatal("reconnect did not load new TLS bundle")
					}
					return nil
				}
				if err := fresh.Open(context.Background(), o, root, probe.loginMaterial); err != nil {
					t.Fatal("reconnect", err)
				}
			}
		})
	}
}

func TestSharedTLSRefreshCloseCancels(t *testing.T) {
	c, p, o, root, _, _ := sharedTLSRefreshFixture(t)
	if err := c.Open(context.Background(), o, root, p.loginMaterial); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	p.tlsRead = func(ctx context.Context) (*sharedpg.TLSTrustBundle, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- c.RefreshTLS(context.Background()) }()
	<-entered
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != context.Canceled {
		t.Fatal(err)
	}
	if c.Admitted() || c.Unlocked() {
		t.Fatal("closed owner remains usable")
	}
}

func TestSharedTLSRefreshGuards(t *testing.T) {
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Default)
	if err := c.RefreshTLS(nil); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if err := c.RefreshTLS(context.Background()); err != sharedpg.ErrSessionClosed {
		t.Fatal(err)
	}
	if err := c.Open(context.Background(), o, root, p.expectedMaterial()); err != nil {
		t.Fatal(err)
	}
	if err := c.RefreshTLS(context.Background()); err != sharedpg.ErrConfiguration || !c.Admitted() {
		t.Fatal("legacy transport changed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.RefreshTLS(ctx); err != context.Canceled || !c.Admitted() {
		t.Fatal(err)
	}
}

func TestSharedTLSRecoveryRefresh(t *testing.T) {
	for _, mode := range []string{"new", "signature", "query", "storage"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, master, newRoot, oldRoot, _, org := sharedRecoveryFixture(t, true)
			pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if err != nil {
				t.Fatal(err)
			}
			sharedTLSFixture(t, &o, pending.ObservedTrust(), org, 5)
			updated := o
			v := sharedTLSFixture(t, &updated, pending.ObservedTrust(), org, 6)
			b, err := sharedpg.DecodeTLSTrustBundle(v.Encode())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "signature" {
				b.Signature[0] ^= 1
			}
			p.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) {
				if mode == "query" {
					return nil, sharedpg.ErrQuery
				}
				if mode == "storage" {
					original := privateFileDirectorySync
					privateFileDirectorySync = func(string) error { return os.ErrPermission }
					t.Cleanup(func() { privateFileDirectorySync = original })
				}
				return &b, nil
			}
			result, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword)
			if err == nil || result != nil || c.Admitted() {
				t.Fatal("recovery continued on stale TLS", err)
			}
			if mode == "new" && err != errSharedTLSChanged {
				t.Fatal(err)
			}
			pending, err = readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if err != nil {
				t.Fatal("journal lost", err)
			}
			want := uint64(5)
			if mode == "new" {
				want = 6
			}
			if pending.ObservedTrust().TLSSequence != want {
				t.Fatal("wrong observed TLS floor")
			}
			if _, err := readSharedTLSCache(o.TrustPath, pending.ObservedTrust()); err != nil {
				t.Fatal("journal has no cache", err)
			}
		})
	}
}

func TestSharedTLSRefreshBeforeAccountUse(t *testing.T) {
	c, p, o, root, master, org := sharedTLSRefreshFixture(t)
	if err := c.Open(context.Background(), o, root, p.loginMaterial); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	v := sharedTLSFixture(t, &o, state, org, 4)
	b, err := sharedpg.DecodeTLSTrustBundle(v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	p.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) { return &b, nil }
	p.accountState = func(context.Context) (*vault.UserKeyState, error) {
		t.Fatal("account read before TLS refresh")
		return nil, nil
	}
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != errSharedTLSChanged {
		t.Fatal(err)
	}
	if c.Admitted() || c.Unlocked() {
		t.Fatal("owner remains usable")
	}
}

func TestSharedTLSRefreshCheckpointsAnUnlockedDeviceBeforeDisconnect(t *testing.T) {
	for _, mode := range []string{"published", "storage-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			c, p, o, root, master, org := sharedTLSRefreshFixture(t)
			if err := c.Open(ctx, o, root, p.loginMaterial); err != nil {
				t.Fatal(err)
			}
			if err := c.Unlock(ctx, master, vault.KDFV1, false); err != nil {
				t.Fatal(err)
			}
			state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			update := sharedTLSFixture(t, &o, state, org, state.TLSSequence+1)
			bundle, err := sharedpg.DecodeTLSTrustBundle(update.Encode())
			if err != nil {
				t.Fatal(err)
			}
			p.tlsRead = func(context.Context) (*sharedpg.TLSTrustBundle, error) { return &bundle, nil }
			published := false
			c.catalogAnchor = func(_ context.Context, path string, key []byte, binding sharedpg.TrustBinding, trust sharedpg.TrustState) error {
				durable, err := readSharedTrustFile(path, key, binding, trust.Revision)
				if err != nil || durable.TLSSequence != bundle.Sequence || trust.TLSSequence != durable.TLSSequence {
					t.Fatal("startup checkpoint preceded the encrypted cache", err)
				}
				published = true
				if mode == "storage-failure" {
					return errSharedTrustStorage
				}
				return nil
			}
			want := errSharedTLSChanged
			if mode == "storage-failure" {
				want = errSharedTrustStorage
			}
			if err := c.RefreshTLS(ctx); !errors.Is(err, want) || !published || c.Admitted() || c.Unlocked() {
				t.Fatal("device kept its obsolete session or lost the publication result", err)
			}
		})
	}
}
