package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedAccountOpenFromSetup(t *testing.T) {
	for _, mode := range []string{"success", "rotated-tls", "missing-tls-cache", "missing", "corrupt", "wrong-root", "pending", "password-transition", "local-floor", "revision", "canceled", "nil-context", "closed-owner", "unlock-error"} {
		t.Run(mode, func(t *testing.T) {
			old, previous, o, root, _, account, org := sharedUnlockFixture(t)
			if err := old.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			lifetime, cancel := context.WithCancel(context.Background())
			p := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response, accountState: previous.accountState, accountMaterial: previous.accountMaterial}
			c := newSharedAdmissionControllerWithSession(p)
			t.Cleanup(func() {
				if err := c.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			owner := derivedAccountForProbe(t, p, o, account)
			state, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
			if err != nil {
				t.Fatal(err)
			}
			managed := mode == "rotated-tls" || mode == "missing-tls-cache"
			if managed {
				bundle := sharedTLSFixture(t, &o, state, org, 3)
				next, e := state.AdvanceTLS(bundle)
				if e != nil {
					t.Fatal(e)
				}
				if e := writeSharedTrustFile(o.TrustPath, root, o.Binding, next, state.Revision); e != nil {
					t.Fatal(e)
				}
				state = next
			}
			raw, err := sharedpg.SealTransportSetup(root, o.Binding, o.Settings, state, o.OSFloor, o.UserFloor, o.Request.API)
			if err != nil {
				t.Fatal(err)
			}
			if err := persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), raw); err != nil {
				t.Fatal(err)
			}
			if managed {
				bundle := sharedTLSFixture(t, &o, state, org, 4)
				next, e := state.AdvanceTLS(bundle)
				if e != nil {
					t.Fatal(e)
				}
				if mode != "missing-tls-cache" {
					if e := writeSharedTLSCache(o.TrustPath, bundle); e != nil {
						t.Fatal(e)
					}
				}
				if e := writeSharedTrustFile(o.TrustPath, root, o.Binding, next, state.Revision); e != nil {
					t.Fatal(e)
				}
			}
			expected := o.Settings
			p.open = func(_ context.Context, got sharedpg.Settings) error {
				if !reflect.DeepEqual(got.Endpoints, expected.Endpoints) || got.Database != expected.Database || got.DeviceRole != expected.DeviceRole || got.TLS != expected.TLS || got.Changes != expected.Changes {
					t.Error("caller redirected protected connection")
				}
				if managed && (got.TLSBundle == nil || got.TLSBundle.Pin().MinimumSequence != 4) {
					t.Error("stale TLS bundle")
				}
				return nil
			}
			// Even plausible caller configuration must not select the destination.
			o.Settings = sharedpg.Settings{Database: "attacker", DeviceRole: "attacker"}
			ctx := context.Background()
			switch mode {
			case "missing":
				err = os.Remove(sharedTransportSetupPath(o.TrustPath))
			case "corrupt":
				err = os.WriteFile(sharedTransportSetupPath(o.TrustPath), []byte("tampered"), 0600)
			case "wrong-root":
				root = bytes.Repeat([]byte{42}, 32)
			case "pending":
				err = os.WriteFile(sharedPendingEnrollmentPath(o.TrustPath), []byte("pending"), 0600)
			case "password-transition":
				err = os.WriteFile(sharedTrustTransitionPath(o.TrustPath), []byte("pending"), 0600)
			case "local-floor":
				o.UserFloor = vault.Paranoid
			case "revision":
				o.MinimumRevision = state.Revision + 10
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			case "closed-owner":
				err = c.Close(context.Background())
			case "unlock-error":
				account.Envelope.Ciphertext[0] ^= 1
			}
			if err != nil {
				t.Fatal(err)
			}
			err = c.OpenAccountFromSetup(ctx, o, root, owner)
			if mode == "success" || mode == "rotated-tls" {
				if err != nil || !c.Unlocked() || p.opens.Load() != 1 {
					t.Fatal("protected reopen", err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if !c.Unlocked() {
					t.Fatal("borrowed master retained")
				}
				stored, e := os.ReadFile(sharedTransportSetupPath(o.TrustPath))
				if e != nil || !bytes.Equal(stored, raw) {
					t.Fatal("reopen rewrote setup", e)
				}
			} else {
				if err == nil || c.Admitted() || c.Unlocked() {
					t.Fatal("invalid reopen admitted", err)
				}
				wantOpens := int32(0)
				if mode == "unlock-error" {
					wantOpens = 1
				}
				if p.opens.Load() != wantOpens {
					t.Fatal("unexpected network call", p.opens.Load())
				}
				if mode == "pending" && !errors.Is(err, errSharedEnrollmentPending) {
					t.Fatal(err)
				}
				if mode == "password-transition" && !errors.Is(err, errSharedTrustTransitionPending) {
					t.Fatal(err)
				}
			}
		})
	}
}
