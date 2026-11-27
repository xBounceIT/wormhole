package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedPasswordRecoveryCloseAndPromotionFailure(t *testing.T) {
	for _, mode := range []string{"close", "promotion"} {
		t.Run(mode, func(t *testing.T) {
			c, p, o, master, newRoot, oldRoot, account, _ := sharedRecoveryFixture(t, true)
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			if mode == "close" {
				entered := make(chan struct{})
				p.accountState = func(ctx context.Context) (*vault.UserKeyState, error) {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				finished := make(chan error, 1)
				go func() {
					_, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword)
					finished <- err
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("recovery not reached")
				}
				if err := c.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("recovery stuck")
				}
				if _, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding); err != nil {
					t.Fatal("close erased pending journal", err)
				}
				return
			}
			p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
				privateFileDirectorySync = func(path string) error {
					if _, err := readSharedTrustFile(o.TrustPath, newRoot, o.Binding, 1); err == nil {
						return os.ErrPermission
					}
					return original(path)
				}
				return account, nil
			}
			result, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, sharedRecoveryNewPassword)
			privateFileDirectorySync = original
			if result == nil || !result.Changed || !errors.Is(err, errSharedTrustCommitUncertain) {
				t.Fatal("verified outcome lost", err)
			}
			pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := promoteSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, pending); err != nil {
				t.Fatal("local retry failed", err)
			}
		})
	}
}

func sharedRecoveryFixture(t *testing.T, committed bool) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	return sharedRecoveryFixtureWithSetup(t, committed, false)
}

func sharedRecoveryFixtureWithSetup(t *testing.T, committed, withSetup bool) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	t.Helper()
	old, previous, o, oldRoot, oldMaster, account, org := sharedPasswordFixture(t)
	if err := old.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := readSharedTrustFile(o.TrustPath, oldRoot, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	newRoot := bytes.Repeat([]byte{99}, 32)
	if withSetup {
		raw, err := sharedpg.SealTransportSetup(oldRoot, o.Binding, o.Settings, state, o.OSFloor, o.UserFloor, o.Request.API)
		if err != nil {
			t.Fatal(err)
		}
		if err := persistSharedTransitionBytes(sharedTransportSetupPath(o.TrustPath), raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stageSharedTrustRootTransition(o.TrustPath, oldRoot, newRoot, o.Binding, state.Revision); err != nil {
		t.Fatal(err)
	}
	activeMaster := oldMaster
	actual := *account
	if committed {
		activeMaster = bytes.Repeat([]byte{97}, 32)
		actual.Binding, actual.Envelope, err = vault.RewrapUserKeys(oldMaster, activeMaster, account.Binding, account.Envelope, vault.UserPublicKeys{Encryption: account.EncryptionCertificate.PublicKey, Signing: account.SigningCertificate.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	p := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response}
	p.loginMaterial, err = vault.DeriveKey(activeMaster, nil, vault.PurposeLogin)
	if err != nil {
		t.Fatal(err)
	}
	p.accountState = func(context.Context) (*vault.UserKeyState, error) { return actual.State, nil }
	p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return &actual, nil }
	c := newSharedAdmissionControllerWithSession(p)
	t.Cleanup(func() {
		p.closeFailure.Store(false)
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
		vault.Wipe(p.loginMaterial)
	})
	return c, p, o, activeMaster, newRoot, oldRoot, &actual, org
}

func TestSharedPasswordRecoveryOutcomes(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-password", true: "new-password"}[committed], func(t *testing.T) {
			c, p, o, master, newRoot, oldRoot, account, _ := sharedRecoveryFixture(t, committed)
			credential := sharedRecoveryOldPassword
			if committed {
				credential = sharedRecoveryNewPassword
			}
			p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
				if p.starts.Load() != 1 {
					t.Fatal("read preceded fresh audited proof")
				}
				return account, nil
			}
			result, err := c.RecoverPasswordChange(context.Background(), o, master, newRoot, oldRoot, vault.KDFV1, false, credential)
			if err != nil || result == nil || result.Changed != committed {
				t.Fatal("recovery failed", err)
			}
			root := oldRoot
			if committed {
				root = newRoot
			}
			restored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, result.TrustRevision)
			if err != nil || restored.WrappingRevision != account.Binding.Revision {
				t.Fatal("wrong destination", err)
			}
			if _, err := os.Stat(sharedTrustTransitionPath(o.TrustPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("journal retained")
			}
			if c.Admitted() || c.Unlocked() || p.opens.Load() != 1 || p.starts.Load() != 1 || p.closes.Load() == 0 {
				t.Fatal("recovery activated owner or skipped cleanup")
			}
		})
	}
}

func TestSharedPasswordRecoveryRejectsUnsafeOutcomes(t *testing.T) {
	for _, mode := range []string{"invalid", "cancelled", "started", "wrong-root", "minimum", "open-failure", "proof-failure", "nil-profile", "stronger-profile", "state-error", "nil-state", "forged-state", "revoked", "material-error", "nil-material", "nil-cert", "late-revoked", "tampered", "wrong-kdf", "wrong-ask", "new-mode-old-wrap", "old-mode-new-wrap", "old-root", "cleanup", "observation-failure", "observation-confirmation", "cancel-after-proof"} {
		t.Run(mode, func(t *testing.T) {
			committed := mode != "new-mode-old-wrap" && mode != "old-root"
			c, p, o, master, newRoot, oldRoot, account, org := sharedRecoveryFixture(t, committed)
			credential := sharedRecoveryNewPassword
			if mode == "old-mode-new-wrap" || mode == "old-root" {
				credential = sharedRecoveryOldPassword
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			switch mode {
			case "invalid":
				credential = 0
			case "cancelled":
				cancel()
			case "started":
				c.started = true
			case "wrong-root":
				newRoot = bytes.Repeat([]byte{2}, 32)
			case "minimum":
				o.MinimumRevision = 999
			case "open-failure":
				p.open = func(context.Context, sharedpg.Settings) error { return sharedpg.ErrAuthentication }
			case "proof-failure":
				p.start = func(context.Context) error { return sharedpg.ErrChangeInProgress }
			case "nil-profile":
				p.response = nil
			case "stronger-profile":
				signed, e := vault.DecodeSignedPolicy(p.response.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				signed.Policy.Sequence++
				signed.Policy.Profile = vault.Hardened
				signed.Policy.KDF = vault.KDFV2
				signed, e = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
				if e != nil {
					t.Fatal(e)
				}
				p.response.SignedProfile, e = vault.EncodeSignedPolicy(signed)
				if e != nil {
					t.Fatal(e)
				}
			case "state-error":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, sharedpg.ErrQuery }
			case "nil-state":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, nil }
			case "forged-state":
				forged := *account.State
				forged.Sequence++
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return &forged, nil }
			case "material-error":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, sharedpg.ErrQuery }
			case "nil-material":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, nil }
			case "nil-cert":
				account.EncryptionCertificate = nil
			case "revoked", "late-revoked":
				active := *account.State
				revoked := active
				revoked.Sequence++
				revoked.Active = false
				var err error
				revoked, err = vault.SignUserKeyState(revoked, org)
				if err != nil {
					t.Fatal(err)
				}
				account.State = &revoked
				if mode == "late-revoked" {
					p.accountState = func(context.Context) (*vault.UserKeyState, error) { return &active, nil }
				}
			case "tampered":
				account.Envelope.Ciphertext = bytes.Clone(account.Envelope.Ciphertext)
				account.Envelope.Ciphertext[0] ^= 1
			case "wrong-kdf":
				account.KDF = vault.KDFLow
			case "wrong-ask":
				account.ASKRequired = true
			case "old-root":
				oldRoot = bytes.Repeat([]byte{2}, 32)
			case "cleanup":
				p.closeFailure.Store(true)
			case "observation-failure", "observation-confirmation":
				calls := 0
				privateFileDirectorySync = func(path string) error {
					calls++
					if mode == "observation-failure" || calls == 1 {
						return os.ErrPermission
					}
					return original(path)
				}
			case "cancel-after-proof":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { cancel(); return account, nil }
			}
			result, err := c.RecoverPasswordChange(ctx, o, master, newRoot, oldRoot, vault.KDFV1, false, credential)
			privateFileDirectorySync = original
			if mode == "observation-confirmation" {
				if err != nil || result == nil {
					t.Fatal("durability confirmation failed", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid recovery succeeded")
			}
			if mode == "cleanup" {
				if result == nil || !errors.Is(err, errSharedAdmissionCleanup) {
					t.Fatal("proof/cleanup lost", err)
				}
				return
			}
			if mode == "old-root" {
				if result == nil || !errors.Is(err, errSharedTrustConflict) {
					t.Fatal("wrong original root not rejected", err)
				}
			} else if result != nil {
				t.Fatal("unproven outcome returned")
			}
			if c.Admitted() || c.Unlocked() {
				t.Fatal("failed recovery activated owner")
			}
			if mode == "wrong-root" {
				newRoot = bytes.Repeat([]byte{99}, 32)
			}
			journal, e := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
			if e != nil {
				t.Fatal("uncertain recovery erased journal", e)
			}
			if mode == "revoked" || mode == "late-revoked" {
				if journal.ObservedTrust().Account.Active {
					t.Fatal("revocation not retained")
				}
			}
			if mode == "stronger-profile" {
				policy, e := journal.ObservedTrust().Policy()
				if e != nil || policy.Profile != vault.Hardened {
					t.Fatal("stronger profile lost", e)
				}
			}
		})
	}
}
