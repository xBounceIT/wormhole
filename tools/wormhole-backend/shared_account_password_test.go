package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func derivedAccountForProbe(t *testing.T, p *sharedAdmissionProbe, o sharedAdmissionOptions, account *sharedpg.UnverifiedAccountKeys) *sharedpg.AccountMaster {
	t.Helper()
	signed, err := vault.DecodeSignedPolicy(p.response.SignedProfile)
	if err != nil {
		t.Fatal(err)
	}
	d := sharedpg.AccountDerivation{WorkspaceID: o.Binding.WorkspaceID, LoginName: "utente@example.test", Preset: vault.KDFV1, EffectiveProfile: vault.Standard}
	owner, err := sharedpg.DeriveAccountMaster(context.Background(), d, signed.Policy, []byte("native-shared-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
		vault.Wipe(p.loginMaterial)
	})
	if err := owner.Use(func(master []byte, preset vault.KDFPreset, ask bool) error {
		keys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{33}, 32), SigningSeed: bytes.Repeat([]byte{34}, 32)}
		defer keys.Wipe()
		var err error
		account.Envelope, err = vault.SealUserKeys(master, account.Binding, keys)
		if err != nil {
			return err
		}
		vault.Wipe(p.loginMaterial)
		p.loginMaterial, err = vault.DeriveKey(master, nil, vault.PurposeLogin)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestSharedDerivedAccountRejectsWeakerMasterBeforeNetwork(t *testing.T) {
	for _, recovering := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "recover"}[recovering], func(t *testing.T) {
			c, p, o, _, newRoot, oldRoot, _, _ := sharedRecoveryFixture(t, true)
			// Recovery uses a pending journal. For ordinary login retain the exact
			// original trust file and remove the synthetic pre-dispatch journal.
			if !recovering {
				pending, err := readSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding)
				if err != nil {
					t.Fatal(err)
				}
				if err := abortSharedTrustRootTransition(o.TrustPath, newRoot, o.Binding, pending); err != nil {
					t.Fatal(err)
				}
			}
			policy := vault.Policy{FormatVersion: 1, WorkspaceID: o.Binding.WorkspaceID.String(), Sequence: 1, Profile: vault.Default, KDF: vault.KDFLow, LowKDFApproved: true, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
			owner, err := sharedpg.DeriveAccountMaster(context.Background(), sharedpg.AccountDerivation{WorkspaceID: o.Binding.WorkspaceID, LoginName: "utente@example.test", Preset: vault.KDFLow, EffectiveProfile: vault.Default}, policy, []byte("test-password"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if err := owner.Use(func(master []byte, _ vault.KDFPreset, _ bool) error {
				vault.Wipe(p.loginMaterial)
				var e error
				p.loginMaterial, e = vault.DeriveKey(master, nil, vault.PurposeLogin)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			p.open = func(context.Context, sharedpg.Settings) error { t.Fatal("weak derivation reached network"); return nil }
			if recovering {
				_, err = c.RecoverAccount(context.Background(), o, owner, newRoot, oldRoot, sharedRecoveryNewPassword)
			} else {
				err = c.OpenAccount(context.Background(), o, oldRoot, owner)
			}
			if err == nil || p.opens.Load() != 0 || c.Admitted() {
				t.Fatal("stronger cached policy was bypassed", err)
			}
		})
	}
}

func TestSharedAccountPasswordOpen(t *testing.T) {
	for _, mode := range []string{"success", "nil", "foreign", "closed", "open-error", "unlock-error", "stronger-server-policy"} {
		t.Run(mode, func(t *testing.T) {
			old, previous, o, root, _, account, org := sharedUnlockFixture(t)
			if err := old.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			lifetime, cancel := context.WithCancel(context.Background())
			p := &sharedAdmissionProbe{ctx: lifetime, cancel: cancel, response: previous.response}
			p.accountState = func(context.Context) (*vault.UserKeyState, error) { return account.State, nil }
			p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return account, nil }
			c := newSharedAdmissionControllerWithSession(p)
			t.Cleanup(func() {
				if err := c.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			owner := derivedAccountForProbe(t, p, o, account)
			switch mode {
			case "nil":
				owner = nil
			case "foreign":
				o.Binding.WorkspaceID = uuid.New()
			case "closed":
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			case "open-error":
				p.open = func(context.Context, sharedpg.Settings) error { return sharedpg.ErrAuthentication }
			case "unlock-error":
				account.Envelope.Ciphertext[0] ^= 1
			case "stronger-server-policy":
				signed, e := vault.DecodeSignedPolicy(p.response.SignedProfile)
				if e != nil {
					t.Fatal(e)
				}
				signed.Policy.Sequence++
				signed.Policy.ASKRequired = true
				signed, e = vault.SignPolicy(signed.Policy, signed.SignerKeyID, signed.SignerKeyVersion, org)
				if e != nil {
					t.Fatal(e)
				}
				p.response.SignedProfile, e = vault.EncodeSignedPolicy(signed)
				if e != nil {
					t.Fatal(e)
				}
				p.accountState = func(context.Context) (*vault.UserKeyState, error) {
					t.Fatal("incompatible derivation reached account fetch")
					return nil, nil
				}
			}
			err := c.OpenAccount(context.Background(), o, root, owner)
			if mode == "success" {
				if err != nil || !c.Unlocked() {
					t.Fatal("native password failed", err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if !c.Unlocked() {
					t.Fatal("controller retained borrowed master instead of its own keys")
				}
			} else {
				if err == nil || c.Unlocked() {
					t.Fatal("invalid account opened")
				}
				if mode == "closed" && !errors.Is(err, securemem.ErrClosed) {
					t.Fatal(err)
				}
				if (mode == "nil" || mode == "foreign" || mode == "closed") && p.opens.Load() != 0 {
					t.Fatal("invalid owner reached network")
				}
				if (mode == "open-error" || mode == "unlock-error") && c.Admitted() {
					t.Fatal("failed account kept admission")
				}
				if mode == "stronger-server-policy" {
					current, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
					if e != nil {
						t.Fatal(e)
					}
					policy, e := current.Policy()
					if e != nil || !policy.ASKRequired || c.Admitted() {
						t.Fatal("stronger policy was not retained before denial", e)
					}
				}
			}
		})
	}
}

func TestSharedDerivedAccountRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "noncommit", true: "commit"}[committed], func(t *testing.T) {
			c, p, o, _, newRoot, oldRoot, account, _ := sharedRecoveryFixture(t, committed)
			owner := derivedAccountForProbe(t, p, o, account)
			credential := sharedRecoveryOldPassword
			if committed {
				credential = sharedRecoveryNewPassword
			}
			if result, err := c.RecoverAccount(context.Background(), o, nil, newRoot, oldRoot, credential); result != nil || err != sharedpg.ErrConfiguration {
				t.Fatal("nil owner", err)
			}
			foreign := o
			foreign.Binding.WorkspaceID = uuid.New()
			if result, err := c.RecoverAccount(context.Background(), foreign, owner, newRoot, oldRoot, credential); result != nil || err != sharedpg.ErrConfiguration {
				t.Fatal("foreign owner", err)
			}
			result, err := c.RecoverAccount(context.Background(), o, owner, newRoot, oldRoot, credential)
			if err != nil || result == nil || result.Changed != committed {
				t.Fatal("derived recovery failed", err)
			}
			if c.Unlocked() || c.Admitted() {
				t.Fatal("recovery activated session")
			}
		})
	}
}
