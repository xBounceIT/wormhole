package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func sharedUnlockFixture(t *testing.T) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	return sharedUnlockFixtureWithASK(t, false)
}

func sharedUnlockFixtureWithASK(t *testing.T, ask bool) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	return sharedUnlockFixtureWithPolicy(t, vault.Standard, vault.KDFV1, ask)
}

func sharedUnlockFixtureWithPolicy(t *testing.T, profile vault.Profile, preset vault.KDFPreset, ask bool,
	configure ...func(*sharedAdmissionController, *sharedAdmissionProbe, *sharedAdmissionOptions),
) (*sharedAdmissionController, *sharedAdmissionProbe, sharedAdmissionOptions, []byte, []byte, *sharedpg.UnverifiedAccountKeys, ed25519.PrivateKey) {
	t.Helper()
	c, p, o, root, _, _ := sharedControllerFixture(t, vault.Standard)
	// Account-key fixtures mutate probes; notification concurrency has its own fixture.
	o.Settings.Changes.TransactionPooler = true
	org := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	t.Cleanup(func() { vault.Wipe(org) })
	signer := vault.KeyRef{ID: uuid.New(), Version: 1}
	policy := vault.Policy{FormatVersion: 1, WorkspaceID: o.Binding.WorkspaceID.String(), Sequence: 1, Profile: profile, KDF: preset, LowKDFApproved: preset == vault.KDFLow, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	o.OSFloor = vault.Standard
	policy.ASKRequired = ask
	signed, err := vault.SignPolicy(policy, signer.ID.String(), 1, org)
	if err != nil {
		t.Fatal(err)
	}
	p.response.SignedProfile, err = vault.EncodeSignedPolicy(signed)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := sharedpg.NewTrustState(p.response, o.Request, sharedpg.PolicyTrust{WorkspaceID: o.Binding.WorkspaceID, SignerKeyID: signer.ID.String(), SignerKeyVersion: 1, PublicKey: org.Public().(ed25519.PublicKey), MinimumSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	o.TrustPath = filepath.Join(t.TempDir(), "unlock.trust")
	if err := writeSharedTrustFile(o.TrustPath, root, o.Binding, initial, 0); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{9}, 32)
	p.loginMaterial, err = vault.DeriveKey(master, nil, vault.PurposeLogin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vault.Wipe(master); vault.Wipe(p.loginMaterial) })
	keys := &vault.UserKeys{EncryptionPrivate: bytes.Repeat([]byte{33}, 32), SigningSeed: bytes.Repeat([]byte{34}, 32)}
	defer keys.Wipe()
	public, err := keys.Public()
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.UserKeyBinding{WorkspaceID: o.Binding.WorkspaceID, UserID: o.Binding.UserID, Encryption: vault.KeyRef{ID: uuid.New(), Version: 1}, Signing: vault.KeyRef{ID: uuid.New(), Version: 1}, Revision: 2}
	envelope, err := vault.SealUserKeys(master, binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: binding.Encryption, Kind: "user-enc", Suite: 2, PublicKey: public.Encryption, Revision: 1, Signer: signer}, org)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := vault.SignUserKeyCertificate(vault.UserKeyCertificate{FormatVersion: 1, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Key: binding.Signing, Kind: "user-sign", Suite: 1, PublicKey: public.Signing, Revision: 1, Signer: signer}, org)
	if err != nil {
		t.Fatal(err)
	}
	state, err := vault.SignUserKeyState(vault.UserKeyState{FormatVersion: 1, WorkspaceID: binding.WorkspaceID, UserID: binding.UserID, Sequence: 3, Active: true, Encryption: binding.Encryption, Signing: binding.Signing, MinimumEncryptionCertificate: 1, MinimumSigningCertificate: 1, Signer: signer}, org)
	if err != nil {
		t.Fatal(err)
	}
	account := &sharedpg.UnverifiedAccountKeys{Binding: binding, Envelope: envelope, KDF: preset, EncryptionCertificate: &enc, SigningCertificate: &sign, State: &state}
	account.ASKRequired = ask
	p.accountState = func(context.Context) (*vault.UserKeyState, error) { return account.State, nil }
	p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return account, nil }
	for _, setup := range configure {
		setup(c, p, &o)
	}
	if err := c.Open(context.Background(), o, root, p.loginMaterial); err != nil {
		t.Fatal(err)
	}
	return c, p, o, root, master, account, org
}

func TestSharedAccountUnlockPersistsAndOwnsKeys(t *testing.T) {
	c, p, o, root, master, account, _ := sharedUnlockFixture(t)
	if c.Unlocked() {
		t.Fatal("transport admission unlocked private keys")
	}
	p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
		stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 2)
		if err != nil || stored.Account.Sequence != 3 || c.Unlocked() {
			t.Error("account state not persisted before material read")
		}
		return account, nil
	}
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != nil {
		t.Fatal(err)
	}
	if !c.Unlocked() || c.privateKeys == nil {
		t.Fatal("private keys not published")
	}
	stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 3)
	if err != nil || stored.WrappingRevision != 2 {
		t.Fatal("wrapper floor not persisted before unlock")
	}
	if err := c.privateKeys.With(func(value []byte) error {
		if !bytes.Equal(value[:32], bytes.Repeat([]byte{33}, 32)) || !bytes.Equal(value[32:], bytes.Repeat([]byte{34}, 32)) {
			t.Error("wrong private pair")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != sharedpg.ErrSessionStarted {
		t.Fatal("repeat unlock accepted")
	}
	owner := c.privateKeys
	p.cancel()
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Unlocked() || c.privateKeys != nil || c.root != nil || c.loginCommitment != ([32]byte{}) {
		t.Fatal("lock retained unlock authority")
	}
	if err := owner.With(func([]byte) error { t.Error("retired private keys accessible"); return nil }); err == nil {
		t.Fatal("retired owner accessible")
	}
}

func TestSharedAccountUnlockFailures(t *testing.T) {
	for _, scenario := range []string{"wrong-master", "bad-preset", "low-preset", "state-error", "state-nil", "state-forged", "revoked", "material-error", "material-nil", "certificate-nil", "ciphertext", "kdf-mismatch", "ask-mismatch", "late-revoked", "disk-conflict", "cleanup-error"} {
		t.Run(scenario, func(t *testing.T) {
			c, p, o, root, master, account, org := sharedUnlockFixture(t)
			preset := vault.KDFV1
			switch scenario {
			case "wrong-master":
				master = make([]byte, 32)
			case "bad-preset":
				preset = "bad"
			case "low-preset":
				preset = vault.KDFLow
			case "state-error":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, sharedpg.ErrQuery }
			case "state-nil":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) { return nil, nil }
			case "state-forged":
				account.State.Signature[0] ^= 1
			case "revoked":
				state := *account.State
				state.Active = false
				state, _ = vault.SignUserKeyState(state, org)
				account.State = &state
			case "material-error":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, sharedpg.ErrQuery }
			case "material-nil":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) { return nil, nil }
			case "certificate-nil":
				account.SigningCertificate = nil
			case "ciphertext":
				account.Envelope.Ciphertext[0] ^= 1
			case "kdf-mismatch":
				account.KDF = vault.KDFV2
			case "ask-mismatch":
				account.ASKRequired = true
			case "late-revoked":
				p.accountMaterial = func(context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
					state := *account.State
					state.Sequence++
					state.Active = false
					state, _ = vault.SignUserKeyState(state, org)
					account.State = &state
					return account, nil
				}
			case "disk-conflict":
				p.accountState = func(context.Context) (*vault.UserKeyState, error) {
					stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
					if e != nil {
						t.Fatal(e)
					}
					next, e := stored.AdvanceAccount(*account.State, 1)
					if e != nil {
						t.Fatal(e)
					}
					if e = writeSharedTrustFile(o.TrustPath, root, o.Binding, next, stored.Revision); e != nil {
						t.Fatal(e)
					}
					return account.State, nil
				}
			case "cleanup-error":
				p.closeFailure.Store(true)
				account.Envelope.Ciphertext[0] ^= 1
			}
			err := c.Unlock(context.Background(), master, preset, false)
			if err == nil || c.Unlocked() || c.Admitted() || c.privateKeys != nil {
				t.Fatalf("failure published private authority: %v", err)
			}
			if scenario == "cleanup-error" && !errors.Is(err, errSharedAdmissionCleanup) {
				t.Fatal("cleanup failure hidden")
			}
			if scenario == "revoked" || scenario == "late-revoked" {
				stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 2)
				if e != nil || stored.Account.Active {
					t.Fatal("revocation discarded on unlock denial")
				}
			}
			if scenario == "ciphertext" {
				stored, e := readSharedTrustFile(o.TrustPath, root, o.Binding, 2)
				if e != nil || stored.WrappingRevision != 1 {
					t.Fatal("unverified wrapping revision persisted")
				}
			}
		})
	}
}

func TestSharedAccountUnlockCancellation(t *testing.T) {
	c, p, _, _, master, _, _ := sharedUnlockFixture(t)
	entered := make(chan struct{})
	p.accountMaterial = func(ctx context.Context) (*sharedpg.UnverifiedAccountKeys, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- c.Unlock(context.Background(), master, vault.KDFV1, false) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("unlock did not reach material read")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled unlock succeeded")
	}
	if c.Unlocked() || c.privateKeys != nil || c.root != nil {
		t.Fatal("cancelled unlock retained secrets")
	}
}

func TestSharedAccountUnlockDurability(t *testing.T) {
	for _, recoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncertain", true: "recovered"}[recoverable], func(t *testing.T) {
			c, _, _, _, master, _, _ := sharedUnlockFixture(t)
			original := privateFileDirectorySync
			t.Cleanup(func() { privateFileDirectorySync = original })
			syncs := 0
			privateFileDirectorySync = func(path string) error {
				syncs++
				if syncs >= 3 && (!recoverable || syncs == 3) {
					return errors.New("synthetic final-floor sync failure")
				}
				return original(path)
			}
			err := c.Unlock(context.Background(), master, vault.KDFV1, false)
			if recoverable {
				if err != nil || !c.Unlocked() || syncs < 4 {
					t.Fatalf("durability recovery failed: %v", err)
				}
			} else if err != errSharedTrustCommitUncertain || c.Unlocked() || c.privateKeys != nil || c.root != nil {
				t.Fatalf("uncertain persistence released keys: %v", err)
			}
		})
	}
}

func TestSharedAccountUnlockPreflight(t *testing.T) {
	c, _, o, root, master, account, _ := sharedUnlockFixture(t)
	if err := c.Unlock(nil, master, vault.KDFV1, false); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	if err := c.Unlock(context.Background(), nil, vault.KDFV1, false); err != sharedpg.ErrConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Unlock(ctx, master, vault.KDFV1, false); err != context.Canceled {
		t.Fatal(err)
	}
	if !c.Admitted() {
		t.Fatal("invalid preflight retired owner")
	}
	stored, err := readSharedTrustFile(o.TrustPath, root, o.Binding, 1)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := stored.AdvanceAccount(*account.State, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSharedTrustFile(o.TrustPath, root, o.Binding, advanced, stored.Revision); err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(context.Background(), master, vault.KDFV1, false); err != errSharedTrustConflict || c.Unlocked() {
		t.Fatal("external trust advance ignored")
	}
}

func TestSharedAccountUnlockRequiresPolicyASK(t *testing.T) {
	for _, used := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[used], func(t *testing.T) {
			c, p, _, _, master, _, _ := sharedUnlockFixtureWithASK(t, true)
			if !used {
				p.accountState = func(context.Context) (*vault.UserKeyState, error) {
					t.Error("missing ASK passed policy preflight")
					return nil, sharedpg.ErrQuery
				}
			}
			err := c.Unlock(context.Background(), master, vault.KDFV1, used)
			if used {
				if err != nil || !c.Unlocked() {
					t.Fatal(err)
				}
			} else if err != vault.ErrPolicy || c.Unlocked() {
				t.Fatal("signed ASK requirement bypassed")
			}
		})
	}
}

func TestSharedAccountUnlockEffectiveProfileKDF(t *testing.T) {
	c, p, _, _, master, _, _ := sharedUnlockFixtureWithPolicy(t, vault.Default, vault.KDFLow, false)
	p.accountState = func(context.Context) (*vault.UserKeyState, error) {
		t.Error("weak KDF passed effective Standard floor")
		return nil, sharedpg.ErrQuery
	}
	if err := c.Unlock(context.Background(), master, vault.KDFLow, false); err != vault.ErrPolicy || c.Unlocked() {
		t.Fatal("OS Standard floor did not prevent kdf-low")
	}
}
