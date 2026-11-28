package sharedpg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func masterDerivationFixture() (AccountDerivation, vault.Policy) {
	d := AccountDerivation{WorkspaceID: uuid.New(), LoginName: "utente@example.test", Preset: vault.KDFLow, EffectiveProfile: vault.Default}
	p := vault.Policy{FormatVersion: 1, WorkspaceID: d.WorkspaceID.String(), Sequence: 1, Profile: vault.Default, KDF: vault.KDFLow, LowKDFApproved: true, OrgEscrow: true, MinAPI: 1, MaxAPI: 1}
	return d, p
}

func TestAccountMasterDerivationAndOwnership(t *testing.T) {
	for _, withASK := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "password-and-ask"}[withASK], func(t *testing.T) {
			d, p := masterDerivationFixture()
			d.ASKRequired = withASK
			p.ASKRequired = withASK
			password := []byte("shared-password-\x00-test")
			var ask []byte
			if withASK {
				ask = bytes.Repeat([]byte{55}, 32)
			}
			owner, err := DeriveAccountMaster(context.Background(), d, p, password, ask)
			if err != nil {
				t.Fatal(err)
			}
			if owner.WorkspaceID() != d.WorkspaceID || owner.LoginName() != d.LoginName {
				t.Fatal("account derivation binding lost")
			}
			t.Cleanup(func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			})
			salt, err := vault.SharedSalt(d.WorkspaceID.String(), d.LoginName)
			if err != nil {
				t.Fatal(err)
			}
			derived, err := vault.DerivePassword(context.Background(), password, salt, d.Preset)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(derived)
			expected, err := vault.MixAccountSecret(derived, ask, withASK)
			if err != nil {
				t.Fatal(err)
			}
			defer vault.Wipe(expected)
			if err := owner.Use(func(master []byte, preset vault.KDFPreset, askUsed bool) error {
				if !bytes.Equal(master, expected) || preset != d.Preset || askUsed != withASK {
					t.Fatal("incorrect derived facts")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			sentinel := errors.New("callback failure")
			if err := owner.Use(func([]byte, vault.KDFPreset, bool) error { return sentinel }); err != sentinel {
				t.Fatal("callback error lost")
			}
			encoded, err := json.Marshal(owner)
			if err != nil || string(encoded) != "{}" {
				t.Fatal("master owner serialized secret material")
			}
			if !bytes.Equal(password, []byte("shared-password-\x00-test")) || (withASK && !bytes.Equal(ask, bytes.Repeat([]byte{55}, 32))) {
				t.Fatal("borrowed factors modified")
			}
			_ = owner.Locked()
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if owner.Locked() {
				t.Fatal("closed owner marked locked")
			}
			if err := owner.Use(func([]byte, vault.KDFPreset, bool) error { t.Fatal("closed master exposed"); return nil }); err != securemem.ErrClosed {
				t.Fatal(err)
			}
		})
	}
	var absent *AccountMaster
	if absent.WorkspaceID() != uuid.Nil || absent.LoginName() != "" {
		t.Fatal("nil workspace binding")
	}
	if absent.Locked() || absent.Close() != nil || absent.Use(nil) != securemem.ErrClosed {
		t.Fatal("nil owner")
	}
	empty := &AccountMaster{}
	if empty.Locked() || empty.Close() != nil || empty.Use(nil) != securemem.ErrClosed {
		t.Fatal("empty owner")
	}
}

type masterMemoryProbe struct {
	data               []byte
	retired, failClose bool
	useError           error
	afterUse           func()
}

func (m *masterMemoryProbe) With(use func([]byte) error) error {
	if m.retired {
		return securemem.ErrClosed
	}
	if m.useError != nil {
		return m.useError
	}
	err := use(m.data)
	if m.afterUse != nil {
		m.afterUse()
	}
	return err
}
func (m *masterMemoryProbe) Close() error {
	m.retired = true
	clear(m.data)
	if m.failClose {
		return securemem.ErrUnavailable
	}
	return nil
}
func (m *masterMemoryProbe) Locked() bool { return !m.retired }

func TestAccountMasterCleanupAndCancellation(t *testing.T) {
	for _, mode := range []string{"allocate", "cancel-after-allocation", "cleanup", "copy", "cancel-after-copy"} {
		t.Run(mode, func(t *testing.T) {
			d, p := masterDerivationFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			memory := &masterMemoryProbe{data: make([]byte, 32)}
			allocated := 0
			allocate := func(required bool) (accountMasterMemory, error) {
				allocated++
				if required {
					t.Fatal("Default unexpectedly requires locked pages")
				}
				if mode == "allocate" {
					return nil, securemem.ErrUnavailable
				}
				if mode == "cancel-after-allocation" || mode == "cleanup" {
					cancel()
				}
				if mode == "cleanup" {
					memory.failClose = true
				}
				if mode == "copy" {
					memory.useError = securemem.ErrUnavailable
				}
				if mode == "cancel-after-copy" {
					memory.afterUse = cancel
				}
				return memory, nil
			}
			owner, err := deriveAccountMaster(ctx, d, p, []byte("test-password"), nil, allocate)
			if err == nil || allocated != 1 {
				t.Fatal("failure not surfaced")
			}
			if !bytes.Equal(memory.data, make([]byte, 32)) {
				t.Fatal("failed derivation retained plaintext")
			}
			if mode == "cleanup" {
				if owner == nil || !errors.Is(err, ErrAccountMasterCleanup) || !errors.Is(err, context.Canceled) {
					t.Fatal("cleanup ownership lost", err)
				}
				if err := owner.Use(func([]byte, vault.KDFPreset, bool) error { t.Fatal("retired master exposed"); return nil }); err != securemem.ErrClosed {
					t.Fatal(err)
				}
				memory.failClose = false
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			} else if owner != nil {
				t.Fatal("failed derivation published owner")
			}
		})
	}
}

func TestAccountMasterRejectsBeforeDerivation(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "empty-password", "long-password", "workspace", "missing-workspace", "policy", "weaker-profile", "unknown-profile", "bad-kdf", "kdf-floor", "missing-ask", "unexpected-ask", "policy-ask", "login-case", "login-nfc", "admin-ask", "custodian-ask"} {
		t.Run(mode, func(t *testing.T) {
			d, p := masterDerivationFixture()
			ctx := context.Background()
			password := []byte("test-password")
			var ask []byte
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "empty-password":
				password = nil
			case "long-password":
				password = make([]byte, 1025)
			case "workspace":
				p.WorkspaceID = uuid.New().String()
			case "missing-workspace":
				d.WorkspaceID = uuid.Nil
			case "policy":
				p.Sequence = 0
			case "weaker-profile":
				p.Profile = vault.Standard
				p.KDF = vault.KDFV1
				d.Preset = vault.KDFV1
			case "unknown-profile":
				d.EffectiveProfile = "unknown"
			case "bad-kdf":
				d.Preset = "unknown"
			case "kdf-floor":
				p.KDF = vault.KDFV1
			case "missing-ask":
				d.ASKRequired = true
			case "unexpected-ask":
				ask = make([]byte, 32)
			case "policy-ask":
				p.ASKRequired = true
			case "login-case":
				d.LoginName = "Utente@example.test"
			case "login-nfc":
				d.LoginName = "e\u0301@example.test"
			case "admin-ask", "custodian-ask":
				p.Profile = vault.Hardened
				p.KDF = vault.KDFV2
				d.EffectiveProfile = vault.Hardened
				d.Preset = vault.KDFV2
				d.Administrator = mode == "admin-ask"
				d.Custodian = mode == "custodian-ask"
			}
			owner, err := deriveAccountMaster(ctx, d, p, password, ask, func(bool) (accountMasterMemory, error) {
				t.Fatal("invalid input reached allocator/KDF")
				return nil, nil
			})
			if err == nil || owner != nil {
				t.Fatal("invalid derivation accepted")
			}
		})
	}
}

func TestAccountMasterRequiresLockedMemoryForStrongProfiles(t *testing.T) {
	for _, profile := range []vault.Profile{vault.Hardened, vault.Paranoid} {
		t.Run(string(profile), func(t *testing.T) {
			d, p := masterDerivationFixture()
			d.EffectiveProfile = profile
			p.Profile = profile
			d.Preset = vault.KDFV2
			if profile == vault.Paranoid {
				d.Preset = vault.KDFV3
			}
			p.KDF = d.Preset
			d.ASKRequired = true
			p.ASKRequired = true
			d.Administrator = true
			owner, err := deriveAccountMaster(context.Background(), d, p, []byte("test-password"), make([]byte, 32), func(required bool) (accountMasterMemory, error) {
				if !required {
					t.Fatal("strong profile allowed unlocked master")
				}
				return nil, securemem.ErrUnavailable
			})
			if err != securemem.ErrUnavailable || owner != nil {
				t.Fatal("unavailable locked pages accepted", err)
			}
		})
	}
}
