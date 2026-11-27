package sharedpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/securemem"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestDeviceTrustRootKnownAnswer(t *testing.T) {
	b := TrustBinding{
		WorkspaceID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		UserID:      uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		DeviceID:    uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		KeyID:       uuid.MustParse("44444444-4444-4444-4444-444444444444"), KeyVersion: 0x01020304,
	}
	m := &AccountMaster{workspaceID: b.WorkspaceID, memory: &masterMemoryProbe{data: bytes.Repeat([]byte{3}, 32)}}
	defer m.Close()
	r, err := m.DeriveTrustRoot(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Independently calculated RFC5869 extract/expand with Python hmac/SHA256:
	// salt = four UUID byte arrays || uint32 big endian; IKM = 32 bytes 0x03;
	// info = wormhole/v1/shared-device-root; one 32-byte expansion block.
	want, err := hex.DecodeString("1e3fb202f8d6d96201b83d6db5c0873ac349436d05360fbc6e34a520e05d888a")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Use(func(key []byte) error {
		if !bytes.Equal(key, want) {
			t.Fatal("device root format changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceTrustRootRecoveryAndIsolation(t *testing.T) {
	d, policy := masterDerivationFixture()
	_, b, state, _, _, organisation := trustFixture(t)
	defer vault.Wipe(organisation)
	d.WorkspaceID = b.WorkspaceID
	policy.WorkspaceID = b.WorkspaceID.String()
	var reference []byte
	var protected []byte
	defer func() { vault.Wipe(reference) }()
	for _, mode := range []string{"initial", "same", "password", "ask", "user", "device", "key", "version"} {
		t.Run(mode, func(t *testing.T) {
			binding, derivation := b, d
			password := []byte("native password")
			var ask []byte
			switch mode {
			case "password":
				password = []byte("changed password")
			case "ask":
				ask = bytes.Repeat([]byte{24}, 32)
				derivation.ASKRequired = true
			case "user":
				binding.UserID = uuid.New()
			case "device":
				binding.DeviceID = uuid.New()
			case "key":
				binding.KeyID = uuid.New()
			case "version":
				binding.KeyVersion++
			}
			master, err := DeriveAccountMaster(context.Background(), derivation, policy, password, ask)
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			root, err := master.DeriveTrustRoot(context.Background(), binding)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if root.Binding() != binding {
				t.Fatal("binding lost")
			}
			if err := root.Use(func(key []byte) error {
				// This would deadlock if derivation retained the master lock.
				return master.Use(func(value []byte, _ vault.KDFPreset, _ bool) error {
					login, err := vault.DeriveKey(value, nil, vault.PurposeLogin)
					defer vault.Wipe(login)
					if bytes.Equal(value, key) || bytes.Equal(login, key) {
						t.Error("domain not separated")
					}
					return err
				})
			}); err != nil {
				t.Fatal(err)
			}
			if err := master.Close(); err != nil {
				t.Fatal(err)
			}
			if err := root.Use(func(key []byte) error {
				if mode == "initial" {
					reference = bytes.Clone(key)
					var err error
					protected, err = SealTrustState(key, b, state)
					return err
				} else if bytes.Equal(key, reference) != (mode == "same") {
					t.Error("root derivation isolation/recovery failed")
				}
				_, err := OpenTrustState(key, b, protected, state.Revision)
				if (err == nil) != (mode == "same") {
					t.Error("protected trust recovery/isolation", err)
				}
				return nil
			}); err != nil {
				t.Fatal("master closure invalidated root", err)
			}
			raw, err := json.Marshal(root)
			if err != nil || string(raw) != "{}" {
				t.Fatal("root serialized")
			}
			_ = root.Locked()
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			if root.Locked() || root.Use(func([]byte) error { t.Fatal("closed root exposed"); return nil }) != securemem.ErrClosed {
				t.Fatal("root stayed live")
			}
		})
	}
}

func TestDeviceTrustRootFailureOwnership(t *testing.T) {
	for _, mode := range []string{"nil-context", "nil-master", "empty-master", "foreign", "invalid-binding", "canceled", "closed-master", "allocate", "copy", "cleanup", "cancel-after-copy", "required-pages"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := TrustBinding{WorkspaceID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(), KeyID: uuid.New(), KeyVersion: 1}
			masterMemory := &masterMemoryProbe{data: bytes.Repeat([]byte{3}, 32)}
			m := &AccountMaster{workspaceID: b.WorkspaceID, memory: masterMemory}
			memory := &masterMemoryProbe{data: make([]byte, 32)}
			switch mode {
			case "nil-context":
				ctx = nil
			case "nil-master":
				m = nil
			case "empty-master":
				m.memory = nil
			case "foreign":
				b.WorkspaceID = uuid.New()
			case "invalid-binding":
				b.KeyVersion = 0
			case "canceled":
				cancel()
			case "closed-master":
				_ = m.Close()
			case "copy", "cleanup":
				memory.useError = securemem.ErrUnavailable
				memory.failClose = mode == "cleanup"
			case "cancel-after-copy":
				memory.afterUse = cancel
			case "required-pages":
				m.requireLocked = true
			}
			allocated := 0
			root, err := m.deriveTrustRoot(ctx, b, func(required bool) (accountMasterMemory, error) {
				allocated++
				if required != (mode == "required-pages") {
					t.Fatal("memory policy lost")
				}
				if mode == "allocate" || mode == "required-pages" {
					return nil, securemem.ErrUnavailable
				}
				return memory, nil
			})
			if err == nil {
				t.Fatal("failure accepted")
			}
			if allocated != 0 && mode != "allocate" && mode != "required-pages" && mode != "copy" && mode != "cleanup" && mode != "cancel-after-copy" {
				t.Fatal("invalid input allocated")
			}
			if !bytes.Equal(memory.data, make([]byte, 32)) {
				t.Fatal("failed root retained secret")
			}
			if mode == "cleanup" {
				if root == nil || !errors.Is(err, ErrDeviceTrustRootCleanup) || !errors.Is(err, securemem.ErrUnavailable) {
					t.Fatal("cleanup owner/error lost", err)
				}
				if root.Use(func([]byte) error { t.Fatal("failed root exposed"); return nil }) != securemem.ErrClosed {
					t.Fatal("not retired")
				}
				memory.failClose = false
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			} else if root != nil {
				t.Fatal("failed root published")
			}
		})
	}
	for _, r := range []*DeviceTrustRoot{nil, {}} {
		if r.Close() != nil || r.Locked() || r.Use(nil) != securemem.ErrClosed || r.Binding() != (TrustBinding{}) {
			t.Fatal("empty owner")
		}
	}
}
