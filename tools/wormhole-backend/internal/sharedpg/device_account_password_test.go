package sharedpg

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestDeviceAccountPasswordPreparation(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	current, err := OpenDeviceAccount(context.Background(), f.target, deviceAccountSelection(t, f.target), []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{'x'}, 1025)} {
		if owner, err := current.PreparePasswordChange(context.Background(), bad, f.ask, vault.Default, vault.Default); err == nil || owner != nil {
			if owner != nil {
				owner.Close()
			}
			t.Fatal("invalid password")
		}
	}
	prepared, err := current.PreparePasswordChange(context.Background(), []byte("next-native-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	var candidate, expectedRoot []byte
	called := false
	err = prepared.BorrowPasswordChange(current, func(old, next *AccountMaster, root *DeviceTrustRoot, key, raw []byte, selection DeviceUnlockSelection) error {
		called = true
		if selection.VaultID != f.slots.VaultID || selection.FileID != f.slots.FileID || selection.MinimumSequence != 2 || !bytes.Equal(key, f.storage) {
			t.Fatal("wrong source selection")
		}
		candidate = bytes.Clone(raw)
		raw[0] ^= 1
		return root.Use(func(value []byte) error {
			expectedRoot = bytes.Clone(value)
			return old.Use(func(oldKey []byte, _ vault.KDFPreset, _ bool) error {
				return next.Use(func(newKey []byte, _ vault.KDFPreset, _ bool) error {
					if bytes.Equal(oldKey, newKey) {
						t.Fatal("password did not change master")
					}
					return nil
				})
			})
		})
	})
	if err != nil || !called {
		t.Fatal(err)
	}
	defer vault.Wipe(expectedRoot)
	if bytes.Equal(expectedRoot, f.next) {
		t.Fatal("root did not change")
	}
	if err := current.BorrowDeviceStorage(func(_ []byte, raw []byte) error {
		if !bytes.Equal(raw, f.target) {
			t.Fatal("source mutated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if owner, err := prepared.PreparePasswordChange(context.Background(), []byte("another"), f.ask, vault.Default, vault.Default); err == nil || owner != nil {
		t.Fatal("nested uncommitted preparation")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDeviceAccount(context.Background(), candidate, deviceAccountSelection(t, candidate), []byte("next-native-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Borrow(func(_ *AccountMaster, root *DeviceTrustRoot) error {
		return root.Use(func(key []byte) error {
			if !bytes.Equal(key, expectedRoot) {
				t.Fatal("candidate uses different factors")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if reopened.BorrowPasswordChange(current, func(*AccountMaster, *AccountMaster, *DeviceTrustRoot, []byte, []byte, DeviceUnlockSelection) error {
		return nil
	}) == nil {
		t.Fatal("reopened file fabricated preparation proof")
	}
}

func TestDeviceAccountPasswordSourceGuards(t *testing.T) {
	f := newDeviceTransitionFixture(t)
	current, err := OpenDeviceAccount(context.Background(), f.target, deviceAccountSelection(t, f.target), []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	prepared, err := current.PreparePasswordChange(context.Background(), []byte("next-native-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	reject := func(*AccountMaster, *AccountMaster, *DeviceTrustRoot, []byte, []byte, DeviceUnlockSelection) error {
		t.Fatal("invalid change borrowed")
		return nil
	}
	if prepared.BorrowPasswordChange(nil, reject) == nil || prepared.BorrowPasswordChange(prepared, reject) == nil || prepared.BorrowPasswordChange(current, nil) == nil {
		t.Fatal("invalid source/callback")
	}
	saved := current.file
	current.file = []byte("different")
	if prepared.BorrowPasswordChange(current, reject) == nil {
		t.Fatal("changed source")
	}
	current.file = saved
	binding := current.root.binding
	current.root.binding.DeviceID = uuid.New()
	if prepared.BorrowPasswordChange(current, reject) == nil {
		t.Fatal("different device")
	}
	current.root.binding = binding
	sentinel := errors.New("native consumer failed")
	if err := prepared.BorrowPasswordChange(current, func(*AccountMaster, *AccountMaster, *DeviceTrustRoot, []byte, []byte, DeviceUnlockSelection) error {
		return sentinel
	}); err != sentinel {
		t.Fatal("callback error lost", err)
	}
	_, journal, err := f.prepare(f.setup)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := OpenDeviceTransitionAccount(context.Background(), journal, deviceAccountSelection(t, f.target), []byte("transition-new-password"), f.ask, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	if owner, err := pending.PreparePasswordChange(context.Background(), []byte("new"), f.ask, vault.Default, vault.Default); err == nil || owner != nil {
		t.Fatal("pending changed again")
	}
	if prepared.BorrowPasswordChange(pending, reject) == nil {
		t.Fatal("pending used as source")
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	if prepared.BorrowPasswordChange(current, reject) == nil {
		t.Fatal("closed source")
	}
	if owner, err := current.PreparePasswordChange(context.Background(), []byte("new"), f.ask, vault.Default, vault.Default); err == nil || owner != nil {
		t.Fatal("closed source prepared")
	}
	var nilOwner *UnlockedDeviceAccount
	if owner, err := nilOwner.PreparePasswordChange(context.Background(), []byte("new"), f.ask, vault.Default, vault.Default); err == nil || owner != nil {
		t.Fatal("nil source")
	}
	if nilOwner.BorrowPasswordChange(current, reject) == nil {
		t.Fatal("nil prepared")
	}
}
