package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
)

func TestSharedDeviceAccountPassword(t *testing.T) {
	j, f, p, _ := preparedDeviceJoinFixture(t)
	if _, err := j.joinPrepared(context.Background(), f.o, p); err != nil {
		t.Fatal(err)
	}
	path := sharedDeviceEnrollmentPath(f.o.TrustPath)
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The existing fixture starts with a recovery slot. Install a real password
	// slot matching its real account derivation before exercising the owner flow.
	source, err = sharedpg.PrepareDevicePasswordFile(context.Background(), p.key, source, p.slots.VaultID, p.slots.FileID, 1, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedTransitionBytes(path, source); err != nil {
		t.Fatal(err)
	}
	slots, _, err := sharedpg.DecodeDeviceEnrollmentFile(source)
	if err != nil {
		t.Fatal(err)
	}
	selection := sharedpg.DeviceUnlockSelection{VaultID: slots.VaultID, FileID: slots.FileID, MinimumSequence: slots.Sequence}
	for _, slot := range slots.Slots {
		if slot.Kind == vault.SlotPassword {
			selection.SlotID = slot.ID
		}
	}
	current, err := sharedpg.OpenDeviceAccount(context.Background(), source, selection, []byte("recovery-test-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	prepared, err := current.PreparePasswordChange(context.Background(), []byte("actual-new-password"), nil, vault.Default, vault.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	ctx, cancel := context.WithCancel(context.Background())
	probe := &sharedAdmissionProbe{ctx: ctx, cancel: cancel, response: f.probe.response, loginMaterial: f.probe.loginMaterial, accountState: f.probe.accountState, enrollmentMaterial: f.probe.enrollmentMaterial}
	c := newSharedAdmissionControllerWithSession(probe)
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	err = current.Borrow(func(master *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error { return c.OpenAccountFromSetup(context.Background(), f.o, key, master) })
	})
	if err != nil {
		t.Fatal("native account reopen", err)
	}
	var nextRoot []byte
	err = prepared.Borrow(func(_ *sharedpg.AccountMaster, root *sharedpg.DeviceTrustRoot) error {
		return root.Use(func(key []byte) error { nextRoot = bytes.Clone(key); return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(nextRoot)
	calls := 0
	probe.changePassword = func(context.Context, *sharedpg.PreparedPasswordChange, string) (*sharedpg.PasswordChangeReceipt, error) {
		calls++
		record, err := readSharedTrustRootTransition(f.o.TrustPath, nextRoot, f.o.Binding)
		if err != nil || record.Device == nil {
			t.Fatal("new factors cannot open journal", err)
		}
		return &sharedpg.PasswordChangeReceipt{WrappingRevision: record.Next.WrappingRevision, AuthEpoch: 2}, nil
	}
	if _, err := c.ChangeDeviceAccountPassword(nil, current, prepared, "ui"); err == nil {
		t.Fatal("nil context")
	}
	if _, err := c.ChangeDeviceAccountPassword(context.Background(), current, nil, "ui"); err == nil {
		t.Fatal("nil preparation")
	}
	receipt, err := c.ChangeDeviceAccountPassword(context.Background(), current, prepared, "ui")
	if err != nil || receipt == nil || calls != 1 {
		t.Fatal("owned change", receipt, err, calls)
	}
	if _, err := readActiveSharedTrustFile(f.o.TrustPath, nextRoot, f.o.Binding, 1); err != nil {
		t.Fatal("new root inactive", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = prepared.BorrowDeviceStorage(func(_ []byte, raw []byte) error {
		if !bytes.Equal(raw, actual) {
			t.Fatal("different candidate published")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
