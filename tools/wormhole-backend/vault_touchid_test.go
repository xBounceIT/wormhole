package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultTouchIDNativeActionsRequireAuthenticationAndKeepRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspace.db")
	password, recovery, factor := []byte("fixture-vault-password"), bytes.Repeat([]byte{71}, 32), bytes.Repeat([]byte{0x54}, 32)
	h := &vaultFoundationHandler{databasePath: path}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := h.Handle(ctx, "initialize", vaultInput(t, map[string]any{"password": password, "recoveryKey": recovery})); err != nil {
		t.Fatal(err)
	}
	document, err := readVaultSlotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var enrolled string
	var calls []touchIDOperation
	var short, cancel bool
	var borrowed []byte
	provider := func(_ context.Context, operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
		calls = append(calls, operation)
		if operation == touchIDProbe {
			if vaultID != "" || slotID != "" {
				t.Fatal("capability probe received slot coordinates")
			}
			return nil, nil
		}
		if vaultID != document.VaultID || !validTouchIDCoordinate(slotID) || (operation != touchIDEnroll && slotID != enrolled) {
			t.Fatal("provider received a slot belonging to another operation or workspace")
		}
		if operation == touchIDRemove {
			enrolled = ""
			return nil, nil
		}
		if cancel {
			return nil, errTouchIDCanceled
		}
		if operation == touchIDEnroll {
			if enrolled != "" {
				t.Fatal("attempted to replace the existing device factor")
			}
			enrolled = slotID
		}
		borrowed = bytes.Clone(factor)
		if short {
			borrowed = borrowed[:31]
		}
		return borrowed, nil
	}
	h.touchID = provider
	helperReply := func(operation string, input []byte, expected string) {
		t.Helper()
		if result, err := h.Handle(ctx, operation, input); err != nil || string(result) != expected {
			t.Fatalf("%s response: %s %v", operation, result, err)
		}
	}
	helperReply("touch-id-availability", nil, `{"status":"ready"}`)
	if _, err := h.Handle(ctx, "touch-id-availability", []byte(`{}`)); !errors.Is(err, vaultwire.ErrProtocol) || len(calls) != 1 {
		t.Fatal("capability accepted an unexpected payload", err)
	}
	fresh := func(operation string, action []byte, auth []byte) json.RawMessage {
		return vaultInput(t, map[string]any{"operation": operation, "action": action,
			"authentication": []byte(vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[0].ID, "password": auth}))})
	}
	if _, err := h.Handle(ctx, "touch-id-enroll", []byte(`{}`)); !errors.Is(err, vault.ErrPolicy) || len(calls) != 1 {
		t.Fatal("enrollment bypassed fresh authorization", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", fresh("touch-id-enroll", []byte(`{}`), []byte("wrong"))); !errors.Is(err, vault.ErrAuthentication) || len(calls) != 1 {
		t.Fatal("incorrect password reached the helper", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", fresh("touch-id-enroll", []byte(`{"factor":true}`), password)); !errors.Is(err, vaultwire.ErrProtocol) || len(calls) != 1 {
		t.Fatal("the renderer could substitute a Keychain factor", err)
	}
	enroll := fresh("touch-id-enroll", []byte(`{}`), password)
	short = true
	if _, err := h.Handle(ctx, "fresh-action", enroll); !errors.Is(err, vault.ErrFormat) || enrolled != "" || calls[len(calls)-1] != touchIDRemove || !bytes.Equal(borrowed, make([]byte, 31)) {
		t.Fatal("the helper retained a factor rejected before publishing a slot", err)
	}
	short = false
	helperReply("fresh-action", fresh("touch-id-enroll", []byte(`{}`), password), `{"enrolled":true}`)
	if !bytes.Equal(borrowed, make([]byte, 32)) {
		t.Fatal("the native factor was retained by the owner")
	}
	withTouchID, err := readVaultSlotFile(path)
	if err != nil || withTouchID.FormatVersion != vault.SlotFileTouchIDVersion || withTouchID.Sequence != document.Sequence+1 || len(withTouchID.Slots) != 3 || withTouchID.Slots[2].ID != enrolled {
		t.Fatal("an optional v6 slot was not published atomically", err)
	}
	if _, err := h.Handle(ctx, "fresh-action", fresh("touch-id-enroll", []byte(`{}`), password)); !errors.Is(err, vault.ErrPolicy) {
		t.Fatal("enrollment replaced the committed item", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path, touchID: provider}
	request := func(slot string) []byte {
		return vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": slot})
	}
	if _, err := h.Handle(ctx, "touch-id-unlock", request(document.Slots[0].ID)); !errors.Is(err, vault.ErrAuthentication) || h.owner != nil {
		t.Fatal("Touch ID selected a software slot", err)
	}
	if _, err := h.Handle(ctx, "touch-id-unlock", []byte(`{"vaultId":"wrong","slotId":"wrong"}`)); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("Touch ID accepted invalid coordinates", err)
	}
	cancel = true
	helperReply("touch-id-unlock", request(enrolled), `{"status":"canceled"}`)
	if h.owner != nil {
		t.Fatal("canceling the prompt opened the vault")
	}
	cancel = false
	helperReply("touch-id-unlock", request(enrolled), `{"unlocked":true,"lockedMemory":true}`)
	if h.owner == nil || !bytes.Equal(borrowed, make([]byte, 32)) {
		t.Fatal("native unlock did not wipe its device factor")
	}
	slotID := enrolled
	remove := vaultInput(t, map[string]any{"slotId": slotID})
	helperReply("fresh-action", fresh("touch-id-remove", remove, password), `{"removed":true,"keyDeleted":true}`)
	withoutTouchID, err := readVaultSlotFile(path)
	if err != nil || len(withoutTouchID.Slots) != 2 || withoutTouchID.FormatVersion != vault.SlotFileTouchIDVersion || enrolled != "" {
		t.Fatal("Touch ID removal did not withdraw exactly its slot", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	h = &vaultFoundationHandler{databasePath: path, touchID: provider}
	if _, err := h.Handle(ctx, "touch-id-unlock", request(slotID)); !errors.Is(err, vault.ErrAuthentication) || h.owner != nil {
		t.Fatal("a withdrawn factor could reopen the vault", err)
	}
	helperReply("unlock", vaultInput(t, map[string]any{"vaultId": document.VaultID, "slotId": document.Slots[1].ID, "recoveryKey": recovery}), `{"unlocked":true,"lockedMemory":true}`)
}

func TestVaultTouchIDHelperWire(t *testing.T) {
	vaultID, slotID := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	if probe, err := encodeTouchIDRequest(touchIDProbe, "", ""); err != nil || !bytes.Equal(probe, []byte{1, 1}) {
		t.Fatal("invalid capability request", err)
	}
	if _, err := encodeTouchIDRequest(touchIDProbe, vaultID, slotID); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("capability included identifiers", err)
	}
	if _, err := encodeTouchIDRequest(touchIDOpen, "", slotID); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("accepted a missing vault", err)
	}
	if _, err := encodeTouchIDRequest(5, vaultID, slotID); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("recognized an unknown operation", err)
	}
	if wire, err := encodeTouchIDRequest(touchIDOpen, vaultID, slotID); err != nil || !bytes.Equal(wire, append([]byte{1, 3}, (vaultID+slotID)...)) {
		t.Fatal("invalid open frame", err)
	}
	for _, row := range []struct {
		operation touchIDOperation
		frame     []byte
		wantErr   error
	}{
		{touchIDProbe, []byte{1, 0}, nil}, {touchIDRemove, []byte{1, 0}, nil},
		{touchIDOpen, []byte{1, 0}, vaultwire.ErrProtocol}, {touchIDOpen, []byte{1, 1}, errTouchIDUnavailable},
		{touchIDOpen, []byte{1, 2}, errTouchIDCanceled}, {touchIDOpen, []byte{1, 2, 99}, vaultwire.ErrProtocol},
		{touchIDOpen, []byte{1, 9}, vaultwire.ErrProtocol}, {touchIDOpen, nil, vaultwire.ErrProtocol},
		{touchIDOpen, []byte{2, 1}, vaultwire.ErrProtocol}, {touchIDProbe, make([]byte, maxTouchIDReply), vaultwire.ErrProtocol},
	} {
		if data, err := decodeTouchIDReply(row.operation, row.frame); data != nil || !errors.Is(err, row.wantErr) {
			t.Fatalf("unexpected result %v for %x", err, row.frame)
		}
	}
	frame := append([]byte{1, 0}, bytes.Repeat([]byte{9}, 32)...)
	data, err := decodeTouchIDReply(touchIDEnroll, frame)
	if err != nil || !bytes.Equal(data, frame[2:]) {
		t.Fatal("valid device factor missing", err)
	}
	vault.Wipe(frame)
	defer vault.Wipe(data)
	if bytes.Equal(data, frame[2:]) {
		t.Fatal("borrowed an output buffer instead of taking ownership")
	}
}
