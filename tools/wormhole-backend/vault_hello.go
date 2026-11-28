package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/ospolicy"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

var (
	errVaultHelloUnavailable = errors.New("vault_hello_unavailable")
	errVaultHelloRemote      = errors.New("vault_hello_remote_desktop")
	errVaultHelloCanceled    = errors.New("vault_hello_canceled")
)

type platformHelloOperation func(context.Context, string, uintptr, bool, func(vault.HelloCredential) error) error

func (h *vaultFoundationHandler) usePlatformHello(ctx context.Context, vaultID, slotID string, hwnd uintptr, create bool, use func(vault.HelloCredential) error) error {
	platform := h.helloOperation
	if platform == nil {
		platform = withPlatformVaultHello
	}
	return platform(ctx, vaultHelloKeyName(vaultID, slotID), hwnd, create, use)
}

func vaultHelloKeyName(vaultID, slotID string) string {
	return "WormholeVault-" + vaultID + "-" + slotID
}

// Publish only these actionable dispositions. Storage, policy and unexpected
// native errors retain the transport's generic failure response.
func helloReply(result json.RawMessage, err error) (json.RawMessage, error) {
	switch {
	case errors.Is(err, errVaultHelloRemote):
		return json.RawMessage(`{"status":"remote-desktop"}`), nil
	case errors.Is(err, errVaultHelloCanceled):
		return json.RawMessage(`{"status":"canceled"}`), nil
	case errors.Is(err, errVaultHelloUnavailable):
		return json.RawMessage(`{"status":"unavailable"}`), nil
	case errors.Is(err, vault.ErrHelloNondeterministic):
		return json.RawMessage(`{"status":"not-repeatable"}`), nil
	default:
		return result, err
	}
}

func vaultHelloAvailability(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if len(raw) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	err := platformVaultHelloAvailable(ctx)
	switch {
	case err == nil:
		return json.RawMessage(`{"status":"ready"}`), nil
	case errors.Is(err, errVaultHelloRemote):
		return json.RawMessage(`{"status":"remote-desktop"}`), nil
	case errors.Is(err, errVaultHelloUnavailable):
		return json.RawMessage(`{"status":"unavailable"}`), nil
	default:
		return nil, err
	}
}

type vaultHelloRequest struct {
	vaultID, slotID, ownerWindow string
}

func decodeVaultHello(raw []byte, enroll bool) (request vaultHelloRequest, hwnd uintptr, err error) {
	if len(raw) > 512 {
		return request, 0, vaultwire.ErrProtocol
	}
	fields := map[string]any{"ownerWindow": &request.ownerWindow}
	required := []string{"ownerWindow"}
	if !enroll {
		fields["vaultId"], fields["slotId"] = &request.vaultID, &request.slotID
		required = append(required, "vaultId", "slotId")
	}
	if decodeVaultObject(raw, fields, required...) != nil {
		return request, 0, vaultwire.ErrProtocol
	}
	value, err := strconv.ParseUint(request.ownerWindow, 10, strconv.IntSize)
	if value == 0 || err != nil || request.ownerWindow != strconv.FormatUint(value, 10) {
		return request, 0, vaultwire.ErrProtocol
	}
	if !enroll {
		for _, id := range []string{request.vaultID, request.slotID} {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil || parsed.String() != id {
				return request, 0, vaultwire.ErrProtocol
			}
		}
	}
	return request, uintptr(value), nil
}

func (h *vaultFoundationHandler) openWithHello(ctx context.Context, raw []byte) (json.RawMessage, error) {
	request, hwnd, err := decodeVaultHello(raw, false)
	if err != nil {
		return nil, err
	}
	return h.openWithPlatformSlot(ctx, request.vaultID, request.slotID, vault.SlotHello, func(document vault.SlotFile, slot vault.Slot) ([]byte, error) {
		var key []byte
		err := h.usePlatformHello(ctx, document.VaultID, slot.ID, hwnd, false, func(credential vault.HelloCredential) error {
			var err error
			key, err = vault.OpenHelloSlot(ctx, document.VaultID, document.FileID, slot, credential)
			return err
		})
		return key, err
	})
}

func (h *vaultFoundationHandler) openWithPlatformSlot(ctx context.Context, vaultID, slotID string, kind vault.SlotKind, unwrap func(vault.SlotFile, vault.Slot) ([]byte, error)) (json.RawMessage, error) {
	if err := h.validateVaultOpening(); err != nil {
		return nil, err
	}
	release, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	defer h.keepVaultOpeningLease(release)
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, err
	}
	if document.VaultID != vaultID || document.Initializing || document.Migration != nil || document.Rotation != nil {
		return nil, vault.ErrPolicy
	}
	if floor, err := ospolicy.ReadFloor(ctx); err != nil || (floor != vault.Default && floor != vault.Standard) {
		return nil, vault.ErrPolicy
	}
	for _, slot := range document.Slots {
		if slot.ID != slotID || slot.Kind != kind {
			continue
		}
		key, err := unwrap(document, slot)
		defer vault.Wipe(key)
		if err != nil {
			return nil, err
		}
		owner, err := openVaultFiles(ctx, h.databasePath, document, key)
		if err != nil {
			return nil, h.retire(err)
		}
		policy, err := owner.ReadLocalPolicy(ctx)
		if err != nil || policy.Policy.ASKRequired {
			_ = owner.Close()
			return nil, h.retire(errors.Join(err, vault.ErrPolicy))
		}
		h.owner = owner
		return marshalLocalVaultUnlock(owner)
	}
	return nil, vault.ErrAuthentication
}

func (h *vaultFoundationHandler) enrollVaultHello(ctx context.Context, raw []byte, fresh bool) (json.RawMessage, error) {
	if !fresh || h.owner == nil || h.enrollment != nil {
		return nil, vault.ErrPolicy
	}
	_, hwnd, err := decodeVaultHello(raw, true)
	if err != nil {
		return nil, err
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, h.retire(err)
	}
	for _, slot := range document.Slots {
		if slot.Kind == vault.SlotHello || slot.Kind == vault.SlotUnprotected {
			return nil, vault.ErrPolicy
		}
	}
	policy, err := h.owner.ReadLocalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if policy.Policy.ASKRequired {
		return nil, vault.ErrPolicy
	}
	id := uuid.NewString()
	err = h.usePlatformHello(ctx, document.VaultID, id, hwnd, true, func(credential vault.HelloCredential) error {
		return h.owner.EnrollHelloSlot(ctx, document, id, credential, func(next vault.SlotFile, root []byte) error {
			return writeVaultSlotFile(h.databasePath, root, next, document.Sequence)
		})
	})
	if err != nil {
		if errors.Is(err, errVaultSlotCommitUncertain) || errors.Is(err, vault.ErrRollback) || errors.Is(err, errVaultSlotConflict) {
			return nil, h.retire(err)
		}
		return nil, err
	}
	return json.RawMessage(`{"enrolled":true}`), nil
}

func (h *vaultFoundationHandler) removeVaultHello(ctx context.Context, raw []byte, fresh bool) (json.RawMessage, error) {
	remove := h.helloRemove
	if remove == nil {
		remove = platformRemoveVaultHello
	}
	return h.removeVaultPlatformSlot(ctx, raw, fresh, vault.SlotHello, func(ctx context.Context, vaultID, slotID string) bool {
		return remove(ctx, vaultHelloKeyName(vaultID, slotID))
	})
}

func (h *vaultFoundationHandler) removeVaultPlatformSlot(ctx context.Context, raw []byte, fresh bool, kind vault.SlotKind, remove func(context.Context, string, string) bool) (json.RawMessage, error) {
	if !fresh || h.owner == nil || h.enrollment != nil {
		return nil, vault.ErrPolicy
	}
	var slotID string
	if len(raw) > 128 || decodeVaultObject(raw, map[string]any{"slotId": &slotID}, "slotId") != nil {
		return nil, vaultwire.ErrProtocol
	}
	id, err := uuid.Parse(slotID)
	if err != nil || id == uuid.Nil || id.String() != slotID {
		return nil, vaultwire.ErrProtocol
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, h.retire(err)
	}
	keyDeleted, err := h.owner.RemovePlatformSlot(ctx, document, slotID, kind, func(ctx context.Context) bool {
		return remove(ctx, document.VaultID, slotID)
	}, func(next vault.SlotFile, root []byte) error {
		return writeVaultSlotFile(h.databasePath, root, next, document.Sequence)
	})
	if err != nil {
		if errors.Is(err, errVaultSlotCommitUncertain) || errors.Is(err, vault.ErrRollback) || errors.Is(err, errVaultSlotConflict) {
			return nil, h.retire(err)
		}
		return nil, err
	}
	return json.Marshal(struct {
		Removed    bool `json:"removed"`
		KeyDeleted bool `json:"keyDeleted"`
	}{true, keyDeleted})
}
