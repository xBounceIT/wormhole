package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type touchIDOperation byte

const (
	touchIDProbe touchIDOperation = iota + 1
	touchIDEnroll
	touchIDOpen
	touchIDRemove
)

var (
	errTouchIDUnavailable = errors.New("vault_touch_id_unavailable")
	errTouchIDCanceled    = errors.New("vault_touch_id_canceled")
)

type touchIDProvider func(context.Context, touchIDOperation, string, string) ([]byte, error)

func (h *vaultFoundationHandler) useTouchID(ctx context.Context, operation touchIDOperation, vaultID, slotID string) ([]byte, error) {
	provider := h.touchID
	if provider == nil {
		provider = platformVaultTouchID
	}
	return provider(ctx, operation, vaultID, slotID)
}

func touchIDReply(result json.RawMessage, err error) (json.RawMessage, error) {
	switch {
	case errors.Is(err, errTouchIDUnavailable):
		return json.RawMessage(`{"status":"unavailable"}`), nil
	case errors.Is(err, errTouchIDCanceled):
		return json.RawMessage(`{"status":"canceled"}`), nil
	default:
		return result, err
	}
}

func (h *vaultFoundationHandler) vaultTouchIDAvailability(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if len(raw) != 0 || h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	policy, err := h.owner.ReadLocalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if policy.Policy.ASKRequired {
		return nil, errTouchIDUnavailable
	}
	data, err := h.useTouchID(ctx, touchIDProbe, "", "")
	vault.Wipe(data)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(`{"status":"ready"}`), nil
}

func validTouchIDCoordinate(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func (h *vaultFoundationHandler) openWithTouchID(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var vaultID, slotID string
	if len(raw) > 128 || decodeVaultObject(raw, map[string]any{"vaultId": &vaultID, "slotId": &slotID}, "vaultId", "slotId") != nil ||
		!validTouchIDCoordinate(vaultID) || !validTouchIDCoordinate(slotID) {
		return nil, vaultwire.ErrProtocol
	}
	return h.openWithPlatformSlot(ctx, vaultID, slotID, vault.SlotTouchID, func(document vault.SlotFile, slot vault.Slot) ([]byte, error) {
		factor, err := h.useTouchID(ctx, touchIDOpen, vaultID, slotID)
		defer vault.Wipe(factor)
		if err != nil {
			return nil, err
		}
		return vault.OpenTouchIDSlot(vaultID, document.FileID, slot, factor)
	})
}

func (h *vaultFoundationHandler) enrollVaultTouchID(ctx context.Context, raw []byte, fresh bool) (json.RawMessage, error) {
	if !fresh || h.owner == nil || h.enrollment != nil {
		return nil, vault.ErrPolicy
	}
	if string(raw) != "{}" {
		return nil, vaultwire.ErrProtocol
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, h.retire(err)
	}
	slotID := uuid.NewString()
	provisioned := false
	err = h.owner.EnrollTouchIDSlot(ctx, document, slotID, func(ctx context.Context) ([]byte, error) {
		data, err := h.useTouchID(ctx, touchIDEnroll, document.VaultID, slotID)
		provisioned = err == nil
		return data, err
	}, func(next vault.SlotFile, root []byte) error {
		return writeVaultSlotFile(h.databasePath, root, next, document.Sequence)
	})
	if err == nil {
		return json.RawMessage(`{"enrolled":true}`), nil
	}
	if provisioned && !errors.Is(err, errVaultSlotCommitUncertain) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		h.deleteVaultTouchID(cleanup, document.VaultID, slotID)
	}
	if errors.Is(err, errVaultSlotCommitUncertain) || errors.Is(err, vault.ErrRollback) || errors.Is(err, errVaultSlotConflict) {
		return nil, h.retire(err)
	}
	return nil, err
}

func (h *vaultFoundationHandler) deleteVaultTouchID(ctx context.Context, vaultID, slotID string) bool {
	data, err := h.useTouchID(ctx, touchIDRemove, vaultID, slotID)
	vault.Wipe(data)
	return err == nil
}
