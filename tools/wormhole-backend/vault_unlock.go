package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This stdin-only input belongs to the native unlock flow. It is never a
// renderer IPC contract. The service never echoes factors or generated keys.
type vaultUnlockInput struct {
	VaultID, SlotID            string
	Password, RecoveryKey, ASK []byte
	RecoveryCode               []byte
}

func (input *vaultUnlockInput) wipe() {
	vault.Wipe(input.Password)
	vault.Wipe(input.RecoveryKey)
	vault.Wipe(input.RecoveryCode)
	vault.Wipe(input.ASK)
}

func (h *vaultFoundationHandler) retire(err error) error {
	h.closed = true
	return errors.Join(vaultwire.ErrRetired, err)
}

func decodeVaultUnlock(payload []byte) (input vaultUnlockInput, err error) {
	if len(payload) == 0 || len(payload) > 8192 {
		return input, vaultwire.ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return input, vaultwire.ErrProtocol
	}
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return input, vaultwire.ErrProtocol
		}
		field, ok := token.(string)
		if !ok || seen[field] {
			return input, vaultwire.ErrProtocol
		}
		seen[field] = true
		var target *[]byte
		switch field {
		case "vaultId":
			err = d.Decode(&input.VaultID)
		case "slotId":
			err = d.Decode(&input.SlotID)
		case "password":
			target = &input.Password
		case "recoveryKey":
			target = &input.RecoveryKey
		case "recoveryCode":
			target = &input.RecoveryCode
		case "ask":
			target = &input.ASK
		default:
			return input, vaultwire.ErrProtocol
		}
		if target != nil {
			var raw json.RawMessage
			err = d.Decode(&raw)
			if err == nil && len(raw) > 0 && raw[0] == '"' {
				err = json.Unmarshal(raw, target)
			} else {
				err = vaultwire.ErrProtocol
			}
			vault.Wipe(raw)
		}
		if err != nil {
			return input, vaultwire.ErrProtocol
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return input, vaultwire.ErrProtocol
	}
	if _, err := d.Token(); err != io.EOF {
		return input, vaultwire.ErrProtocol
	}
	if len(input.Password) > 1024 || (len(input.RecoveryKey) != 0 && len(input.RecoveryKey) != 32) || (len(input.RecoveryCode) != 0 && len(input.RecoveryCode) != 76) || (len(input.ASK) != 0 && len(input.ASK) != 32) {
		return input, vaultwire.ErrProtocol
	}
	return input, nil
}

func (h *vaultFoundationHandler) validateVaultOpening() error {
	if err := requireNoRootRotation(h.databasePath); err != nil {
		return err
	}
	if err := requireNoSharedWorkspace(h.databasePath); err != nil {
		return err
	}
	if err := requireNoLegacyMigrationSetup(h.databasePath); err != nil {
		return err
	}
	if h.owner != nil || h.enrollment != nil || h.databasePath == "" {
		return vaultwire.ErrProtocol
	}
	return nil
}

func (h *vaultFoundationHandler) keepVaultOpeningLease(release func()) {
	if h.owner == nil {
		release()
		return
	}
	h.releaseWorkspace = release
}

func (h *vaultFoundationHandler) open(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	if err := h.validateVaultOpening(); err != nil {
		return nil, err
	}
	input, err := decodeVaultUnlock(payload)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	releaseWorkspace, err := acquireWorkspaceOwnership(h.databasePath, true)
	if err != nil {
		return nil, err
	}
	defer h.keepVaultOpeningLease(releaseWorkspace)
	if operation == "initialize" {
		if input.VaultID != "" || input.SlotID != "" || len(input.Password) == 0 || len(input.RecoveryKey) != 32 || len(input.RecoveryCode) != 0 || len(input.ASK) != 0 {
			return nil, vaultwire.ErrProtocol
		}
		// Avoid a 256 MiB Argon2 derivation for an already initialized path.
		// Publication still checks again and atomically refuses replacement.
		if err := requireNewVaultWorkspace(h.databasePath); err != nil {
			return nil, err
		}
		key := vault.NewRecoveryKey()
		defer vault.Wipe(key)
		document := vault.SlotFile{FormatVersion: 1, VaultID: uuid.NewString(), FileID: uuid.NewString(), RootKeyID: uuid.NewString(), RootKeyVersion: 1, Initializing: true, Sequence: 1, FileEpoch: 1}
		password, err := vault.CreatePasswordSlot(ctx, document.VaultID, uuid.NewString(), 1, key, input.Password, nil, vault.KDFV1)
		if err != nil {
			return nil, err
		}
		recovery, err := vault.CreateRecoverySlot(document.VaultID, uuid.NewString(), 1, key, input.RecoveryKey)
		if err != nil {
			return nil, err
		}
		document.Slots = []vault.Slot{password, recovery}
		h.owner, err = initializeVaultFiles(ctx, h.databasePath, document, key)
		if err != nil {
			return nil, h.retire(err)
		}
	} else {
		document, err := readVaultSlotFile(h.databasePath)
		if err != nil {
			return nil, err
		}
		key, err := openVaultUnlockFactor(ctx, document, &input)
		defer vault.Wipe(key)
		if err != nil {
			return nil, err
		}
		h.owner, err = openVaultFiles(ctx, h.databasePath, document, key)
		if err != nil {
			return nil, h.retire(err)
		}
	}
	return marshalLocalVaultUnlock(h.owner)
}

func marshalLocalVaultUnlock(owner *localvault.Owner) (json.RawMessage, error) {
	return json.Marshal(struct {
		Unlocked     bool `json:"unlocked"`
		LockedMemory bool `json:"lockedMemory"`
	}{true, owner.LockedMemory()})
}

// Shared by ordinary unlock and the native migration continuation. Callers wipe
// the returned borrowed root even when authentication fails.
func openVaultUnlockFactor(ctx context.Context, document vault.SlotFile, input *vaultUnlockInput) ([]byte, error) {
	if input.VaultID != document.VaultID {
		return nil, vault.ErrAuthentication
	}
	var selected *vault.Slot
	for i := range document.Slots {
		if document.Slots[i].ID == input.SlotID {
			selected = &document.Slots[i]
			break
		}
	}
	if selected == nil {
		return nil, vault.ErrAuthentication
	}
	var key []byte
	var err error
	switch selected.Kind {
	case vault.SlotPassword:
		// Bootstrap uses kdf-v1. Lower presets need an authenticated profile
		// exception; they are not accepted by this initial native flow.
		if selected.Preset == vault.KDFLow {
			return nil, vault.ErrPolicy
		}
		if len(input.Password) == 0 || len(input.RecoveryKey) != 0 || len(input.RecoveryCode) != 0 {
			return nil, vaultwire.ErrProtocol
		}
		key, err = vault.OpenPasswordSlot(ctx, document.VaultID, *selected, input.Password, input.ASK)
	case vault.SlotRecovery:
		if len(input.Password) != 0 || len(input.ASK) != 0 || (len(input.RecoveryCode) != 0 && len(input.RecoveryKey) != 0) {
			return nil, vaultwire.ErrProtocol
		}
		if len(input.RecoveryCode) != 0 {
			input.RecoveryKey, err = vault.ParseRecoveryKey(input.RecoveryCode)
			vault.Wipe(input.RecoveryCode)
			if err != nil {
				return nil, err
			}
		}
		if len(input.RecoveryKey) != 32 {
			return nil, vaultwire.ErrProtocol
		}
		key, err = vault.OpenRecoverySlot(document.VaultID, *selected, input.RecoveryKey)
	default:
		return nil, vault.ErrPolicy
	}
	return key, err
}
