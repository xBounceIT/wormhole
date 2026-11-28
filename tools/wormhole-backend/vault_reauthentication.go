package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func vaultFreshAction(operation string) bool {
	switch operation {
	case "tighten-local-profile", "local-backup-export", "hello-enroll", "hello-remove", "touch-id-enroll", "touch-id-remove":
		return true
	case "bitwarden-cleanup", "bitwarden-install-zip", "bitwarden-install-folder", "credential-clipboard-release", "credential-copy", "credential-display", "ssh-host-trust", "ssh-quick-host-trust", "tunnel-edit", "credential-edit", "migration-decide", "connection-save", "folder-save", "credential-save", "credential-delete", "tunnel-save", "tunnel-delete", "node-save", "node-delete", "node-delete-tree", "node-delete-trees", "node-move", "node-duplicate":
		return true
	default:
		return false
	}
}

// Authentication and the exact action travel in one bounded stdin request. No
// token, process-wide flag or successful earlier unlock can authorize a second
// action. The ordinary dispatch still validates policy and the domain request.
func (h *vaultFoundationHandler) freshAction(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > vaultwire.MaxFrameBytes-1024 {
		return nil, vaultwire.ErrProtocol
	}
	var operation string
	var authJSON, actionJSON json.RawMessage
	defer func() { vault.Wipe(authJSON); vault.Wipe(actionJSON) }()
	if decodeVaultObject(payload, map[string]any{"operation": &operation, "authentication": &authJSON, "action": &actionJSON}, "operation", "authentication", "action") != nil || !vaultFreshAction(operation) {
		return nil, vaultwire.ErrProtocol
	}
	var authentication, action []byte
	defer func() { vault.Wipe(authentication); vault.Wipe(action) }()
	if len(authJSON) == 0 || authJSON[0] != '"' || len(actionJSON) == 0 || actionJSON[0] != '"' || json.Unmarshal(authJSON, &authentication) != nil || json.Unmarshal(actionJSON, &action) != nil || len(action) == 0 || len(action) > 6*1024*1024 {
		return nil, vaultwire.ErrProtocol
	}
	input, err := decodeVaultUnlock(authentication)
	defer input.wipe()
	if err != nil {
		return nil, err
	}
	document, err := readVaultSlotFile(h.databasePath)
	if err != nil {
		return nil, h.retire(err)
	}
	err = h.verifyCurrentVaultFactor(ctx, document, &input)
	vault.Wipe(authentication)
	vault.Wipe(authJSON)
	if err != nil {
		return nil, err
	}
	// The decoded action owns its bytes; retire the outer request too, which
	// still contains the base64-encoded factor until the transport returns.
	vault.Wipe(payload)
	if operation == "tighten-local-profile" {
		// Pin the checkpoint write to the same slot revision that proved the factor.
		return h.tightenLocalProfile(ctx, action, document)
	}
	return h.handle(ctx, operation, action, true)
}

// Shared native action authentication. Success is consumed by its current caller,
// never retained as a process-wide authorization for another operation.
func (h *vaultFoundationHandler) verifyCurrentVaultFactor(ctx context.Context, document vault.SlotFile, input *vaultUnlockInput) error {
	defer input.wipe()
	if input.VaultID != document.VaultID {
		return vault.ErrAuthentication
	}
	if len(input.RecoveryCode) != 0 {
		if len(input.RecoveryKey) != 0 {
			return vaultwire.ErrProtocol
		}
		var err error
		input.RecoveryKey, err = vault.ParseRecoveryKey(input.RecoveryCode)
		if err != nil {
			return vaultwire.ErrProtocol
		}
	}
	err := h.owner.VerifyReauthentication(ctx, document, input.SlotID, input.Password, input.RecoveryKey, input.ASK)
	// Verification is finished; the mutation must not extend the factor lifetime.
	input.wipe()
	if errors.Is(err, localvault.ErrReauthentication) {
		h.reauthenticationFailures++
		if h.reauthenticationFailures >= 3 {
			return h.retire(vault.ErrAuthentication)
		}
		return vault.ErrAuthentication
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return h.retire(err)
	}
	h.reauthenticationFailures = 0
	return nil
}
