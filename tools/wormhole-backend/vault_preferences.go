package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Preferences are display/interaction settings, never authentication policy.
// Read them only after unlock; startup exposes just the cosmetic theme.
func (h *vaultFoundationHandler) preferences(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(payload) != 0 {
		return nil, vaultwire.ErrProtocol
	}
	if h.shared != nil {
		if _, err := h.readSharedRuntime(ctx); err != nil {
			return nil, err
		}
	}
	settings, err := loadAppSettingsSnapshot(h.databasePath)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(settings)
	if err != nil || len(raw) > vaultwire.MaxFrameBytes-65536 {
		return nil, vaultwire.ErrProtocol
	}
	return raw, nil
}

// Only the resident owner can update its public preferences. This operation
// accepts individual fields so a check cannot overwrite a concurrent UI edit.
func (h *vaultFoundationHandler) updatePreferences(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(payload) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var autoCheck *bool
	var theme *applicationTheme
	var terminalTheme *string
	var skipped json.RawMessage
	var checkedAt *string
	if decodeVaultNullableObject(payload, map[string]any{
		"theme": &theme, "sshTerminalTheme": &terminalTheme,
		"autoCheckForUpdates": &autoCheck, "skippedUpdateVersion": &skipped, "lastUpdateCheck": &checkedAt,
	}, map[string]bool{"skippedUpdateVersion": true}) != nil {
		return nil, vaultwire.ErrProtocol
	}
	values := make(map[string]any, 5)
	if terminalTheme != nil {
		if !validSshTerminalTheme(*terminalTheme) {
			return nil, vaultwire.ErrProtocol
		}
		values[sshTerminalThemeKey] = *terminalTheme
	}
	if theme != nil {
		persisted, ok := persistedApplicationTheme(*theme)
		if !ok {
			return nil, vaultwire.ErrProtocol
		}
		values[themeKey] = persisted
	}
	if autoCheck != nil {
		values[autoCheckForUpdatesKey] = *autoCheck
	}
	if len(skipped) != 0 {
		var version *string
		if json.Unmarshal(skipped, &version) != nil {
			return nil, vaultwire.ErrProtocol
		}
		if version != nil {
			if _, ok := parseAppVersion(*version); !ok || len(*version) > 64 {
				return nil, vaultwire.ErrProtocol
			}
		}
		values[skippedUpdateVersionKey] = version
	}
	if checkedAt != nil {
		parsed, err := time.Parse(time.RFC3339, *checkedAt)
		if err != nil || parsed.UTC().Format(time.RFC3339) != *checkedAt {
			return nil, vaultwire.ErrProtocol
		}
		values[lastUpdateCheckKey] = *checkedAt
	}
	if h.shared != nil {
		if _, err := h.readSharedRuntime(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(values) != 0 {
		if err := writeSettingsValues(h.databasePath, values); err != nil {
			return nil, err
		}
	}
	return json.RawMessage("true"), nil
}
