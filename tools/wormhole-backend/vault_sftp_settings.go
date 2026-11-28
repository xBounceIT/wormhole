package main

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Editor preferences contain no credentials and do not alter vault protection.
// The unlocked owner writes them without invoking legacy startup or a database.
func (h *vaultFoundationHandler) fileEditSettings(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(payload) > 64*1024 {
		return nil, vaultwire.ErrProtocol
	}
	if h.shared != nil {
		// Device-local editor preferences are public metadata, not a local tree.
		// Authenticate the current shared owner/policy before filesystem access.
		if _, err := h.readSharedRuntime(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		var settings sftpEditorSettings
		var editors []json.RawMessage
		if decodeVaultObject(payload, map[string]any{"editors": &editors, "defaultEditor": &settings.DefaultEditor, "maxFileSize": &settings.MaxFileSize, "swapPanels": &settings.SwapPanels}, "editors", "defaultEditor", "maxFileSize", "swapPanels") != nil || len(editors) > 32 {
			return nil, vaultwire.ErrProtocol
		}
		settings.Editors = []sftpEditor{}
		for _, raw := range editors {
			var editor sftpEditor
			var arguments []json.RawMessage
			if decodeVaultObject(raw, map[string]any{"id": &editor.ID, "name": &editor.Name, "executable": &editor.Executable, "arguments": &arguments, "patterns": &editor.Patterns}, "id", "name", "executable", "arguments", "patterns") != nil {
				return nil, vaultwire.ErrProtocol
			}
			if len(arguments) > 64 {
				return nil, vaultwire.ErrProtocol
			}
			editor.Arguments = []string{}
			for _, rawArgument := range arguments {
				var argument string
				if len(bytes.TrimSpace(rawArgument)) == 0 || bytes.TrimSpace(rawArgument)[0] != '"' || json.Unmarshal(rawArgument, &argument) != nil {
					return nil, vaultwire.ErrProtocol
				}
				editor.Arguments = append(editor.Arguments, argument)
			}
			settings.Editors = append(settings.Editors, editor)
		}
		if err := validateSftpEditorSettings(settings); err != nil {
			return nil, vaultwire.ErrProtocol
		}
		encoded, _ := json.Marshal(settings) // Fixed fields cannot fail to encode.
		if len(encoded) > 64*1024 {
			return nil, vaultwire.ErrProtocol
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writeSftpEditorSettings(h.databasePath, settings); err != nil {
			return nil, err
		}
	}
	settings, err := readSftpEditorSettings(h.databasePath)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if settings.Editors == nil {
		settings.Editors = []sftpEditor{}
	}
	for i := range settings.Editors {
		if settings.Editors[i].Arguments == nil {
			settings.Editors[i].Arguments = []string{}
		}
	}
	raw, err := json.Marshal(settings)
	if err != nil || len(raw) > 64*1024 {
		return nil, vaultwire.ErrProtocol
	}
	return raw, nil
}
