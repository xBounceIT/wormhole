package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PromptBeforeTunnelConnect lives in the shared settings.json document next to app-auth.dpapi
// (see authPaths). It is owned by Go: the renderer only reads and writes it through the
// settings-read / settings-set-prompt-before-tunnel operations.
const promptBeforeTunnelConnectKey = "PromptBeforeTunnelConnect"

// Update preferences share the same settings.json document and use the same JSON keys as the
// WinUI 3 AppSettings model (AutoCheckForUpdates, LastUpdateCheck, SkippedUpdateVersion).
const (
	autoCheckForUpdatesKey  = "AutoCheckForUpdates"
	lastUpdateCheckKey      = "LastUpdateCheck"
	skippedUpdateVersionKey = "SkippedUpdateVersion"
)

// readPromptBeforeTunnelConnect reports whether connecting to a saved connection should first
// ask whether to use its configured VPN tunnel. Absent, invalid, or unreadable settings fall
// back to true, matching the WinUI 3 default.
func readPromptBeforeTunnelConnect(databasePath string) (bool, error) {
	promptBeforeTunnel, _, _, _, err := readAppSettings(databasePath)
	return promptBeforeTunnel, err
}

// writePromptBeforeTunnelConnect merges the setting into settings.json, preserving every other
// key (including the app-authentication settings) that already lives in the document.
func writePromptBeforeTunnelConnect(databasePath string, enabled bool) error {
	return writeSettingsValues(databasePath, map[string]any{promptBeforeTunnelConnectKey: enabled})
}

// readAppSettings reads the shared settings.json document. Absent, invalid, or unreadable
// settings fall back to the WinUI 3 defaults: prompt-before-tunnel on, auto-check on, no last
// check marker, no skipped version.
func readAppSettings(databasePath string) (
	promptBeforeTunnel bool,
	autoCheckForUpdates bool,
	lastUpdateCheck *string,
	skippedUpdateVersion *string,
	err error,
) {
	promptBeforeTunnel = true
	autoCheckForUpdates = true
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return promptBeforeTunnel, autoCheckForUpdates, nil, nil, nil
	}
	if err != nil {
		return promptBeforeTunnel, autoCheckForUpdates, nil, nil,
			fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(contents, &document) != nil || document == nil {
		return promptBeforeTunnel, autoCheckForUpdates, nil, nil, nil
	}
	if value, ok := document[promptBeforeTunnelConnectKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			promptBeforeTunnel = enabled
		}
	}
	if value, ok := document[autoCheckForUpdatesKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			autoCheckForUpdates = enabled
		}
	}
	if value, ok := document[lastUpdateCheckKey]; ok && string(value) != "null" {
		var stamp string
		if json.Unmarshal(value, &stamp) == nil && stamp != "" {
			lastUpdateCheck = &stamp
		}
	}
	if value, ok := document[skippedUpdateVersionKey]; ok && string(value) != "null" {
		var skipped string
		if json.Unmarshal(value, &skipped) == nil && skipped != "" {
			skippedUpdateVersion = &skipped
		}
	}
	return promptBeforeTunnel, autoCheckForUpdates, lastUpdateCheck, skippedUpdateVersion, nil
}

// writeSettingsValues merges the given keys into settings.json, preserving every other key
// (including the app-authentication settings) that already lives in the document. A nil value
// writes JSON null, which clears the key on the next read.
func writeSettingsValues(databasePath string, values map[string]any) error {
	_, settingsPath := authPaths(databasePath)
	document := map[string]json.RawMessage{}
	contents, err := readAuthSettingsFile(settingsPath)
	if err == nil {
		_ = json.Unmarshal(contents, &document)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	if document == nil {
		document = map[string]json.RawMessage{}
	}
	for key, value := range values {
		encoded, encodeErr := json.Marshal(value)
		if encodeErr != nil {
			return fmt.Errorf("cannot encode Wormhole settings: %w", encodeErr)
		}
		document[key] = encoded
	}
	contents, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		return fmt.Errorf("cannot create the Wormhole data directory: %w", err)
	}
	temporaryPath := settingsPath + ".tmp"
	if err := os.WriteFile(temporaryPath, append(contents, '\n'), 0o600); err != nil {
		return fmt.Errorf("cannot write Wormhole settings: %w", err)
	}
	if err := replaceAuthFile(temporaryPath, settingsPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("cannot save Wormhole settings: %w", err)
	}
	return nil
}
