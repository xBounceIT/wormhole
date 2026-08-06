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

// readPromptBeforeTunnelConnect reports whether connecting to a saved connection should first
// ask whether to use its configured VPN tunnel. Absent, invalid, or unreadable settings fall
// back to true, matching the WinUI 3 default.
func readPromptBeforeTunnelConnect(databasePath string) (bool, error) {
	_, settingsPath := authPaths(databasePath)
	contents, err := readAuthSettingsFile(settingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return true, fmt.Errorf("cannot read Wormhole settings: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil || document == nil {
		return true, nil
	}
	if value, ok := document[promptBeforeTunnelConnectKey]; ok {
		var enabled bool
		if json.Unmarshal(value, &enabled) == nil {
			return enabled, nil
		}
	}
	return true, nil
}

// writePromptBeforeTunnelConnect merges the setting into settings.json, preserving every other
// key (including the app-authentication settings) that already lives in the document.
func writePromptBeforeTunnelConnect(databasePath string, enabled bool) error {
	_, settingsPath := authPaths(databasePath)
	document := map[string]json.RawMessage{}
	contents, err := readAuthSettingsFile(settingsPath)
	if err == nil {
		_ = json.Unmarshal(contents, &document)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if document == nil {
		document = map[string]json.RawMessage{}
	}
	value, err := json.Marshal(enabled)
	if err != nil {
		return fmt.Errorf("cannot encode Wormhole settings: %w", err)
	}
	document[promptBeforeTunnelConnectKey] = value

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
