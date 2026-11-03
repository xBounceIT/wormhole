package main

import "errors"

const sshTerminalThemeKey = "SshTerminalTheme"
const defaultSshTerminalTheme = "tango"

func validSshTerminalTheme(theme string) bool {
	switch theme {
	case "wormhole-dark", "dracula", "tango", "light":
		return true
	default:
		return false
	}
}

func writeSshTerminalTheme(databasePath, theme string) error {
	if !validSshTerminalTheme(theme) {
		return errors.New("SSH terminal theme is invalid")
	}
	return writeSettingsValues(databasePath, map[string]any{sshTerminalThemeKey: theme})
}
