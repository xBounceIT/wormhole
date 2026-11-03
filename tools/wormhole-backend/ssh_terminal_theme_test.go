package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSshTerminalThemeCLIRoundTrip(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	run := func(operation, input string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := runBackendCLI([]string{"-database", databasePath, "-operation", operation}, strings.NewReader(input), &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", operation, code, stderr.String())
		}
		return stdout.Bytes()
	}
	for _, theme := range []string{"wormhole-dark", "dracula", "tango", "light"} {
		run("settings-set-ssh-terminal-theme", `{"theme":"`+theme+`"}`)
		var settings struct {
			Theme string `json:"sshTerminalTheme"`
		}
		if err := json.Unmarshal(run("settings-read", ""), &settings); err != nil || settings.Theme != theme {
			t.Fatalf("settings = %+v, error = %v", settings, err)
		}
		var startup struct {
			Settings struct {
				Theme string `json:"sshTerminalTheme"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(run("startup", ""), &startup); err != nil || startup.Settings.Theme != theme {
			t.Fatalf("startup = %+v, error = %v", startup, err)
		}
	}
	for _, input := range []string{`{`, `{}`, `{"theme":null}`, `{"theme":42}`, `{"theme":"invalid"}`} {
		var stdout, stderr bytes.Buffer
		if code := runBackendCLI([]string{"-database", databasePath, "-operation", "settings-set-ssh-terminal-theme"}, strings.NewReader(input), &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("input %q: exit %d, stdout %q, stderr %q", input, code, stdout.String(), stderr.String())
		}
	}
}

func TestSshTerminalThemeDefaultsAndInvalidSettings(t *testing.T) {
	for _, value := range []any{nil, "unknown", "DRACULA", " dracula", "", 42, true, []string{"tango"}} {
		t.Run(fmtThemeTestName(value), func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			if value != nil {
				bitwardenTestWriteSettings(t, databasePath, map[string]any{sshTerminalThemeKey: value})
			}
			settings, err := loadAppSettingsSnapshot(databasePath)
			if err != nil || settings.SshTerminalTheme != "tango" {
				t.Fatalf("settings = %+v, error = %v", settings, err)
			}
		})
	}
}

func fmtThemeTestName(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestSshTerminalThemeRoundTripPreservesOtherSettings(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	bitwardenTestWriteSettings(t, databasePath, map[string]any{
		"Theme": 1, "AppAuthenticationMode": 2, "FutureSetting": "preserved",
	})
	for _, theme := range []string{"wormhole-dark", "dracula", "tango", "light"} {
		if err := writeSshTerminalTheme(databasePath, theme); err != nil {
			t.Fatal(err)
		}
		settings, err := loadAppSettingsSnapshot(databasePath)
		if err != nil || settings.SshTerminalTheme != theme || settings.Theme != applicationThemeLight {
			t.Fatalf("settings = %+v, error = %v", settings, err)
		}
	}
	_, settingsPath := authPaths(databasePath)
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "sepia", "DRACULA", "light\x00", " light"} {
		if err := writeSshTerminalTheme(databasePath, invalid); err == nil {
			t.Fatalf("accepted invalid theme %q", invalid)
		}
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("invalid theme modified settings")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(after, &document); err != nil {
		t.Fatal(err)
	}
	if string(document["AppAuthenticationMode"]) != "2" || string(document["FutureSetting"]) != `"preserved"` {
		t.Fatal("unrelated settings changed")
	}
}

func TestSshTerminalThemeWritePropagatesStorageError(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	_, settingsPath := authPaths(databasePath)
	if err := os.MkdirAll(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeSshTerminalTheme(databasePath, "tango"); err == nil {
		t.Fatal("storage failure was ignored")
	}
	settings, err := readAppSettings(databasePath)
	if err == nil || settings.SshTerminalTheme != defaultSshTerminalTheme {
		t.Fatalf("settings = %+v, error = %v", settings, err)
	}
}
