package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSidebarPinSettingDefaultsAndRoundTrips(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := writeSidebarWidth(databasePath, 420); err != nil {
		t.Fatal(err)
	}
	run := func(operation, input string) json.RawMessage {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := runBackendCLI([]string{"-database", databasePath, "-operation", operation}, strings.NewReader(input), &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", operation, code, stderr.String())
		}
		return stdout.Bytes()
	}
	for _, pinned := range []bool{true, false, true} {
		if !pinned {
			run("settings-set-sidebar-pinned", `{"pinned":false}`)
		}
		var settings struct {
			Pinned bool `json:"sidebarPinned"`
			Width  int  `json:"sidebarWidth"`
		}
		if err := json.Unmarshal(run("settings-read", ""), &settings); err != nil {
			t.Fatal(err)
		}
		if settings.Pinned != pinned || settings.Width != 420 {
			t.Fatalf("settings = %+v, want pinned %v and width 420", settings, pinned)
		}
		var startup struct {
			Settings struct {
				Pinned bool `json:"sidebarPinned"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(run("startup", ""), &startup); err != nil || startup.Settings.Pinned != pinned {
			t.Fatalf("startup pinned = %v, want %v, error %v", startup.Settings.Pinned, pinned, err)
		}
		run("settings-set-sidebar-pinned", `{"pinned":true}`)
	}
}

func TestSidebarPinSettingRejectsInvalidInputAndWriteErrors(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	for _, input := range []string{`{`, `{}`, `{"pinned":null}`, `{"pinned":"false"}`, `{"pinned":0}`} {
		var stdout, stderr bytes.Buffer
		if code := runBackendCLI([]string{"-database", databasePath, "-operation", "settings-set-sidebar-pinned"}, strings.NewReader(input), &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("input %q: exit %d, stdout %q, stderr %q", input, code, stdout.String(), stderr.String())
		}
	}
	_, settingsPath := authPaths(databasePath)
	if err := os.MkdirAll(settingsPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runBackendCLI([]string{"-database", databasePath, "-operation", "settings-set-sidebar-pinned"}, strings.NewReader(`{"pinned":false}`), &stdout, &stderr); code != 1 {
		t.Fatalf("write failure: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestSidebarPinSettingIgnoresMalformedStoredValues(t *testing.T) {
	for _, value := range []any{nil, "false", 0, []bool{false}, map[string]bool{"pinned": false}} {
		databasePath := filepath.Join(t.TempDir(), "wormhole.db")
		bitwardenTestWriteSettings(t, databasePath, map[string]any{sidebarPinnedKey: value})
		settings, err := readAppSettings(databasePath)
		if err != nil || !settings.SidebarPinned {
			t.Fatalf("stored %v: pinned = %v, error %v", value, settings.SidebarPinned, err)
		}
	}
}
