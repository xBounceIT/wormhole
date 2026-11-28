package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestVisualChangelogClaimThroughBackendCLI(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	if err := writeSidebarPinned(databasePath, false); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		version      string
		hasChangelog bool
		claimed      bool
	}{
		{"2.5.0-preview.1", true, false},
		{"02.5.0", true, false},
		{"2.5.0.0", true, false},
		{"2.5.0", true, true},
		{"2.5.0", true, false},
		{"2.4.0", true, false},
		{"2.5.1", true, false},
		{"2.9.0", true, true},
		{"2.10.0", true, true},
		{"3.0.0", true, true},
		{"2.10.0", true, false},
	} {
		var stdout, stderr bytes.Buffer
		payload, err := json.Marshal(map[string]any{
			"appVersion": test.version, "hasChangelog": test.hasChangelog,
		})
		if err != nil {
			t.Fatal(err)
		}
		exit := runBackendCLI([]string{"-database", databasePath, "-operation", "visual-changelog-claim"},
			bytes.NewReader(payload), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("%s: exit %d: %s", test.version, exit, stderr.String())
		}
		want := `{"claimed":false}`
		if test.claimed {
			want = `{"claimed":true}`
		}
		if got := strings.TrimSpace(stdout.String()); got != want {
			t.Fatalf("%s: got %s, want %s", test.version, got, want)
		}
	}
	settings, err := readAppSettings(databasePath)
	if err != nil || settings.SidebarPinned {
		t.Fatalf("changelog claims must preserve existing settings: %+v, %v", settings, err)
	}
}

func TestVaultChangelogClaimLeavesWorkspaceUnopened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wormhole.db")
	slot := vaultSlotPath(path)
	if err := os.WriteFile(slot, []byte("vault marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	if code := runBackendCLI([]string{"-database", path, "-operation", "visual-changelog-claim"}, strings.NewReader(`{"appVersion":"2.5.0","hasChangelog":true}`), &output, &stderr); code != 0 || strings.TrimSpace(output.String()) != `{"claimed":true}` {
		t.Fatalf("claim %d %q %q", code, &output, &stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("claim attempted to open workspace", err)
	}
	if marker, err := os.ReadFile(slot); err != nil || string(marker) != "vault marker" {
		t.Fatal("claim changed vault marker", err)
	}
}

func TestVisualChangelogClaimIsAtomic(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "wormhole.db")
	var claims atomic.Int32
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			claimed, err := claimVisualChangelog(databasePath, "2.5.0", true)
			if err != nil {
				t.Error(err)
			}
			if claimed {
				claims.Add(1)
			}
		})
	}
	wait.Wait()
	if got := claims.Load(); got != 1 {
		t.Fatalf("claimed %d times, want 1", got)
	}
}

func TestVisualChangelogDoesNotOpenAfterDowngradeFromNewerLaunch(t *testing.T) {
	for _, newer := range []string{"2.5.1", "2.6.0"} {
		t.Run(newer, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			if claimed, err := claimVisualChangelog(databasePath, newer, false); claimed || err != nil {
				t.Fatalf("launch %s without slides = %v, %v, want false", newer, claimed, err)
			}
			if claimed, err := claimVisualChangelog(databasePath, "2.5.0", true); claimed || err != nil {
				t.Fatalf("downgraded release claim = %v, %v, want false", claimed, err)
			}
			if claimed, err := claimVisualChangelog(databasePath, "3.0.0", true); !claimed || err != nil {
				t.Fatalf("newer release claim = %v, %v, want true", claimed, err)
			}
		})
	}
}

func TestVisualChangelogClaimPreservesMalformedSettings(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{"malformed document", `{"Theme":"dark",`},
		{"malformed version", `{"Theme":"dark","LastVisualChangelogVersion":"invalid"}`},
		{"wrong version type", `{"Theme":"dark","LastVisualChangelogVersion":123}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "wormhole.db")
			_, settingsPath := authPaths(databasePath)
			if err := os.WriteFile(settingsPath, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if claimed, err := claimVisualChangelog(databasePath, "2.5.0", true); claimed || err == nil {
				t.Fatalf("claim = %v, %v, want false and an error", claimed, err)
			}
			if got, err := os.ReadFile(settingsPath); err != nil || string(got) != test.contents {
				t.Fatalf("settings changed: %q, %v", got, err)
			}
		})
	}
}
