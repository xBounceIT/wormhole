package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultPreferences(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "preferences", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	h := vaultCredentialFixture(t)
	if _, err := h.Handle(ctx, "preferences", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	raw, err := h.Handle(ctx, "preferences", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got appSettingsSnapshot
	if err := json.Unmarshal(raw, &got); err != nil || got.SidebarWidth != 320 || !got.ConfirmOnWindowClose {
		t.Fatal(string(raw), err)
	}
	_, settingsPath := authPaths(h.databasePath)
	settings := []byte(`{"Theme":"dark","SidebarWidth":600,"AppAuthMode":"disabled","Password":"do-not-project","Token":"do-not-project","IdleTimeoutMinutes":0}`)
	if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err = h.Handle(ctx, "preferences", nil)
	if err != nil || bytes.Contains(raw, []byte("do-not-project")) || bytes.Contains(raw, []byte("Auth")) {
		t.Fatal(string(raw), err)
	}
	if err := json.Unmarshal(raw, &got); err != nil || got.Theme != applicationThemeDark || got.SidebarWidth != 600 {
		t.Fatal(string(raw), err)
	}
	unchanged, err := os.ReadFile(settingsPath)
	if err != nil || !bytes.Equal(unchanged, settings) {
		t.Fatal("preferences wrote legacy settings", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.preferences(cancelled, nil); err != context.Canceled {
		t.Fatal(err)
	}
	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "preferences", nil); err == nil {
		t.Fatal("settings read failure ignored")
	}
}

func TestVaultUpdatePreferences(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "update-preferences", []byte(`{}`)); err != vaultwire.ErrProtocol {
		t.Fatalf("locked preferences write returned %v", err)
	}
	h := vaultCredentialFixture(t)
	_, settingsPath := authPaths(h.databasePath)
	if err := os.WriteFile(settingsPath, []byte(`{"Theme":"dark","AuthMode":"disabled","TestSetting":42}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		``, `[]`, `{"unknown":1}`, `{"autoCheckForUpdates":null}`, `{"autoCheckForUpdates":true,"autoCheckForUpdates":false}`,
		`{"skippedUpdateVersion":true}`, `{"skippedUpdateVersion":"not a version"}`,
		`{"lastUpdateCheck":"2026-11-25T09:13:54+00:00"}`, `{"lastUpdateCheck":"invalid"}`,
		`{"skippedUpdateVersion":"` + strings.Repeat("1", 1024) + `"}`,
	} {
		if _, err := h.Handle(ctx, "update-preferences", []byte(payload)); err != vaultwire.ErrProtocol {
			t.Fatalf("invalid update preferences %q returned %v", payload, err)
		}
	}
	for _, payload := range []string{
		`{}`, `{"autoCheckForUpdates":false,"skippedUpdateVersion":"2.4.1"}`,
		`{"lastUpdateCheck":"2026-11-25T09:13:54Z"}`, `{"skippedUpdateVersion":null}`,
	} {
		result, err := h.Handle(ctx, "update-preferences", []byte(payload))
		if err != nil || string(result) != "true" {
			t.Fatalf("valid update preferences %q returned %s %v", payload, result, err)
		}
	}
	raw, err := h.Handle(ctx, "preferences", nil)
	if err != nil {
		t.Fatal(err)
	}
	var settings appSettingsSnapshot
	if err := json.Unmarshal(raw, &settings); err != nil || settings.AutoCheckForUpdates ||
		settings.SkippedUpdateVersion != nil || settings.LastUpdateCheck == nil ||
		*settings.LastUpdateCheck != "2026-11-25T09:13:54Z" || settings.Theme != applicationThemeDark {
		t.Fatalf("unexpected update preferences: %s (%v)", raw, err)
	}
	stored, err := os.ReadFile(settingsPath)
	if err != nil || !bytes.Contains(stored, []byte(`"TestSetting":42`)) {
		var rawSettings map[string]any
		if json.Unmarshal(stored, &rawSettings) != nil || rawSettings["TestSetting"] != float64(42) {
			t.Fatalf("unrelated setting was lost: %s (%v)", stored, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.updatePreferences(cancelled, []byte(`{"autoCheckForUpdates":true}`)); err != context.Canceled {
		t.Fatal(err)
	}
	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "update-preferences", []byte(`{"autoCheckForUpdates":true}`)); err == nil {
		t.Fatal("update preference write falsely succeeded")
	}
}
