package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedFileEditSettingsAuthenticateWithoutSQLite(t *testing.T) {
	c, p, _, _, _, _, _, _ := credentialControllerFixture(t)
	original := p.runtime
	reads := 0
	p.runtime = func(ctx context.Context) (*sharedpg.UnverifiedRuntimeState, error) { reads++; return original(ctx) }
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: uuid.NewString()}, databasePath: filepath.Join(t.TempDir(), "workspace.sqlite")}
	t.Cleanup(func() { _ = h.Close() })
	raw, err := h.Handle(context.Background(), "file-edit-settings", nil)
	var settings sftpEditorSettings
	if err != nil || json.Unmarshal(raw, &settings) != nil || settings.DefaultEditor != "auto" || reads != 1 {
		t.Fatal("shared preference read", err, reads)
	}
	settings.SwapPanels = true
	input, _ := json.Marshal(settings)
	raw, err = h.Handle(context.Background(), "file-edit-settings", input)
	if err != nil || !bytes.Equal(raw, input) || reads != 2 {
		t.Fatal("shared preference write", err, reads)
	}
	if _, err = os.Stat(h.databasePath); !os.IsNotExist(err) {
		t.Fatal("shared preferences opened a local database", err)
	}
	_, settingsPath := authPaths(h.databasePath)
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{[]byte(`{}`), bytes.Repeat([]byte(" "), 65537)} {
		if _, err := h.Handle(context.Background(), "file-edit-settings", input); err != vaultwire.ErrProtocol || !c.Unlocked() {
			t.Fatal("malformed settings changed owner", err)
		}
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid settings changed disk", err)
	}
	p.runtime = func(context.Context) (*sharedpg.UnverifiedRuntimeState, error) {
		return nil, errors.New("unauthenticated state")
	}
	settings.SwapPanels = false
	input, _ = json.Marshal(settings)
	if raw, err = h.Handle(context.Background(), "file-edit-settings", input); !errors.Is(err, vaultwire.ErrRetired) || len(raw) != 0 || !h.closed || c.Unlocked() {
		t.Fatal("failed shared authentication retained owner", err)
	}
	after, err = os.ReadFile(settingsPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("unauthenticated preferences changed disk", err)
	}
}

func TestSharedFileEditSettingsRejectsInvalidOwnerBeforeFilesystem(t *testing.T) {
	c, _, _, _, _, _, _, _ := credentialControllerFixture(t)
	path := filepath.Join(t.TempDir(), "unused", "workspace.sqlite")
	h := &vaultFoundationHandler{shared: &vaultSharedSession{controller: c, vaultID: "invalid"}, databasePath: path}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := h.Handle(context.Background(), "file-edit-settings", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("invalid owner reached filesystem", err)
	}
}
