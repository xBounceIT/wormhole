package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultStartupOnlyPublicSlotsAndCosmetics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workspace.db")
	// This is deliberately not SQLite. Startup must not open, migrate or repair it.
	database := []byte("not-a-database-private-sentinel")
	if err := os.WriteFile(path, database, 0600); err != nil {
		t.Fatal(err)
	}
	authPath, settingsPath := authPaths(path)
	if err := os.Mkdir(authPath, 0700); err != nil {
		t.Fatal(err)
	} // authState cannot read this.
	settings := []byte(`{"SettingsSchemaVersion":0,"Theme":2,"AuthenticationMode":0,"IdleTimeoutMinutes":null,"McpApprovalMode":"full-access","BitwardenSession":"startup-private-token","AutoCheckForUpdates":false}`)
	if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
		t.Fatal(err)
	}
	doc, key := localSlotFixture(t)
	defer vault.Wipe(key)
	raw, err := vault.EncodeSlotFile(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(path), raw, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: path}
	response, err := h.Handle(context.Background(), "startup", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result vaultStartupMetadata
	if err := json.Unmarshal(response, &result); err != nil {
		t.Fatal(err)
	}
	if result.Cosmetics.Theme != applicationThemeDark || result.Slots == nil || result.Slots.VaultID != doc.VaultID || h.owner != nil {
		t.Fatal("startup opened vault or lost public hints")
	}
	for _, forbidden := range []string{"startup-private", "AuthenticationMode", "idleTimeout", "Mcp", "AutoCheck", "rootKey", "keyCheck", "wrapped", "ciphertext", "migration", "workspace", "auth"} {
		if bytes.Contains(response, []byte(forbidden)) {
			t.Fatal("non-allowlisted field", forbidden)
		}
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := func(entries []os.DirEntry) []string {
		var result []string
		for _, entry := range entries {
			result = append(result, entry.Name())
		}
		return result
	}
	if !reflect.DeepEqual(names(before), names(after)) {
		t.Fatal("startup wrote files")
	}
	for name, want := range map[string][]byte{path: database, settingsPath: settings, vaultSlotPath(path): raw} {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("startup modified source", name, err)
		}
	}
}

func TestVaultStartupOSUpgradeIsOnlyPublicRouting(t *testing.T) {
	f, custody, h := upgradeEnrollmentSource(t)
	doc, err := readVaultSlotFile(f.source)
	if err != nil {
		t.Fatal(err)
	}
	// Neither a missing OS factor nor an invalid database can grant ordinary
	// access. Startup must only return a hint and leave both untouched.
	if err := os.Remove(custody); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("startup-must-not-open-sqlite")
	if err := os.WriteFile(f.source, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := h.startup(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var result vaultStartupMetadata
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Unprotected == nil || result.Unprotected.VaultID != doc.VaultID || result.Upgrade != nil || result.Slots != nil || result.NewWorkspace || h.owner != nil || h.enrollment != nil || h.releaseWorkspace != nil {
		t.Fatal("upgrade hint granted an owner", string(raw))
	}
	got, err := os.ReadFile(f.source)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("startup touched database", err)
	}
	if _, err := os.Stat(custody); !os.IsNotExist(err) {
		t.Fatal("startup recreated custody", err)
	}
	if _, err := os.Stat(rootRotationJournalPath(f.source)); !os.IsNotExist(err) {
		t.Fatal("startup prepared upgrade", err)
	}
	for _, field := range []string{"ciphertext", "salt", "slotId", "wrapped", "factor", "policy"} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatal("non-public startup field", field)
		}
	}
	doc.Initializing = true
	encoded, err := vault.EncodeSlotFile(f.old, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultSlotPath(f.source), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.startup(context.Background(), nil); err != nil {
		t.Fatal("Default OS initialization cannot be resumed", err)
	}
}

func TestVaultStartupDoesNotInferAuthorizationFromMissingOrCorruptSlots(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "workspace.db")
	h := &vaultFoundationHandler{databasePath: path}
	raw, err := h.Handle(ctx, "startup", nil)
	if err != nil || string(raw) != `{"slots":null,"cosmetics":{"theme":"system"},"newWorkspace":true,"unprotectedAllowed":true}` {
		t.Fatal(string(raw), err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("created database")
	}
	if _, err := h.Handle(ctx, "workspace", nil); err != vaultwire.ErrProtocol {
		t.Fatal("missing slots authorized workspace", err)
	}
	for _, payload := range [][]byte{[]byte(`{}`), []byte(`{"password":"private"}`)} {
		if _, err := h.Handle(ctx, "startup", payload); err != vaultwire.ErrProtocol {
			t.Fatal(err)
		}
	}
	if _, err := (&vaultFoundationHandler{}).Handle(ctx, "startup", nil); err != vaultwire.ErrProtocol {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.startup(canceled, nil); err != context.Canceled {
		t.Fatal(err)
	}
	for _, contents := range []string{`{"rootKey":"private"}`, `null`, strings.Repeat("x", vault.MaxSlotFileBytes+1)} {
		if err := os.WriteFile(vaultSlotPath(path), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if raw, err := h.Handle(ctx, "startup", nil); err == nil || len(raw) != 0 {
			t.Fatal("bad slot file became legacy/unprotected workspace", err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "startup", nil); err == nil {
		t.Fatal("closed handler accepted startup")
	}
}

func TestVaultStartupNewWorkspaceRequiresAbsentDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.db")
	h := &vaultFoundationHandler{databasePath: path}
	for _, exists := range []bool{false, true} {
		if exists {
			if err := os.WriteFile(path, []byte("legacy workspace sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		raw, err := h.Handle(context.Background(), "startup", nil)
		if err != nil {
			t.Fatal(err)
		}
		var result vaultStartupMetadata
		if err := json.Unmarshal(raw, &result); err != nil || result.NewWorkspace == exists || result.Slots != nil {
			t.Fatal("wrong creation eligibility", err)
		}
		if h.owner != nil {
			t.Fatal("public probe acquired secret owner")
		}
		if exists && (result.Legacy == nil || !result.Legacy.UnprotectedAllowed || result.UnprotectedAllowed) || !exists && result.Legacy != nil {
			t.Fatal("legacy routing hint confused with new workspace")
		}
	}
}

func TestVaultStartupLegacyHintNeverOpensSQLOrUnsafeFileTypes(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "workspace.db")
			original := []byte("not SQLite: private legacy source")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "target.db")
				if err := os.WriteFile(target, original, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skip("file symlinks unavailable", err)
				}
			default:
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			h := &vaultFoundationHandler{databasePath: path}
			raw, err := h.startup(ctx, nil)
			if kind != "file" {
				if err == nil || len(raw) != 0 {
					t.Fatal("unsafe source granted legacy route")
				}
			} else {
				var metadata vaultStartupMetadata
				if err != nil || json.Unmarshal(raw, &metadata) != nil || metadata.Legacy == nil || !metadata.Legacy.UnprotectedAllowed || bytes.Contains(raw, []byte("private")) {
					t.Fatal("invalid legacy hint", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, original) {
					t.Fatal("public probe modified SQL", err)
				}
			}
			if h.owner != nil || h.enrollment != nil || h.releaseWorkspace != nil {
				t.Fatal("public probe admitted owner")
			}
			if _, err := os.Stat(vaultSlotPath(path)); !os.IsNotExist(err) {
				t.Fatal("public probe created vault slots", err)
			}
		})
	}
}

func TestVaultStartupCosmeticsCannotLockOutRecoveryOrWriteSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workspace.db")
	_, settingsPath := authPaths(path)
	for _, test := range []struct {
		raw  string
		want applicationTheme
	}{
		{`{"Theme":"light"}`, applicationThemeLight}, {`{"Theme":1}`, applicationThemeLight},
		{`{"Theme":"dark"}`, applicationThemeDark}, {`{"Theme":0}`, applicationThemeSystem},
		{`{"Theme":"unknown"}`, applicationThemeSystem}, {`{"Theme":{"password":"private"}}`, applicationThemeSystem},
		{`{"Theme":"dark"} trailing`, applicationThemeSystem}, {`null`, applicationThemeSystem},
		{`[]`, applicationThemeSystem}, {`{}`, applicationThemeSystem},
		{strings.Repeat(" ", authMaxSettingsBytes+1), applicationThemeSystem},
	} {
		original := []byte(test.raw)
		if err := os.WriteFile(settingsPath, original, 0600); err != nil {
			t.Fatal(err)
		}
		if result := readVaultStartupCosmetics(path); result.Theme != test.want {
			t.Fatal("wrong theme", result.Theme, test.want)
		}
		got, err := os.ReadFile(settingsPath)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("settings rewritten", err)
		}
	}
	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(settingsPath, 0700); err != nil {
		t.Fatal(err)
	}
	if result := readVaultStartupCosmetics(path); result.Theme != applicationThemeSystem {
		t.Fatal("non-regular settings accepted")
	}
}

func TestVaultStartupIgnoresSettingsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cosmetics.json")
	if err := os.WriteFile(target, []byte(`{"Theme":"dark"}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "workspace.db")
	_, settings := authPaths(path)
	if err := os.Symlink(target, settings); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if result := readVaultStartupCosmetics(path); result.Theme != applicationThemeSystem {
		t.Fatal("followed settings symlink")
	}
}
