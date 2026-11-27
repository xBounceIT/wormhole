package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedSetupServerKitPublicationAndRetirementRecovery(t *testing.T) {
	useTemporaryServerKitCache(t)
	h, _ := sharedSetupTestHandler(t)
	input := map[string]any{
		"host": "127.0.0.1", "port": 5432, "database": "vault", "approvedHosts": []string{"127.0.0.1"},
		"accountPassword": []byte("synthetic-stage-password"), "keyPassphrase": []byte("synthetic-key-passphrase"),
	}
	ctx := context.Background()
	raw, err := h.Handle(ctx, "shared-setup-prepare-generated-tls", vaultInput(t, input))
	var out sharedSetupReply
	if err != nil || json.Unmarshal(raw, &out) != nil || out.Plan == nil || out.ServerKit == nil || out.TLS == nil ||
		bytes.Contains(raw, []byte("ENCRYPTED PRIVATE KEY")) || bytes.Contains(raw, input["keyPassphrase"].([]byte)) {
		t.Fatal("generated setup did not return public-only staging metadata", err)
	}
	folder := out.ServerKit.Folder
	path := sharedSetupPlanPath(h.databasePath)
	protection := h.startupProtection()
	plan, err := readSharedSetupPlan(path, protection)
	if err != nil || plan.ServerKit == nil || plan.ServerKit.State != serverKitPending {
		t.Fatal("pending export was not durable", err)
	}
	key := plan.ServerKit.EncryptedKey
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(rest) != 0 || bytes.Contains(key, input["keyPassphrase"].([]byte)) {
		t.Fatal("staged server key was not an encrypted PKCS#8 record")
	}
	if _, err := os.Lstat(folder); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generation created a file before the save action", err)
	}
	request := vaultInput(t, map[string]any{"workspaceId": out.Plan.WorkspaceID})
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", request); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("unverified server allowed local key deletion", err)
	}
	foreign := vaultInput(t, map[string]any{"workspaceId": out.Plan.WorkspaceID, "path": "other-key"})
	if _, err := h.Handle(ctx, "shared-setup-save-server-kit", foreign); !errors.Is(err, vaultwire.ErrProtocol) {
		t.Fatal("renderer selected an arbitrary export path", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := saveSharedServerKit(cancelled, plan); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled export proceeded", err)
	}

	// The file publication can commit before a reply or the plan state write.
	// A retry must recognize the exact existing export, then retire staging.
	stage := serverKitStagePath(folder)
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, serverKeyName), key[:len(key)/2], 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveSharedServerKit(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("publication left a second copy of the staged key", err)
	}
	keyPath := filepath.Join(folder, serverKeyName)
	if err := os.WriteFile(keyPath, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-save-server-kit", request); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("retry overwrote conflicting content", err)
	}
	if unchanged, err := os.ReadFile(keyPath); err != nil || string(unchanged) != "foreign" {
		t.Fatal("conflicting content changed", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-save-server-kit", request); err != nil {
		t.Fatal(err)
	}
	assertServerKitPrivateFile(t, keyPath)
	saved, err := readSharedSetupPlan(path, protection)
	if err != nil || saved.ServerKit.State != serverKitSaved || len(saved.ServerKit.EncryptedKey) != 0 {
		t.Fatal("encrypted key remained staged after durable publication", err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", request); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("saving alone authorized deletion", err)
	}
	// The loopback integration exercises Check deployment's exact proof.
	// Here resume at that checkpoint and inject local filesystem conflicts.
	saved.ServerKit.State = serverKitVerified
	saved.Summary.State = setupSubmitted
	if err := writeSharedSetupPlan(path, saved, protection); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", request); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("replacement key was not protected", err)
	}
	if data, err := os.ReadFile(keyPath); err != nil || string(data) != "replacement" {
		t.Fatal("replacement key was removed or modified", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	retiring := filepath.Join(folder, retiredServerKey)
	if err := os.Rename(keyPath, retiring); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", request); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{keyPath, retiring} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retired key is present", err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(folder, "server.pem")); err != nil || string(data) != out.TLS.ServerPEM {
		t.Fatal("retirement changed the public certificate", err)
	}
	if state := setupTestCall(t, h, "plan", nil).ServerKit; state == nil || state.State != serverKitRemoved {
		t.Fatal("local key retirement did not survive reload")
	}
}

func useTemporaryServerKitCache(t *testing.T) {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "cache")
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LOCALAPPDATA", cache)
	case "linux":
		t.Setenv("XDG_CACHE_HOME", cache)
	default:
		t.Skip("fixture confines output to an overridden OS cache under the test directory")
	}
}

func TestSharedSetupServerKitRefusesConflictingPathsAndAllowsLostRemovalReply(t *testing.T) {
	useTemporaryServerKitCache(t)
	h, _ := sharedSetupTestHandler(t)
	input := map[string]any{
		"host": "127.0.0.1", "port": 5432, "database": "vault", "approvedHosts": []string{"127.0.0.1"},
		"accountPassword": []byte("synthetic-stage-password"), "keyPassphrase": []byte("synthetic-key-passphrase"),
	}
	reply := setupTestCall(t, h, "prepare-generated-tls", input)
	path := sharedSetupPlanPath(h.databasePath)
	plan, err := readSharedSetupPlan(path, h.startupProtection())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	foreign := *plan.ServerKit
	foreign.Folder = filepath.Join(t.TempDir(), plan.Summary.WorkspaceID)
	changed := plan
	changed.ServerKit = &foreign
	malformed := foreign
	malformed.Folder = "relative"
	if malformed.valid(plan.Summary.WorkspaceID) {
		t.Fatal("relative kit location passed plan validation")
	}
	malformed = *plan.ServerKit
	malformed.State = "unknown"
	if malformed.valid(plan.Summary.WorkspaceID) {
		t.Fatal("unknown kit state passed plan validation")
	}
	if err := saveSharedServerKit(ctx, changed); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("kit accepted another cache folder", err)
	}
	if err := discardUnpublishedServerKit(changed); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("discard followed another cache folder", err)
	}
	if err := deleteSharedSetupServerKey(changed); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("retirement followed another cache folder", err)
	}
	parent := filepath.Dir(reply.ServerKit.Folder)
	if err := os.WriteFile(parent, []byte("unrelated file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveSharedServerKit(ctx, plan); err == nil {
		t.Fatal("a non-directory cache root was accepted")
	}
	if got, err := os.ReadFile(parent); err != nil || string(got) != "unrelated file" {
		t.Fatal("cache collision modified unrelated bytes", err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	stage := serverKitStagePath(reply.ServerKit.Folder)
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(stage, "server.pem")
	if err := os.Mkdir(conflict, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveSharedServerKit(ctx, plan); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("directory at a staged file path was accepted", err)
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conflict, []byte("not the issued certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveSharedServerKit(ctx, plan); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("staged certificate was replaced despite conflict", err)
	}
	if err := discardUnpublishedServerKit(plan); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("discard removed a modified staged certificate", err)
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	payload := vaultInput(t, map[string]any{"workspaceId": plan.Summary.WorkspaceID})
	if _, err := h.Handle(ctx, "shared-setup-save-server-kit", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-save-server-kit", payload); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("saved kit authorized another publication", err)
	}
	saved, err := readSharedSetupPlan(path, h.startupProtection())
	if err != nil {
		t.Fatal(err)
	}
	saved.Summary.State = setupSubmitted
	saved.ServerKit.State = serverKitVerified
	if err := writeSharedSetupPlan(path, saved, h.startupProtection()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(saved.ServerKit.Folder, retiredServerKey), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", payload); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("competing retirement name was accepted", err)
	}
	if err := os.Remove(filepath.Join(saved.ServerKit.Folder, retiredServerKey)); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(saved.ServerKit.Folder, serverKeyName)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(key, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", payload); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("server key path accepted a directory", err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", payload); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("empty file was treated as the generated key", err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-delete-server-key", payload); err != nil {
		t.Fatal("verified removal did not reconcile an already absent key", err)
	}
	if _, err := os.Lstat(filepath.Join(saved.ServerKit.Folder, "postgresql-tls.conf")); err != nil {
		t.Fatal("removal touched configuration", err)
	}
}

func TestSharedSetupServerKitDiscardCleansOnlyItsPartialStage(t *testing.T) {
	useTemporaryServerKitCache(t)
	h, _ := sharedSetupTestHandler(t)
	input := map[string]any{
		"host": "127.0.0.1", "port": 5432, "database": "vault", "approvedHosts": []string{"127.0.0.1"},
		"accountPassword": []byte("synthetic-stage-password"), "keyPassphrase": []byte("synthetic-key-passphrase"),
	}
	reply := setupTestCall(t, h, "prepare-generated-tls", input)
	plan, err := readSharedSetupPlan(sharedSetupPlanPath(h.databasePath), h.startupProtection())
	if err != nil || reply.ServerKit == nil {
		t.Fatal("could not stage the pending plan", err)
	}
	stage := serverKitStagePath(reply.ServerKit.Folder)
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(stage, serverKeyName)
	if err := os.WriteFile(key, plan.ServerKit.EncryptedKey[:40], 0600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(stage, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := vaultInput(t, map[string]any{"workspaceId": plan.Summary.WorkspaceID})
	if _, err := h.Handle(ctx, "shared-setup-discard", payload); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("discard accepted unrelated content", err)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "keep" {
		t.Fatal("discard damaged unrelated content", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, "shared-setup-discard", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("discard left an untracked copy of the staged key", err)
	}
}
