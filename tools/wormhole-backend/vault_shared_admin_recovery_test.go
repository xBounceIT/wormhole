package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestVaultAdministratorRecoveryValidatesBeforeJoining(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "workspace.db")
	code, err := vault.FormatRecoveryKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"workspaceId": "11111111-1111-4111-8111-111111111111", "host": "localhost", "port": 5432,
		"database": "test", "role": "wh_testrole_deployer", "kitPath": filepath.Join(dir, "team.whrecovery"),
		"trustPath": filepath.Join(dir, "team.whtls"), "loginName": "recovered", "deviceName": "device",
		"appVersion": "2.4.3", "confirmed": true, "recoveryCode": code, "deployerPassword": []byte("dba"),
		"accountPassword": []byte("synthetic"), "ask": bytes.Repeat([]byte{42}, 32),
	}
	encode := func() []byte {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const op = "shared-admin-recover"
	ctx := context.Background()
	h := &vaultFoundationHandler{databasePath: root}
	for field, bad := range map[string]any{
		"confirmed": false, "workspaceId": "unknown", "kitPath": "relative.whrecovery", "trustPath": filepath.Join(dir, "other.json"),
		"recoveryCode": []byte("short"), "deployerPassword": 5, "accountPassword": []byte{0}, "ask": []byte{1},
		"deviceName": "line\nbreak", "appVersion": "not a version",
	} {
		t.Run(field, func(t *testing.T) {
			good := input[field]
			input[field] = bad
			defer func() { input[field] = good }()
			if _, err := h.Handle(ctx, op, encode()); !errors.Is(err, vaultwire.ErrProtocol) {
				t.Fatal("invalid recovery request reached the workspace", err)
			}
		})
	}
	if _, err := h.Handle(ctx, op, encode()); !errors.Is(err, errSharedTrustMissing) {
		t.Fatal("recovery contacted the deployer despite the missing kit", err)
	}
	if err := os.WriteFile(input["kitPath"].(string), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, op, encode()); !errors.Is(err, errSharedTrustMissing) {
		t.Fatal("recovery contacted the deployer despite the missing TLS bundle", err)
	}
	if err := os.WriteFile(root, []byte("existing workspace"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(ctx, op, encode()); !errors.Is(err, vaultstore.ErrConflict) {
		t.Fatal("recovery could replace an existing local database", err)
	}
	if raw, err := os.ReadFile(root); err != nil || string(raw) != "existing workspace" {
		t.Fatal("the legacy workspace was modified", err)
	}
	if _, err := os.Lstat(sharedAdminRecoveryPath(root)); !errors.Is(err, os.ErrNotExist) || !h.ExitOnCancel(op) {
		t.Fatal("a refused recovery staged a checkpoint or could survive cancellation", err)
	}
}
