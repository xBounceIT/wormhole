package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedSetupAdministratorRejectsUnauthorizedAndMalformedRequests(t *testing.T) {
	h, request := sharedSetupTestHandler(t)
	plan := setupTestCall(t, h, "prepare", request).Plan
	if _, err := h.Handle(context.Background(), "shared-setup-admin-open", vaultInput(t, map[string]any{"workspaceId": plan.WorkspaceID, "accountPassword": []byte("synthetic")})); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("administrator setup started without a deployed workspace", err)
	}
	path := sharedSetupPlanPath(h.databasePath)
	if pending, err := sharedAdminCheckpointExists(path); err != nil || pending {
		t.Fatal("unexpected administrator checkpoint", err)
	}
	if err := os.Mkdir(sharedAdminCheckpointPath(path), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Handle(context.Background(), "shared-setup-plan", nil); !errors.Is(err, errSharedTrustStorage) {
		t.Fatal("mutable checkpoint directory was accepted", err)
	}
	if _, err := h.Handle(context.Background(), "shared-setup-discard", vaultInput(t, map[string]any{"workspaceId": plan.WorkspaceID})); !errors.Is(err, errSharedTrustConflict) {
		t.Fatal("plan discard hid an existing administrator checkpoint", err)
	}
	operation := "shared-setup-admin-prepare"
	valid := map[string]any{"workspaceId": plan.WorkspaceID, "accountPassword": []byte("synthetic-account"), "ask": bytes.Repeat([]byte{9}, 32), "password": []byte("synthetic-dba"), "role": "dba", "loginName": "alice", "profile": "default"}
	factors, err := decodeSharedAdminSetup(operation, vaultInput(t, valid), plan.WorkspaceID)
	if err != nil || factors.profile != vault.Default || factors.login != "alice" || len(factors.ask) != 32 {
		t.Fatal("valid administrator factors were rejected", err)
	}
	factors.wipe()
	for _, value := range [][]byte{factors.account, factors.dba, factors.ask} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("administrator factors survived cleanup")
		}
	}
	for _, invalid := range []map[string]any{
		{"workspaceId": "elsewhere"}, {"password": []byte{0}}, {"password": []byte{255}}, {"password": "!"},
		{"accountPassword": []byte{}}, {"accountPassword": []byte(nil)}, {"accountPassword": make([]byte, 1025)}, {"ask": []byte{0}},
		{"recipient": []byte{3}}, {"appVersion": "9.9.9"}, {"path": filepath.Join(filepath.Dir(path), "wrong.whrecovery")},
	} {
		request := make(map[string]any, len(valid)+len(invalid))
		for key, value := range valid {
			request[key] = value
		}
		for key, value := range invalid {
			request[key] = value
		}
		if _, err := decodeSharedAdminSetup(operation, vaultInput(t, request), plan.WorkspaceID); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid administrator request accepted", err)
		}
	}
}
