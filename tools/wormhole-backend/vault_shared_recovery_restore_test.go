package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func TestSharedRecoveryRestoreChecksApprovedArchiveBeforeConnecting(t *testing.T) {
	snapshot := recoveryInspectionSnapshot(t)
	defer snapshot.Close()
	code, err := vault.FormatRecoveryKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(code)
	plain, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Wipe(plain)
	digest := sha256.Sum256(plain)
	envelope, err := encodeSharedRecoveryBackup(snapshot, code, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "archive.json")
	if err := os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	h := &vaultFoundationHandler{databasePath: filepath.Join(dir, "workspace.db")}
	request := func(override map[string]any) (string, error) {
		base := map[string]any{
			"path": path, "archiveDigest": hex.EncodeToString(digest[:]), "workspaceId": snapshot.WorkspaceID,
			"roleTag": "archive2", "host": "localhost", "port": 0, "database": "restore_fixture",
			"password": code, "deployerPassword": []byte("fixture-deployer"),
		}
		for field, value := range override {
			base[field] = value
		}
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		defer vault.Wipe(raw)
		reply, err := h.Handle(context.Background(), "shared-recovery-restore", raw)
		if err != nil {
			return "", err
		}
		var result string
		if err := json.Unmarshal(reply, &result); err != nil {
			t.Fatal("restore returned an unexpected receipt", err)
		}
		return result, nil
	}
	for _, tc := range []struct {
		override map[string]any
		want     string
	}{
		{map[string]any{"archiveDigest": hex.EncodeToString(make([]byte, 32))}, "archive-changed"},
		{map[string]any{"path": filepath.Join(dir, "missing.json")}, "invalid-backup"},
		{map[string]any{"password": bytes.Repeat([]byte{1}, 76)}, "invalid-password"},
		{map[string]any{"workspaceId": uuid.New()}, "rejected"},
		{nil, "rejected"},
	} {
		if got, err := request(tc.override); got != tc.want || err != nil {
			t.Fatal("unexpected restore result", got, err)
		}
	}
	for _, override := range []map[string]any{
		{"path": "relative.json"},
		{"roleTag": "wrong-tag"},
		{"deployerPassword": []byte{}},
		{"deployerPassword": []int{12, 13}},
		{"archiveDigest": string(bytes.Repeat([]byte{'g'}, 64))},
		{"confirmed": true},
	} {
		if _, err := request(override); !errors.Is(err, vaultwire.ErrProtocol) {
			t.Fatal("invalid archive apply request accepted", err)
		}
	}
	h.migrationQuiesced = true
	if _, err := request(nil); !errors.Is(err, vault.ErrPolicy) || !h.ExitOnCancel("shared-recovery-restore") {
		t.Fatal("restore escaped ownership and cancellation boundary", err)
	}
}

func TestSharedWorkspaceRestoreFailureKeepsUncertainty(t *testing.T) {
	for cause, status := range map[error]string{
		sharedpg.ErrWorkspaceRestoreLogging: "logging-enabled",
		sharedpg.ErrDeploymentUncertain:     "uncertain",
		context.Canceled:                    "uncertain",
		context.DeadlineExceeded:            "uncertain",
		sharedpg.ErrDeploymentRejected:      "rejected",
	} {
		if got := sharedWorkspaceRestoreFailure(cause); got != status {
			t.Fatalf("wrong restore failure for %v: %s", cause, got)
		}
	}
}
