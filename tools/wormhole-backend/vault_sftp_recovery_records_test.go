package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func seedOfflineRecord(t *testing.T, h *vaultFoundationHandler, node string) *sftpEditRecord {
	t.Helper()
	workspace, err := h.owner.WorkspaceID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record := &sftpEditRecord{View: sftpEditView{ID: uuid.NewString(), NodeID: node, SessionID: uuid.NewString(), Name: "file.txt", RemotePath: "/file.txt", Editor: "fixture"}, Host: "server", Port: 22, Username: "user", Fingerprint: "fixture-pin", Route: "direct", UploadedHash: sftpEditHash([]byte("original")), Mode: 0o600, BaseSize: 8}
	record.directory = filepath.Join(h.userDataPath, "vault-sftp-edit", workspace, node, "sftp-edit", record.View.ID)
	if err := os.MkdirAll(filepath.Join(record.directory, "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record.localPath(), []byte("unsent content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := record.save(); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestVaultOfflineRecoveryRecords(t *testing.T) {
	h := vaultCredentialFixture(t)
	h.userDataPath = t.TempDir()
	node := uuid.NewString()
	ctx := context.Background()
	query := func(q map[string]any) sftpRecoveryRecords {
		t.Helper()
		raw, err := h.Handle(ctx, "sftp-recovery-records", vaultInput(t, q))
		var result sftpRecoveryRecords
		if err != nil || json.Unmarshal(raw, &result) != nil {
			t.Fatal(string(raw), err)
		}
		return result
	}
	if got := query(map[string]any{"nodeId": node, "operation": "list"}); len(got.Edits) != 0 || got.Busy {
		t.Fatal(got)
	}
	if entries, _ := os.ReadDir(h.userDataPath); len(entries) != 0 {
		t.Fatal("read created directories")
	}
	records := []*sftpEditRecord{}
	for i := 0; i < 35; i++ {
		records = append(records, seedOfflineRecord(t, h, node))
	}
	first := query(map[string]any{"nodeId": node, "operation": "list"})
	if len(first.Edits) != 32 || first.After == "" {
		t.Fatal(first)
	}
	second := query(map[string]any{"nodeId": node, "operation": "list", "after": first.After})
	if len(second.Edits) != 3 || second.After != "" || second.Edits[0].ID <= first.After {
		t.Fatal(second)
	}
	if got := query(map[string]any{"nodeId": uuid.NewString(), "operation": "list"}); len(got.Edits) != 0 {
		t.Fatal("foreign node exposed")
	}
	workspace, _ := h.owner.WorkspaceID(ctx)
	release, err := tryAcquireExclusiveFileLock(filepath.Join(h.userDataPath, "vault-sftp-edit", workspace, node, ".owner.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if got := query(map[string]any{"nodeId": node, "operation": "reveal", "editId": records[0].View.ID}); !got.Busy || got.RevealReady || len(got.Edits) != 0 {
		t.Fatal("active scope authorized a reveal")
	}
	release()
	if got := query(map[string]any{"nodeId": node, "operation": "reveal", "editId": records[0].View.ID}); !got.RevealReady || got.Busy || got.After != "" || len(got.Edits) != 0 {
		t.Fatalf("wrong reveal authorization: %+v", got)
	}
	if got := query(map[string]any{"nodeId": node, "operation": "discard", "editId": records[0].View.ID, "decision": "discard"}); got.RevealReady || got.Busy {
		t.Fatalf("wrong discard result: %+v", got)
	}
	if _, err := os.Stat(records[0].directory); !os.IsNotExist(err) {
		t.Fatal("discard did not remove copy")
	}
	if _, err := os.Stat(records[1].directory); err != nil {
		t.Fatal("discard affected another copy")
	}
	for _, q := range []map[string]any{
		{"nodeId": node, "operation": "discard", "editId": records[1].View.ID},
		{"nodeId": node, "operation": "reveal", "editId": uuid.NewString()},
		{"nodeId": node, "operation": "reveal", "editId": records[1].View.ID, "path": "injected"},
		{"nodeId": "../escape", "operation": "list"}, {"nodeId": node, "operation": "list", "after": "../escape"},
		{"nodeId": node, "operation": "recover", "editId": records[1].View.ID},
	} {
		if _, err := h.recoveryRecords(ctx, vaultInput(t, q)); err == nil {
			t.Fatal("invalid action accepted", q)
		}
	}
	if _, err := (&vaultFoundationHandler{}).recoveryRecords(ctx, nil); err == nil {
		t.Fatal("locked owner admitted")
	}
	if _, err := h.recoveryRecords(ctx, make([]byte, 513)); err == nil {
		t.Fatal("oversized request admitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.recoveryRecords(cancelled, vaultInput(t, map[string]any{"nodeId": node, "operation": "list"})); err != context.Canceled {
		t.Fatal(err)
	}
	// Long paths produce a bounded page with an explicit continuation.
	for _, r := range records[1:] {
		r.View.RemotePath = "/" + strings.Repeat("x", 16000)
		if err := r.save(); err != nil {
			t.Fatal(err)
		}
	}
	large := query(map[string]any{"nodeId": node, "operation": "list"})
	if len(large.Edits) >= 32 || large.After == "" {
		t.Fatal("byte budget ignored")
	}
	// Missing copies and malformed private paths fail closed on mutation.
	if _, err := h.recoveryRecords(ctx, vaultInput(t, map[string]any{"nodeId": uuid.NewString(), "operation": "discard", "editId": uuid.NewString(), "decision": "discard"})); err == nil {
		t.Fatal("missing copy silently discarded")
	}
	h.userDataPath = "relative"
	if _, err := h.recoveryRecords(ctx, vaultInput(t, map[string]any{"nodeId": node, "operation": "list"})); !errors.Is(err, errSealedSFTPEditsUnavailable) {
		t.Fatal(err)
	}
}
