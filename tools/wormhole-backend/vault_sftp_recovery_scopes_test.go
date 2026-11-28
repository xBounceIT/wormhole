package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/uuid"
)

func TestSFTPRecoveryScopePages(t *testing.T) {
	ctx, base, workspace := context.Background(), t.TempDir(), uuid.NewString()
	page, err := readSFTPRecoveryScopes(ctx, base, workspace, "")
	if err != nil || len(page.NodeIDs) != 0 || page.NodeIDs == nil {
		t.Fatal(page, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatal("discovery created directories")
	}
	root := filepath.Join(base, "vault-sftp-edit", workspace)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readSFTPRecoveryScopes(&editorCancelledContext{Context: ctx, after: 3}, base, uuid.NewString(), ""); err != context.Canceled {
		t.Fatal("cancellation after missing workspace ignored", err)
	}
	ids := []string{}
	for i := 0; i < 70; i++ {
		id := uuid.NewString()
		ids = append(ids, id)
		if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "not-a-node"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, uuid.NewString()), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	page, err = readSFTPRecoveryScopes(ctx, base, workspace, "")
	if err != nil || len(page.NodeIDs) != 64 || page.After != ids[63] {
		t.Fatal(page, err)
	}
	for i, id := range page.NodeIDs {
		if id != ids[i] {
			t.Fatal("unordered scope page")
		}
	}
	last, err := readSFTPRecoveryScopes(ctx, base, workspace, page.After)
	if err != nil || len(last.NodeIDs) != 6 || last.After != "" {
		t.Fatal(last, err)
	}
	for i, id := range last.NodeIDs {
		if id != ids[64+i] {
			t.Fatal("pagination skipped or repeated a scope")
		}
	}
	other, err := readSFTPRecoveryScopes(ctx, base, uuid.NewString(), "")
	if err != nil || len(other.NodeIDs) != 0 {
		t.Fatal("foreign workspace exposed", err)
	}
	if _, err := scanSFTPRecoveryScopes(ctx, base, workspace, "", 2); !errors.Is(err, errSealedSFTPEditsUnavailable) {
		t.Fatal("scan budget ignored", err)
	}
}

func TestSFTPRecoveryScopeErrors(t *testing.T) {
	base, workspace := t.TempDir(), uuid.NewString()
	for _, args := range [][3]string{{"relative", workspace, ""}, {base, "../escape", ""}, {base, workspace, "../escape"}} {
		if _, err := readSFTPRecoveryScopes(context.Background(), args[0], args[1], args[2]); err == nil {
			t.Fatal("unsafe scope accepted")
		}
	}
	if _, err := scanSFTPRecoveryScopes(context.Background(), base, workspace, "", 0); err == nil {
		t.Fatal("invalid budget accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readSFTPRecoveryScopes(cancelled, base, workspace, ""); err != context.Canceled {
		t.Fatal(err)
	}
	root := filepath.Join(base, "vault-sftp-edit")
	if err := os.WriteFile(root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSFTPRecoveryScopes(context.Background(), base, workspace, ""); err == nil {
		t.Fatal("non-directory traversed")
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, workspace), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSFTPRecoveryScopes(context.Background(), base, workspace, ""); err == nil {
		t.Fatal("invalid workspace directory traversed")
	}
}

func TestSFTPRecoveryScopeSymlink(t *testing.T) {
	base, workspace, outside := t.TempDir(), uuid.NewString(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "vault-sftp-edit")); err != nil {
		t.Skip("symlink creation unavailable:", err)
	}
	if _, err := readSFTPRecoveryScopes(context.Background(), base, workspace, ""); err == nil {
		t.Fatal("symlink traversed")
	}
}

func TestVaultRecoveryScopesEndpoint(t *testing.T) {
	ctx := context.Background()
	if _, err := (&vaultFoundationHandler{}).recoveryScopes(ctx, nil); err == nil {
		t.Fatal("locked owner admitted")
	}
	h := vaultCredentialFixture(t)
	h.userDataPath = t.TempDir()
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	node := uuid.NewString()
	if err := os.MkdirAll(filepath.Join(h.userDataPath, "vault-sftp-edit", workspace, node), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{nil, []byte(`{"after":""}`)} {
		raw, err := h.Handle(ctx, "sftp-recovery-scopes", payload)
		var got sftpRecoveryScopePage
		if err != nil || json.Unmarshal(raw, &got) != nil || len(got.NodeIDs) != 1 || got.NodeIDs[0] != node {
			t.Fatal(string(raw), err)
		}
	}
	for _, payload := range [][]byte{[]byte(`{}`), []byte(`{"after":null}`), []byte(`{"after":"../bad"}`), []byte(`{"after":"","workspaceId":"injected"}`), make([]byte, 129)} {
		if _, err := h.recoveryScopes(ctx, payload); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	if _, err := h.recoveryScopes(&editorCancelledContext{Context: ctx, after: 1}, nil); err != context.Canceled {
		t.Fatal(err)
	}
	h.userDataPath = "relative"
	if _, err := h.recoveryScopes(ctx, nil); err == nil {
		t.Fatal("untrusted root accepted")
	}
}
