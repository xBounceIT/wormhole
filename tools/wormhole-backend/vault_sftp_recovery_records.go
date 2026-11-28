package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type sftpRecoveryRecords struct {
	Edits       []sftpEditView `json:"edits"`
	After       string         `json:"after"`
	Busy        bool           `json:"busy"`
	RevealReady bool           `json:"revealReady,omitempty"`
}

// The lease covers manifest validation and discard. The desktop opens a folder
// only after the vault confirms that the requested recovery record exists.
// A live transport owns its scope exclusively; offline access never steals it.
func (h *vaultFoundationHandler) recoveryRecords(ctx context.Context, payload []byte) (json.RawMessage, error) {
	result := sftpRecoveryRecords{Edits: []sftpEditView{}}
	respond := func() (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	var node, operation, after, edit, decision string
	var header struct {
		Operation string `json:"operation"`
	}
	if h.owner == nil || len(payload) > 512 || json.Unmarshal(payload, &header) != nil {
		return nil, errSealedSFTPEditsUnavailable
	}
	fields := map[string]any{"nodeId": &node, "operation": &operation}
	required := []string{"nodeId", "operation"}
	switch header.Operation {
	case "list":
		fields["after"] = &after
	case "reveal":
		fields["editId"] = &edit
		required = append(required, "editId")
	case "discard":
		fields["editId"] = &edit
		fields["decision"] = &decision
		required = append(required, "editId", "decision")
	default:
		return nil, errSealedSFTPEditsUnavailable
	}
	if decodeVaultObject(payload, fields, required...) != nil || !vaultCredentialID(node) || (after != "" && !vaultCredentialID(after)) || (operation != "list" && !vaultCredentialID(edit)) || (operation == "discard" && decision != "discard") {
		return nil, errSealedSFTPEditsUnavailable
	}
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(h.userDataPath) {
		return nil, errSealedSFTPEditsUnavailable
	}
	root := h.userDataPath
	for _, part := range []string{"vault-sftp-edit", workspace, node, "sftp-edit"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		root = filepath.Join(root, part)
		info, err := os.Lstat(root)
		if errors.Is(err, os.ErrNotExist) && operation == "list" {
			return respond()
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errSealedSFTPEditsUnavailable
		}
	}
	lock := filepath.Join(filepath.Dir(root), ".owner.lock")
	if info, err := os.Lstat(lock); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errSealedSFTPEditsUnavailable
	}
	release, err := tryAcquireExclusiveFileLock(lock)
	if errors.Is(err, errExclusiveFileLockBusy) {
		result.Busy = true
		return respond()
	}
	if err != nil {
		return nil, errSealedSFTPEditsUnavailable
	}
	defer release()
	directory, err := os.Open(root)
	if err != nil {
		return nil, errSealedSFTPEditsUnavailable
	}
	defer directory.Close()
	entries, err := directory.ReadDir(1025)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 1024 {
		return nil, errSealedSFTPEditsUnavailable
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	budget := 256 * 1024
	found := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !vaultCredentialID(entry.Name()) {
			continue
		}
		if operation == "list" && entry.Name() <= after {
			continue
		}
		if operation != "list" && entry.Name() != edit {
			continue
		}
		path := filepath.Join(root, entry.Name())
		raw, err := sftpEditBytes(filepath.Join(path, "manifest.json"), 64*1024)
		if err != nil {
			continue
		}
		record := sftpEditRecord{}
		if json.Unmarshal(raw, &record) != nil || record.View.ID != entry.Name() || record.View.NodeID != node || !validSftpEditManifest(&record) {
			continue
		}
		if info, err := os.Lstat(filepath.Join(path, "files")); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		record.directory = path
		record.View.Recovered, record.View.State = true, "Recovered"
		if operation != "list" {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if operation == "discard" && record.remove() != nil {
				return nil, errSealedSFTPEditsUnavailable
			}
			result.RevealReady = operation == "reveal"
			found = true
			break
		}
		encoded, _ := json.Marshal(record.View)
		if len(result.Edits) == 32 || budget < len(encoded) {
			result.After = result.Edits[len(result.Edits)-1].ID
			break
		}
		budget -= len(encoded)
		result.Edits = append(result.Edits, record.View)
	}
	if operation != "list" && !found {
		return nil, errSealedSFTPEditsUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return respond()
}
