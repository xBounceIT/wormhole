package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const sftpRecoveryScopePageSize = 64
const sftpRecoveryScopeScanLimit = 50000

type sftpRecoveryScopePage struct {
	NodeIDs []string `json:"nodeIds"`
	After   string   `json:"after"`
}

// The authenticated owner supplies workspaceID and the trusted startup path.
// This discovery pass neither acquires a child process's lease nor creates files.
func readSFTPRecoveryScopes(ctx context.Context, userDataPath, workspaceID, after string) (sftpRecoveryScopePage, error) {
	return scanSFTPRecoveryScopes(ctx, userDataPath, workspaceID, after, sftpRecoveryScopeScanLimit)
}

func scanSFTPRecoveryScopes(ctx context.Context, userDataPath, workspaceID, after string, limit int) (sftpRecoveryScopePage, error) {
	page := sftpRecoveryScopePage{NodeIDs: []string{}}
	if !filepath.IsAbs(userDataPath) || !vaultCredentialID(workspaceID) || (after != "" && !vaultCredentialID(after)) || limit < 1 {
		return page, errSealedSFTPEditsUnavailable
	}
	root := userDataPath
	for _, component := range []string{"vault-sftp-edit", workspaceID} {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		root = filepath.Join(root, component)
		info, err := os.Lstat(root)
		if errors.Is(err, os.ErrNotExist) {
			return page, ctx.Err()
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return page, errSealedSFTPEditsUnavailable
		}
	}
	directory, err := os.Open(root)
	if err != nil {
		return page, errSealedSFTPEditsUnavailable
	}
	defer directory.Close()
	ids := []string{}
	scanned := 0
	for {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			scanned++
			if scanned > limit {
				return page, errSealedSFTPEditsUnavailable
			}
			if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && vaultCredentialID(entry.Name()) && entry.Name() > after {
				ids = append(ids, entry.Name())
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return page, errSealedSFTPEditsUnavailable
		}
	}
	if err := ctx.Err(); err != nil {
		return page, err
	}
	sort.Strings(ids)
	if len(ids) > sftpRecoveryScopePageSize {
		ids = ids[:sftpRecoveryScopePageSize]
		page.After = ids[len(ids)-1]
	}
	page.NodeIDs = ids
	return page, nil
}

func (h *vaultFoundationHandler) recoveryScopes(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 128 {
		return nil, vaultwire.ErrProtocol
	}
	after := ""
	if len(payload) != 0 && decodeVaultObject(payload, map[string]any{"after": &after}, "after") != nil {
		return nil, vaultwire.ErrProtocol
	}
	if after != "" && !vaultCredentialID(after) {
		return nil, vaultwire.ErrProtocol
	}
	workspace, err := h.owner.WorkspaceID(ctx)
	if err != nil {
		return nil, err
	}
	page, err := readSFTPRecoveryScopes(ctx, h.userDataPath, workspace, after)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(page)
}
