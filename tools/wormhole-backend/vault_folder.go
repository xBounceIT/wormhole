package main

import (
	"context"
	"encoding/json"
	"math"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// The app's folder editor can change only these public fields. Starting with the
// authenticated stored row preserves hidden legacy settings and every secret.
func (h *vaultFoundationHandler) saveFolder(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 8192 {
		return nil, vaultwire.ErrProtocol
	}
	var request workspaceNodeWriteRequest
	var version string
	fields := map[string]any{"id": &request.ID, "rowVersion": &version, "parentId": &request.ParentID, "name": &request.Name, "sshAutoSudo": &request.SshAutoSudo, "tunnelEnabled": &request.TunnelEnabled, "tunnelConfigId": &request.TunnelConfigID, "credentialMode": &request.CredentialMode, "credentialId": &request.CredentialID}
	if decodeVaultNullableObject(payload, fields, map[string]bool{"sshAutoSudo": true, "tunnelEnabled": true}, "id", "rowVersion", "parentId", "name", "sshAutoSudo", "tunnelEnabled", "tunnelConfigId", "credentialMode", "credentialId") != nil {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, true)
	if err != nil || revision == math.MaxInt64 || (revision == 0) != (request.ID == "") || (request.ID != "" && !vaultCredentialID(request.ID)) || (request.ParentID != "" && !vaultCredentialID(request.ParentID)) || (request.TunnelConfigID != "" && !vaultCredentialID(request.TunnelConfigID)) || (request.CredentialID != "" && !vaultCredentialID(request.CredentialID)) || (request.CredentialMode != 2 && request.CredentialID != "") {
		return nil, vaultwire.ErrProtocol
	}
	if revision == 0 {
		request.ID = uuid.NewString()
	}
	request.Kind = "folder"
	// Folder normalization never queries the legacy database.
	normalized, err := normalizeWorkspaceNodeWrite(nil, request, true)
	if err != nil {
		return nil, vaultwire.ErrProtocol
	}
	m := vaultstore.NodeMetadata{ID: request.ID, Kind: 0}
	if revision != 0 {
		old, err := h.owner.ReadNode(ctx, request.ID, 0)
		if err != nil {
			return h.domainResult(nil, err)
		}
		if old.Kind != 0 || old.RowVersion != revision {
			return nil, vaultstore.ErrConflict
		}
		m = old.NodeMetadata
	} else {
		m.SortOrder, err = h.nextNodeSortOrder(ctx, request.ParentID)
		if err != nil {
			return h.domainResult(nil, err)
		}
	}
	m.ParentID = nil
	if request.ParentID != "" {
		m.ParentID = &request.ParentID
	}
	m.Name = normalized.name
	m.SshAutoSudo, m.TunnelEnabled = request.SshAutoSudo, request.TunnelEnabled
	m.CredentialMode, m.CredentialID, m.CredentialSlotID = &request.CredentialMode, nil, nil
	if request.CredentialID != "" {
		m.CredentialID = &request.CredentialID
	}
	m.TunnelConfigID = nil
	if request.TunnelConfigID != "" {
		m.TunnelConfigID = &request.TunnelConfigID
	}
	saved, err := h.owner.PutNode(ctx, m, nil, revision)
	return h.domainResult(struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{saved.ID, strconv.FormatUint(saved.RowVersion, 10), true}, err)
}

// The wire dispatcher serializes mutations for the exclusive workspace owner.
// Paging bounds memory and authenticates every position used to append a node.
func (h *vaultFoundationHandler) nextNodeSortOrder(ctx context.Context, parent string) (int64, error) {
	var next int64
	after, count := "", 0
	for {
		nodes, err := h.owner.ListNodes(ctx, after, 128)
		if err != nil {
			return 0, err
		}
		count += len(nodes)
		if count > 50000 {
			return 0, vaultwire.ErrProtocol
		}
		for _, node := range nodes {
			if ((node.ParentID == nil && parent == "") || (node.ParentID != nil && *node.ParentID == parent)) && node.SortOrder >= next {
				if node.SortOrder == math.MaxInt64 {
					return 0, vaultstore.ErrConflict
				}
				next = node.SortOrder + 1
			}
		}
		if len(nodes) < 128 {
			return next, nil
		}
		after = nodes[len(nodes)-1].ID
	}
}
