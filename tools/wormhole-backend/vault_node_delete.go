package main

import (
	"context"
	"encoding/json"
	"math"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func (h *vaultFoundationHandler) deleteNodeTrees(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 512*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var raw []json.RawMessage
	if decodeVaultObject(payload, map[string]any{"nodes": &raw}, "nodes") != nil || len(raw) == 0 || len(raw) > vaultstore.MaxNodeDeleteRoots {
		return nil, vaultwire.ErrProtocol
	}
	targets := make([]vaultstore.NodeRevision, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		var id, version string
		if decodeVaultObject(item, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) || seen[id] {
			return nil, vaultwire.ErrProtocol
		}
		revision, err := vaultCredentialRevision(version, false)
		if err != nil || revision >= math.MaxInt64 {
			return nil, vaultwire.ErrProtocol
		}
		seen[id] = true
		targets = append(targets, vaultstore.NodeRevision{ID: id, RowVersion: revision})
	}
	count, err := h.owner.DeleteNodeTrees(ctx, targets)
	return h.domainResult(struct {
		Deleted      bool   `json:"deleted"`
		DeletedCount string `json:"deletedCount"`
	}{true, strconv.FormatUint(count, 10)}, err)
}
