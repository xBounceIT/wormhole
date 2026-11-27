package main

import (
	"context"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"math"
	"strconv"
)

func (h *vaultFoundationHandler) moveNodes(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 512*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var raw []json.RawMessage
	var target json.RawMessage
	var placement string
	if decodeVaultObject(payload, map[string]any{"nodes": &raw, "target": &target, "placement": &placement}, "nodes", "target", "placement") != nil || len(raw) == 0 || len(raw) > 1000 || (placement != "inside" && placement != "before" && placement != "after") {
		return nil, vaultwire.ErrProtocol
	}
	seen := map[string]bool{}
	revisions := make([]vaultstore.NodeRevision, 0, len(raw)+1)
	for _, item := range append(raw, target) {
		var id, version string
		if decodeVaultObject(item, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) || seen[id] {
			return nil, vaultwire.ErrProtocol
		}
		revision, err := vaultCredentialRevision(version, false)
		if err != nil || revision >= math.MaxInt64 {
			return nil, vaultwire.ErrProtocol
		}
		seen[id] = true
		revisions = append(revisions, vaultstore.NodeRevision{ID: id, RowVersion: revision})
	}
	count, err := h.owner.MoveNodes(ctx, vaultstore.NodeMoveRequest{Nodes: revisions[:len(raw)], Target: revisions[len(raw)], Placement: placement})
	return h.domainResult(struct {
		Moved        bool   `json:"moved"`
		UpdatedCount string `json:"updatedCount"`
	}{true, strconv.FormatUint(count, 10)}, err)
}
