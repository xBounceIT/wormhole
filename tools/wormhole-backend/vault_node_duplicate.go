package main

import (
	"context"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"math"
)

func (h *vaultFoundationHandler) duplicateConnection(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if h.owner == nil || len(payload) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var id, version string
	if decodeVaultObject(payload, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) {
		return nil, vaultwire.ErrProtocol
	}
	revision, err := vaultCredentialRevision(version, false)
	if err != nil || revision >= math.MaxInt64 {
		return nil, vaultwire.ErrProtocol
	}
	n, err := h.owner.DuplicateConnection(ctx, id, revision)
	return h.domainResult(struct {
		NodeID     string `json:"nodeId"`
		Name       string `json:"name"`
		RowVersion string `json:"rowVersion"`
	}{n.ID, n.Name, "1"}, err)
}
