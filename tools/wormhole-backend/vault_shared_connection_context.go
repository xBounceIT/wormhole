package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Public presentation context only. Go resolves inherited protocols under the
// current signed metadata snapshot and Use authorization, without secret release.
func (h *vaultFoundationHandler) sharedConnectionContext(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h.shared == nil || len(raw) > 256 {
		return nil, vaultwire.ErrProtocol
	}
	var node string
	if decodeVaultObject(raw, map[string]any{"nodeId": &node}, "nodeId") != nil || !vaultCredentialID(node) {
		return nil, vaultwire.ErrProtocol
	}
	controller, err := h.sharedProtocolController(ctx)
	if err != nil {
		return nil, err
	}
	result, err := controller.PlanConnection(ctx, uuid.MustParse(node))
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		NodeID   string `json:"nodeId"`
		Protocol int    `json:"protocol"`
	}{NodeID: node, Protocol: result.Plan.Protocol})
}
