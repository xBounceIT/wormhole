package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Main checks only the generations attached to its live browser owners. This
// is a read of the current View registry, not a new registration or a resolver
// request that would retire the admission on an expected permission denial.
func (h *vaultFoundationHandler) verifyWebSessionViews(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if len(raw) > 4096 {
		return nil, vaultwire.ErrProtocol
	}
	var entries []json.RawMessage
	if decodeVaultObject(raw, map[string]any{"views": &entries}, "views") != nil ||
		len(entries) == 0 || len(entries) > sharedpg.MaxTreePage {
		return nil, vaultwire.ErrProtocol
	}
	type view struct{ node, generation uuid.UUID }
	pins := make([]view, 0, len(entries))
	nodes := make([]uuid.UUID, 0, len(entries))
	seen := make(map[uuid.UUID]struct{}, len(entries))
	for _, entry := range entries {
		var nodeID, generationID string
		if decodeVaultObject(entry, map[string]any{"nodeId": &nodeID, "generation": &generationID}, "nodeId", "generation") != nil ||
			!vaultCredentialID(nodeID) || !vaultCredentialID(generationID) {
			return nil, vaultwire.ErrProtocol
		}
		node := uuid.MustParse(nodeID)
		pins = append(pins, view{node, uuid.MustParse(generationID)})
		if _, ok := seen[node]; !ok {
			seen[node] = struct{}{}
			nodes = append(nodes, node)
		}
	}
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return nil, err
	}
	current := make([]bool, len(entries))
	err = c.withCatalogOperation(ctx, func(context.Context, sharedpg.TrustState, *sharedpg.TrustState) error {
		return nil
	}, func(ctx context.Context, _ sharedpg.TrustState) error {
		session, err := c.webViewSession(ctx)
		if err != nil || session == nil {
			return err
		}
		generations, err := session.CheckWebSessionViews(ctx, nodes)
		if err != nil {
			return err
		}
		for i, pin := range pins {
			current[i] = generations[pin.node] == pin.generation
		}
		return nil
	}, true)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		Current []bool `json:"current"`
	}{current})
}
