package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type vaultSharedChanges struct {
	Epoch     string   `json:"epoch"`
	ChangeSeq string   `json:"changeSeq"`
	Reset     bool     `json:"reset"`
	Nodes     []string `json:"nodes"`
}

func decodeSharedChangesRequest(payload []byte) (uint64, uint64, error) {
	var epoch, seq string
	if len(payload) > 256 || decodeVaultObject(payload, map[string]any{"epoch": &epoch, "changeSeq": &seq}, "epoch", "changeSeq") != nil {
		return 0, 0, vaultwire.ErrProtocol
	}
	e, err := strconv.ParseUint(epoch, 10, 63)
	s, err2 := strconv.ParseUint(seq, 10, 63)
	if err != nil || err2 != nil || strconv.FormatUint(e, 10) != epoch || strconv.FormatUint(s, 10) != seq || (e == 0 && s != 0) {
		return 0, 0, vaultwire.ErrProtocol
	}
	return e, s, nil
}

func (h *vaultFoundationHandler) sharedChanges(ctx context.Context, payload []byte) (json.RawMessage, error) {
	if ctx == nil || h.closed || h.owner != nil || h.shared == nil || h.shared.controller == nil || !h.shared.controller.Unlocked() {
		return nil, vaultwire.ErrProtocol
	}
	e, s, err := decodeSharedChangesRequest(payload)
	if err != nil {
		return nil, err
	}
	changes, err := h.shared.controller.CatalogChanges(ctx, e, s)
	if err != nil {
		return nil, h.retire(err)
	}
	result := vaultSharedChanges{Epoch: strconv.FormatUint(changes.Epoch, 10), ChangeSeq: strconv.FormatUint(changes.ChangeSeq, 10), Reset: changes.Reset, Nodes: make([]string, 0, len(changes.Nodes))}
	for _, id := range changes.Nodes {
		result.Nodes = append(result.Nodes, id.String())
	}
	if err := ctx.Err(); err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(result)
}
