package main

import (
	"context"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"time"
)

func (h *vaultFoundationHandler) releaseClipboard(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || len(raw) > 1024 {
		return nil, vaultwire.ErrProtocol
	}
	var id, request, version, field string
	var keyJSON json.RawMessage
	if decodeVaultObject(raw, map[string]any{"nodeId": &id, "requestId": &request, "rowVersion": &version, "field": &field, "publicKey": &keyJSON}, "nodeId", "requestId", "rowVersion", "field", "publicKey") != nil || !vaultCredentialID(id) || !vaultCredentialID(request) || (field != "username" && field != "domain" && field != "secret") {
		return nil, vaultwire.ErrProtocol
	}
	var key []byte
	revision, err := vaultCredentialRevision(version, false)
	if err != nil || len(keyJSON) == 0 || keyJSON[0] != '"' || json.Unmarshal(keyJSON, &key) != nil || len(key) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	ttl, err := h.clipboardTTL(ctx)
	if err != nil {
		return nil, err
	}
	result, err := h.owner.SealConnectionClipboard(ctx, id, request, revision, field, int(ttl/time.Second), key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
