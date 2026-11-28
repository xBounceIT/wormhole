package main

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Main-only endpoint. The ordinary renderer cannot choose a recipient key.
func (h *vaultFoundationHandler) displayNotes(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.displayNodeSecret(ctx, raw, false)
}

func (h *vaultFoundationHandler) displayCredentials(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.displayNodeSecret(ctx, raw, true)
}

func (h *vaultFoundationHandler) displayNodeSecret(ctx context.Context, raw []byte, credentials bool) (json.RawMessage, error) {
	if h.closed || len(raw) > 1024 ||
		(h.owner == nil && (credentials || h.shared == nil || h.shared.controller == nil || !h.shared.controller.Unlocked())) {
		return nil, vaultwire.ErrProtocol
	}
	var id, request, version string
	var keyJSON json.RawMessage
	if decodeVaultObject(raw, map[string]any{"nodeId": &id, "requestId": &request, "rowVersion": &version, "publicKey": &keyJSON}, "nodeId", "requestId", "rowVersion", "publicKey") != nil || !vaultCredentialID(id) || !vaultCredentialID(request) {
		return nil, vaultwire.ErrProtocol
	}
	var key []byte
	revision, err := vaultCredentialRevision(version, false)
	if err != nil || len(keyJSON) == 0 || keyJSON[0] != '"' || json.Unmarshal(keyJSON, &key) != nil || len(key) != 32 {
		return nil, vaultwire.ErrProtocol
	}
	var result localvault.NotesDisplay
	if credentials {
		result, err = h.owner.SealConnectionCredentials(ctx, id, request, revision, key)
	} else if h.owner != nil {
		result, err = h.owner.SealNodeNotes(ctx, id, request, revision, key)
	} else {
		result, err = h.shared.controller.sealNodeNotes(ctx, uuid.MustParse(id), request, revision, key)
		if err != nil && !h.shared.controller.Unlocked() {
			return nil, h.retire(err)
		}
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
