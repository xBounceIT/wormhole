package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Native/main-only. Never expose ciphertext or recipient-key selection through
// a renderer IPC: main must bind this key to the child it just spawned.
func (h *vaultFoundationHandler) sshBundle(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 2048 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.SSHBundleRequest
	var epoch string
	if decodeVaultObject(raw, map[string]any{"sftpOnly": &q.SFTPOnly, "nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "publicKey": &q.PublicKey}, "nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "publicKey") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch {
		return nil, vaultwire.ErrProtocol
	}
	var result localvault.SSHConnectionBundle
	if h.shared != nil {
		controller, e := h.sharedProtocolController(ctx)
		if e != nil {
			return nil, e
		}
		result, err = controller.SealSSHConnection(ctx, q, "ui")
		if err != nil && !controller.Unlocked() {
			return nil, h.retire(err)
		}
	} else {
		result, err = h.owner.SealSSHConnection(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
