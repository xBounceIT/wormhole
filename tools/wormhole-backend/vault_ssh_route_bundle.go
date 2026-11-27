package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Main binds the endpoint to its native route lease. Neither endpoint selection
// nor a recipient key is accepted through renderer IPC.
func (h *vaultFoundationHandler) sshRouteBundle(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 8192 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.SSHBundleRequest
	var epoch, endpoint string
	var routeRaw json.RawMessage
	if decodeVaultObject(raw, map[string]any{"sftpOnly": &q.SFTPOnly, "nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "publicKey": &q.PublicKey, "route": &routeRaw, "endpoint": &endpoint}, "nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "publicKey", "route", "endpoint") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	request := localvault.TunnelBundleRequest{NodeID: q.NodeID, CredentialOverride: q.CredentialOverride, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch, PublicKey: q.PublicKey}
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || request.Validate() != nil || !vault.ValidRouteEndpoint(endpoint) {
		return nil, vaultwire.ErrProtocol
	}
	route, err := decodeTunnelBundleBinding(routeRaw)
	if err != nil {
		return nil, err
	}
	if h.shared != nil {
		c, err := h.sharedProtocolController(ctx)
		if err != nil {
			return nil, err
		}
		result, err := c.SealRoutedSSHConnection(ctx, q, route, endpoint, h.shared.fileID, "ui")
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(result)
	}
	result, err := h.owner.SealRoutedSSHConnection(ctx, q, route, endpoint)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
