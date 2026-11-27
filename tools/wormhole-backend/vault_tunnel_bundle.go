package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Only a main-owned native child may select this recipient. No ordinary renderer
// IPC exposes the route configuration, sealed packet or recipient-key selection.
func (h *vaultFoundationHandler) tunnelBundle(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.connectionTunnel(ctx, raw, "tunnel-bundle")
}
func (h *vaultFoundationHandler) tunnelPlan(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.connectionTunnel(ctx, raw, "tunnel-plan")
}
func (h *vaultFoundationHandler) connectionRoute(ctx context.Context, raw []byte) (json.RawMessage, error) {
	return h.connectionTunnel(ctx, raw, "connection-route")
}
func (h *vaultFoundationHandler) connectionTunnel(ctx context.Context, raw []byte, operation string) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 2048 {
		return nil, vaultwire.ErrProtocol
	}
	sealed := operation == "tunnel-bundle"
	var q localvault.TunnelBundleRequest
	var epoch string
	fields := map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch"}
	if sealed {
		fields["publicKey"] = &q.PublicKey
		required = append(required, "publicKey")
	}
	if decodeVaultObject(raw, fields, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || q.Plan().Validate() != nil || (sealed && q.Validate() != nil) {
		return nil, vaultwire.ErrProtocol
	}
	var value any
	if h.shared != nil {
		controller, e := h.sharedProtocolController(ctx)
		if e != nil {
			return nil, e
		}
		if sealed {
			value, err = controller.SealConnectionTunnel(ctx, q, h.shared.fileID, "ui")
		} else if operation == "connection-route" {
			value, err = controller.ResolveConnectionRoute(ctx, q.Plan(), h.shared.fileID)
		} else {
			value, err = controller.PlanConnectionTunnel(ctx, q.Plan(), h.shared.fileID)
		}
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(value)
	}
	if sealed {
		value, err = h.owner.SealConnectionTunnel(ctx, q)
	} else if operation == "connection-route" {
		value, err = h.owner.ResolveConnectionRoute(ctx, q.Plan())
	} else {
		value, err = h.owner.PlanConnectionTunnel(ctx, q.Plan())
	}
	if err != nil {
		return h.domainResult(nil, err)
	}
	return json.Marshal(value)
}
