package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/permissions"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type serialPermissionsSession interface {
	NodePermissions(context.Context, uuid.UUID) (permissions.Mask, error)
}

// Alive serial tabs need a server-side Use check even when their nodes are
// outside the current catalog page. This RPC never issues a new connection.
func (h *vaultFoundationHandler) checkSerialUse(ctx context.Context, raw []byte) (json.RawMessage, error) {
	var ids []string
	if len(raw) > 2048 || decodeVaultObject(raw, map[string]any{"nodeIds": &ids}, "nodeIds") != nil || len(ids) == 0 || len(ids) > 32 {
		return nil, vaultwire.ErrProtocol
	}
	nodes := make([]uuid.UUID, len(ids))
	seen := make(map[uuid.UUID]bool, len(ids))
	for i, id := range ids {
		if !vaultCredentialID(id) {
			return nil, vaultwire.ErrProtocol
		}
		node := uuid.MustParse(id)
		if seen[node] {
			return nil, vaultwire.ErrProtocol
		}
		seen[node], nodes[i] = true, node
	}
	c, err := h.sharedProtocolController(ctx)
	if err != nil {
		return nil, err
	}
	session, ok := c.session.(serialPermissionsSession)
	if !ok {
		return nil, vaultwire.ErrProtocol
	}
	current := make([]bool, len(nodes))
	err = c.withCatalogOperation(ctx, func(ctx context.Context, _ sharedpg.TrustState, _ *sharedpg.TrustState) error {
		for i, node := range nodes {
			mask, err := session.NodePermissions(ctx, node)
			if err != nil {
				return err
			}
			current[i] = mask&permissions.Use != 0
		}
		return nil
	}, nil, false)
	if err != nil {
		return nil, h.retire(err)
	}
	return json.Marshal(struct {
		Current []bool `json:"current"`
	}{current})
}

func (h *vaultFoundationHandler) serialBundle(ctx context.Context, raw []byte) (json.RawMessage, error) {
	if ctx == nil || len(raw) > 4096 || (h.shared == nil && h.owner == nil) {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelBundleRequest
	var epoch string
	var quickRaw json.RawMessage
	if decodeVaultObject(raw, map[string]any{
		"nodeId": &q.NodeID, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch,
		"publicKey": &q.PublicKey, "quick": &quickRaw,
	}, "nodeId", "sessionId", "requestId", "epoch", "publicKey") != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || q.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	if h.shared != nil {
		if len(quickRaw) != 0 {
			return nil, vault.ErrPolicy
		}
		c, err := h.sharedProtocolController(ctx)
		if err != nil {
			return nil, err
		}
		var result vault.SerialConnectionBundle
		err = c.withConnectionPlan(ctx, uuid.MustParse(q.NodeID), func(_ context.Context, current sharedpg.ResolvedConnectionPlan) error {
			p := current.Plan
			if p.NodeID != q.NodeID || p.Protocol != int(serialProtocolValue) || p.Credential.Kind != "none" || p.TunnelID != "" || p.Port != 0 || current.Tunnel != nil {
				return vault.ErrPolicy
			}
			b := vault.BundleBinding{WorkspaceID: c.trustBinding.WorkspaceID.String(), NodeID: q.NodeID, SessionID: q.SessionID,
				RequestID: q.RequestID, Epoch: q.Epoch, Protocol: "serial", Host: p.Host}
			result, err = vault.SealSerialConnection(q.PublicKey, b, current.SerialSettings)
			return err
		})
		if err != nil {
			return nil, h.retire(err)
		}
		return json.Marshal(result)
	}
	var quick *localvault.QuickSerialTarget
	if len(quickRaw) != 0 {
		quick = new(localvault.QuickSerialTarget)
		var settings json.RawMessage
		if decodeVaultObject(quickRaw, map[string]any{"portName": &quick.PortName, "settings": &settings}, "portName", "settings") != nil ||
			decodeVaultObject(settings, map[string]any{"baudRate": &quick.Settings.BaudRate, "dataBits": &quick.Settings.DataBits,
				"stopBits": &quick.Settings.StopBits, "parity": &quick.Settings.Parity, "flowControl": &quick.Settings.FlowControl,
			}, "baudRate", "dataBits", "stopBits", "parity", "flowControl") != nil {
			return nil, vaultwire.ErrProtocol
		}
	}
	result, err := h.owner.SealSerialConnection(ctx, q, quick)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
