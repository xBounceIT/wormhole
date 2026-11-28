package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/sharedpg"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func decodeSSHHostPlan(raw []byte) (localvault.SSHHostPlan, error) {
	var p localvault.SSHHostPlan
	var binding json.RawMessage
	if decodeVaultObject(raw, map[string]any{"binding": &binding, "fileId": &p.FileID, "revision": &p.Revision, "fingerprint": &p.Fingerprint}, "binding", "fileId", "revision", "fingerprint") != nil {
		return p, vaultwire.ErrProtocol
	}
	b := &p.Binding
	if decodeVaultObject(binding, map[string]any{"workspaceId": &b.WorkspaceID, "sessionId": &b.SessionID, "requestId": &b.RequestID, "nodeId": &b.NodeID, "protocol": &b.Protocol, "host": &b.Host, "port": &b.Port, "tunnelConfigId": &b.TunnelConfigID, "useExternalClient": &b.UseExternalClient, "epoch": &b.Epoch}, "workspaceId", "sessionId", "requestId", "nodeId", "protocol", "host", "port", "tunnelConfigId", "useExternalClient", "epoch") != nil {
		return p, vaultwire.ErrProtocol
	}
	return p, nil // exact comparison with the native current plan validates values
}

// These operations are main-only. Neither a renderer-selected pin nor a generic
// trust mutation is exposed through preload. Standard requires fresh-action.
func (h *vaultFoundationHandler) sshHost(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	return h.sshHostAction(ctx, operation, raw, nil)
}

func (h *vaultFoundationHandler) sshHostAction(ctx context.Context, operation string, raw []byte, auth *vaultUnlockInput) (json.RawMessage, error) {
	if (h.owner == nil && h.shared == nil) || len(raw) > 16384 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.TunnelPlanRequest
	var epoch, received string
	var routeRaw, expectedRaw json.RawMessage
	fields := map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "route": &routeRaw}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "route"}
	if operation != "ssh-host-plan" {
		fields["expected"], fields["received"] = &expectedRaw, &received
		required = append(required, "expected", "received")
	}
	if decodeVaultNullableObject(raw, fields, map[string]bool{"route": true}, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || q.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	var route *vault.TunnelBundleBinding
	if string(routeRaw) != "null" {
		b, err := decodeTunnelBundleBinding(routeRaw)
		if err != nil {
			return nil, err
		}
		route = &b
	}
	if h.shared != nil {
		if q.CredentialOverride != "" || (operation != "ssh-host-plan" && operation != "shared-ssh-host-trust") {
			return nil, vault.ErrPolicy
		}
		controller, e := h.sharedProtocolController(ctx)
		if e != nil {
			return nil, e
		}
		if !vaultCredentialID(h.shared.fileID) {
			return nil, vaultwire.ErrProtocol
		}
		p, e := controller.PlanConnection(ctx, uuid.MustParse(q.NodeID))
		if e != nil {
			return nil, h.retire(e)
		}
		current, e := sharedHostPlan(controller.trustBinding.WorkspaceID, h.shared.fileID, p, q, route)
		if e != nil {
			return nil, e
		}
		if operation == "ssh-host-plan" {
			return json.Marshal(current)
		}
		expected, e := decodeSSHHostPlan(expectedRaw)
		if e != nil {
			return nil, e
		}
		if expected != current || !vault.ValidSSHFingerprint(received) || received == current.Fingerprint {
			return nil, vault.ErrPolicy
		}
		return h.commitSharedSSHHost(ctx, controller, p, received, auth)
	}
	if operation == "ssh-host-plan" {
		p, err := h.owner.PlanSSHHost(ctx, q, route)
		return h.domainResult(p, err)
	}
	expected, err := decodeSSHHostPlan(expectedRaw)
	if err != nil {
		return nil, err
	}
	if operation == "ssh-quick-host-trust" {
		result, err := h.owner.TrustQuickSSHHost(ctx, q, route, expected, received)
		return h.domainResult(result, err)
	}
	node, err := h.owner.TrustSSHHost(ctx, q, route, expected, received)
	return h.domainResult(struct {
		NodeID     string `json:"nodeId"`
		RowVersion string `json:"rowVersion"`
		Updated    bool   `json:"updated"`
	}{node.ID, strconv.FormatUint(node.RowVersion, 10), true}, err)
}

func sharedHostPlan(workspace uuid.UUID, fileID string, p sharedpg.ResolvedConnectionPlan, q localvault.TunnelPlanRequest, route *vault.TunnelBundleBinding) (localvault.SSHHostPlan, error) {
	if route != nil {
		current, err := sharedTunnelBinding(workspace, fileID, p.Plan, q, p.Tunnel)
		if err != nil {
			return localvault.SSHHostPlan{}, err
		}
		if current != *route {
			return localvault.SSHHostPlan{}, vault.ErrPolicy
		}
	}
	b, err := sharedSSHRouteBinding(workspace, p.Plan, q, route != nil)
	if err != nil {
		return localvault.SSHHostPlan{}, err
	}
	if p.Plan.HostKeyFingerprint != "" && !vault.ValidSSHFingerprint(p.Plan.HostKeyFingerprint) {
		return localvault.SSHHostPlan{}, vault.ErrPolicy
	}
	return localvault.SSHHostPlan{Binding: b, FileID: fileID, Revision: p.Revision, Fingerprint: p.Plan.HostKeyFingerprint}, nil
}
