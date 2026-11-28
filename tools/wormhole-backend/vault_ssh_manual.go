package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// This API is native/main-only. The ordinary renderer cannot supply a recipient
// key, authenticated snapshot, route endpoint, or document credential envelope.
func (h *vaultFoundationHandler) sshManual(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if h.owner == nil || h.shared != nil || len(raw) > 3*1024*1024 {
		return nil, vaultwire.ErrProtocol
	}
	var q localvault.SSHBundleRequest
	var epoch, mode, endpoint string
	var sftpOnly *bool
	var routeRaw, expectedRaw, envelope json.RawMessage
	fields := map[string]any{"nodeId": &q.NodeID, "credentialOverride": &q.CredentialOverride, "sessionId": &q.SessionID, "requestId": &q.RequestID, "epoch": &epoch, "mode": &mode, "sftpOnly": &sftpOnly, "route": &routeRaw}
	required := []string{"nodeId", "credentialOverride", "sessionId", "requestId", "epoch", "mode", "sftpOnly", "route"}
	if operation == "ssh-manual-bundle" {
		fields["publicKey"], fields["expected"], fields["manual"], fields["endpoint"] = &q.PublicKey, &expectedRaw, &envelope, &endpoint
		required = append(required, "publicKey", "expected", "manual", "endpoint")
	} else if operation != "ssh-manual-plan" {
		return nil, vaultwire.ErrProtocol
	}
	if decodeVaultNullableObject(raw, fields, map[string]bool{"route": true}, required...) != nil || sftpOnly == nil || (mode != "account" && mode != "passphrase") {
		return nil, vaultwire.ErrProtocol
	}
	q.SFTPOnly = *sftpOnly
	var err error
	q.Epoch, err = strconv.ParseUint(epoch, 10, 64)
	planRequest := localvault.TunnelPlanRequest{NodeID: q.NodeID, CredentialOverride: q.CredentialOverride, SessionID: q.SessionID, RequestID: q.RequestID, Epoch: q.Epoch}
	if err != nil || strconv.FormatUint(q.Epoch, 10) != epoch || planRequest.Validate() != nil {
		return nil, vaultwire.ErrProtocol
	}
	var route *vault.TunnelBundleBinding
	if string(routeRaw) != "null" {
		b, e := decodeTunnelBundleBinding(routeRaw)
		if e != nil {
			return nil, e
		}
		route = &b
	}
	if operation == "ssh-manual-plan" {
		result, e := h.owner.PlanManualSSHConnection(ctx, planRequest, route, mode, q.SFTPOnly)
		if e != nil {
			return nil, e
		}
		return json.Marshal(result)
	}
	var expected localvault.SSHManualPlan
	var hostRaw json.RawMessage
	if decodeVaultObject(expectedRaw, map[string]any{"host": &hostRaw, "mode": &expected.Mode, "autoSudo": &expected.AutoSudo, "sftpOnly": &expected.SFTPOnly}, "host", "mode", "autoSudo", "sftpOnly") != nil || expected.Mode != mode || expected.SFTPOnly != q.SFTPOnly {
		return nil, vaultwire.ErrProtocol
	}
	expected.Host, err = decodeSSHHostPlan(hostRaw)
	if err != nil {
		return nil, err
	}
	var inner vault.SealedBundle
	if decodeVaultObject(envelope, map[string]any{"formatVersion": &inner.FormatVersion, "suiteId": &inner.SuiteID, "enc": &inner.Enc, "ciphertext": &inner.Ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return nil, vaultwire.ErrProtocol
	}
	result, err := h.owner.SealManualSSHConnection(ctx, q, expected, route, endpoint, inner)
	if err != nil {
		return nil, err
	}
	if route != nil {
		return json.Marshal(localvault.RoutedSSHConnectionBundle{SFTPOnly: q.SFTPOnly, Binding: *route, Endpoint: endpoint, Bundle: result.Bundle})
	}
	return json.Marshal(result)
}
