package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"strconv"
	"strings"
)

// Main/native-only. Targets live in this unlocked local owner. Shared targets
// require audited server admission, never a local bypass.
func (h *vaultFoundationHandler) quickTarget(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if ctx == nil || h.owner == nil || h.shared != nil || len(raw) > 32768 {
		return nil, vaultwire.ErrProtocol
	}
	var session, epoch, id, workspace string
	var target json.RawMessage
	fields := map[string]any{"sessionId": &session, "epoch": &epoch}
	required := []string{"sessionId", "epoch"}
	switch operation {
	case "quick-target-register":
		fields["target"] = &target
		required = append(required, "target")
	case "quick-target-release":
		fields["id"] = &id
		fields["workspaceId"] = &workspace
		required = append(required, "id", "workspaceId")
	default:
		return nil, vaultwire.ErrProtocol
	}
	if decodeVaultObject(raw, fields, required...) != nil {
		return nil, vaultwire.ErrProtocol
	}
	number, err := strconv.ParseUint(epoch, 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != epoch {
		return nil, vaultwire.ErrProtocol
	}
	if operation == "quick-target-release" {
		err = h.owner.ReleaseQuickTarget(ctx, localvault.QuickTargetRef{WorkspaceID: workspace, ID: id, SessionID: session, Epoch: number})
		if errors.Is(err, localvault.ErrQuickTargetInput) {
			return nil, vaultwire.ErrProtocol
		}
		return h.domainResult(struct {
			Released bool `json:"released"`
		}{true}, err)
	}
	var q localvault.QuickConnectionTarget
	var rdp json.RawMessage
	targets := map[string]any{"protocol": &q.Protocol, "host": &q.Host, "port": &q.Port, "credentialId": &q.CredentialID, "tunnelId": &q.TunnelID, "sshAutoSudo": &q.SSHAutoSudo, "httpPath": &q.HTTPPath, "ignoreCertificateErrors": &q.IgnoreCertificateErrors, "rdp": &rdp}
	if decodeVaultNullableObject(target, targets, map[string]bool{"rdp": true}, "protocol", "host", "port", "credentialId", "tunnelId", "sshAutoSudo", "httpPath", "ignoreCertificateErrors", "rdp") != nil {
		return nil, vaultwire.ErrProtocol
	}
	if !bytes.Equal(bytes.TrimSpace(rdp), []byte("null")) {
		settings, err := decodeVaultRDPSettings(rdp)
		if err != nil {
			return nil, err
		}
		q.RDP = &settings
	}
	if q.Protocol == "http" || q.Protocol == "https" {
		// Public Quick input may be a pasted URL. Reuse the existing Go
		// browser rules before creating the strictly normalized private stage.
		if len(q.Host) > 4096 || (q.HTTPPath != "" && strings.ContainsAny(q.Host, "/?#")) {
			return nil, vaultwire.ErrProtocol
		}
		resolved, err := resolveDirectWebTarget(webTargetRequest{
			Address: q.Host + q.HTTPPath, Port: q.Port, Protocol: q.Protocol,
			IgnoreCertErrors: q.IgnoreCertificateErrors, TunnelConfigID: q.TunnelID,
		})
		if err != nil {
			return nil, vaultwire.ErrProtocol
		}
		q.Host, q.Port, q.HTTPPath = resolved.Host, resolved.Port, resolved.path
	}
	result, err := h.owner.RegisterQuickTarget(ctx, localvault.QuickTargetRequest{SessionID: session, Epoch: number, Target: q})
	if errors.Is(err, localvault.ErrQuickTargetInput) {
		return nil, vaultwire.ErrProtocol
	}
	return h.domainResult(result, err)
}
