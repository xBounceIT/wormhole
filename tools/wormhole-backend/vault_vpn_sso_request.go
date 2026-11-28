package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

type nativeVPNSSOBegin struct {
	request                       localvault.TunnelPlanRequest
	binding                       vault.TunnelBundleBinding
	transfer                      localvault.VPNSSOTransferRequest
	startURL                      string
	ignore                        bool
	custodyWorkspace, custodyFile string
	fallback                      vault.TunnelFallbackBinding
	hasFallback                   bool
}

func decodeNativeVPNSSOBegin(raw []byte) (q nativeVPNSSOBegin, err error) {
	var requestRaw, bindingRaw, custody, fallback json.RawMessage
	var epoch, public string
	if len(raw) > 16384 || decodeVaultObject(raw, map[string]any{"request": &requestRaw, "binding": &bindingRaw, "challengeId": &q.transfer.ChallengeID, "startURL": &q.startURL, "ignoreCertificateErrors": &q.ignore, "profileId": &q.transfer.ProfileID, "restorePublicKey": &public, "custody": &custody, "fallback": &fallback}, "request", "binding", "challengeId", "startURL", "ignoreCertificateErrors", "profileId", "restorePublicKey") != nil {
		return q, vaultwire.ErrProtocol
	}
	if len(fallback) == 0 && len(raw) > 8192 {
		return q, vaultwire.ErrProtocol
	}
	if decodeVaultObject(requestRaw, map[string]any{"nodeId": &q.request.NodeID, "credentialOverride": &q.request.CredentialOverride, "sessionId": &q.request.SessionID, "requestId": &q.request.RequestID, "epoch": &epoch}, "nodeId", "credentialOverride", "sessionId", "requestId", "epoch") != nil {
		return q, vaultwire.ErrProtocol
	}
	q.request.Epoch, err = strconv.ParseUint(epoch, 10, 53)
	if err != nil || strconv.FormatUint(q.request.Epoch, 10) != epoch || q.request.Validate() != nil {
		return q, vaultwire.ErrProtocol
	}
	q.binding, err = decodeTunnelBundleBinding(bindingRaw)
	if err != nil {
		return q, err
	}
	if len(fallback) != 0 {
		q.hasFallback = true
		q.fallback, err = decodeTunnelFallbackBinding(fallback)
		p := q.fallback.Primary
		if err != nil || q.fallback.Fallback != q.binding || p.NodeID != q.request.NodeID || p.SessionID != q.request.SessionID || p.RequestID != q.request.RequestID || p.Epoch != q.request.Epoch {
			return q, vaultwire.ErrProtocol
		}
	}
	q.transfer.RestorePublicKey, err = browserTransferBytes(public, 32, 32)
	if err != nil {
		return q, err
	}
	q.transfer.RequestID, q.transfer.SessionID, q.transfer.Epoch = q.request.RequestID, q.request.SessionID, q.request.Epoch
	if len(custody) != 0 {
		if decodeVaultObject(custody, map[string]any{"workspaceId": &q.custodyWorkspace, "fileId": &q.custodyFile}, "workspaceId", "fileId") != nil {
			return q, vaultwire.ErrProtocol
		}
		id, err := uuid.Parse(q.custodyWorkspace)
		if err != nil || id == uuid.Nil || id.String() != q.custodyWorkspace || q.custodyFile != q.binding.FileID {
			return q, vaultwire.ErrProtocol
		}
	}
	return q, nil
}

type nativeVPNSSOAction struct {
	context  vault.VPNSSOTransferContext
	packet   vault.VPNSSOTransferPacket
	manifest vault.VPNSSOTransferManifest
	index    int
}

func decodeNativeVPNSSOAction(operation string, raw []byte) (q nativeVPNSSOAction, err error) {
	if operation == "vpn-sso-push" {
		q.packet, err = decodeVPNSSOPacket(raw)
		q.context = q.packet.Context
		return q, err
	}
	var contextRaw, manifestRaw json.RawMessage
	fields := map[string]any{"context": &contextRaw}
	required := []string{"context"}
	switch operation {
	case "vpn-sso-take":
		fields["index"] = &q.index
		required = append(required, "index")
	case "vpn-sso-restore-ack":
		fields["manifest"] = &manifestRaw
		required = append(required, "manifest")
	case "vpn-sso-commit", "vpn-sso-cancel":
	default:
		return q, vaultwire.ErrProtocol
	}
	if len(raw) > 4608 || decodeVaultObject(raw, fields, required...) != nil {
		return q, vaultwire.ErrProtocol
	}
	q.context, err = decodeVPNSSOTransferContext(contextRaw)
	if err == nil && operation == "vpn-sso-restore-ack" {
		q.manifest, err = decodeVPNSSOManifest(manifestRaw)
	}
	return q, err
}

// Both custody modes execute identical archive/HPKE operations. Admission and
// checkpoint publication surround this synchronous operation in their owner.
func performNativeVPNSSOAction(ctxOwner *localvault.Owner, ctx context.Context, operation string, q nativeVPNSSOAction) (value any, committed *localvault.VPNSSOCheckpoint, err error) {
	switch operation {
	case "vpn-sso-take":
		packet, e := ctxOwner.TakeVPNSSOTransfer(ctx, q.context, q.index)
		defer vault.Wipe(packet.Bundle.Ciphertext)
		if e != nil {
			return nil, nil, e
		}
		// Serialization must precede wiping the owned ciphertext buffer.
		encoded, e := json.Marshal(packet)
		return json.RawMessage(encoded), nil, e
	case "vpn-sso-restore-ack":
		err = ctxOwner.AcknowledgeVPNSSOTransfer(ctx, q.context, q.manifest)
		value = struct {
			Restored bool `json:"restored"`
		}{true}
	case "vpn-sso-push":
		err = ctxOwner.PushVPNSSOTransfer(ctx, q.packet)
		value = struct {
			Accepted bool `json:"accepted"`
			Index    int  `json:"index"`
		}{true, q.packet.Index}
	case "vpn-sso-commit":
		checkpoint, e := ctxOwner.CommitVPNSSOTransfer(ctx, q.context)
		value, committed, err = checkpoint, &checkpoint, e
	case "vpn-sso-cancel":
		err = ctxOwner.CancelVPNSSOTransfer(q.context)
		value = struct {
			Cancelled bool `json:"cancelled"`
		}{true}
	default:
		err = vaultwire.ErrProtocol
	}
	return value, committed, err
}
