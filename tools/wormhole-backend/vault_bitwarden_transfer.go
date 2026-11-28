package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/localvault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// These operations belong to the native browser owner. No renderer IPC exposes
// them. Public metadata and sealed chunks are the entire wire representation.
func browserTransferBytes(raw string, minimum, maximum int) ([]byte, error) {
	if len(raw) < base64.StdEncoding.EncodedLen(minimum) || len(raw) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, vaultwire.ErrProtocol
	}
	value, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(value) < minimum || len(value) > maximum || base64.StdEncoding.EncodeToString(value) != raw {
		vault.Wipe(value)
		return nil, vaultwire.ErrProtocol
	}
	return value, nil
}

func decodeBrowserTransferContext(raw []byte) (c vault.BrowserTransferContext, err error) {
	var capture, restore string
	if len(raw) > 2048 || decodeVaultObject(raw, map[string]any{
		"workspaceId": &c.WorkspaceID, "fileId": &c.FileID, "profileId": &c.ProfileID,
		"requestId": &c.RequestID, "transferId": &c.TransferID, "epoch": &c.Epoch,
		"policySequence": &c.PolicySequence, "action": &c.Action, "sourceRevision": &c.SourceRevision,
		"capturePublicKey": &capture, "restorePublicKey": &restore,
	}, "workspaceId", "fileId", "profileId", "requestId", "transferId", "epoch", "policySequence", "action", "sourceRevision", "capturePublicKey", "restorePublicKey") != nil {
		return c, vaultwire.ErrProtocol
	}
	c.CapturePublicKey, err = browserTransferBytes(capture, 32, 32)
	if err == nil {
		c.RestorePublicKey, err = browserTransferBytes(restore, 32, 32)
	}
	if err != nil || c.Validate() != nil {
		return c, vaultwire.ErrProtocol
	}
	return c, nil
}

func decodeBrowserTransferPacket(raw []byte) (p vault.BrowserTransferPacket, err error) {
	var contextRaw, manifestRaw, bundleRaw json.RawMessage
	defer func() { vault.Wipe(contextRaw); vault.Wipe(manifestRaw); vault.Wipe(bundleRaw) }()
	if decodeVaultObject(raw, map[string]any{"context": &contextRaw, "direction": &p.Direction,
		"manifest": &manifestRaw, "index": &p.Index, "bundle": &bundleRaw}, "context", "direction", "manifest", "index", "bundle") != nil {
		return p, vaultwire.ErrProtocol
	}
	p.Context, err = decodeBrowserTransferContext(contextRaw)
	if err != nil || len(manifestRaw) > 256 || decodeVaultObject(manifestRaw, map[string]any{
		"bytes": &p.Manifest.Bytes, "revision": &p.Manifest.Revision, "restore": &p.Manifest.Restore,
	}, "bytes", "revision", "restore") != nil {
		return p, vaultwire.ErrProtocol
	}
	var enc, ciphertext string
	if decodeVaultObject(bundleRaw, map[string]any{"formatVersion": &p.Bundle.FormatVersion, "suiteId": &p.Bundle.SuiteID,
		"enc": &enc, "ciphertext": &ciphertext}, "formatVersion", "suiteId", "enc", "ciphertext") != nil {
		return p, vaultwire.ErrProtocol
	}
	p.Bundle.Enc, err = browserTransferBytes(enc, 32, 32)
	if err == nil {
		p.Bundle.Ciphertext, err = browserTransferBytes(ciphertext, 16, vault.MaxSecretBytes+16)
	}
	if err != nil || vault.ValidateBrowserTransferPacket(p) != nil {
		vault.Wipe(p.Bundle.Enc)
		vault.Wipe(p.Bundle.Ciphertext)
		return vault.BrowserTransferPacket{}, vaultwire.ErrProtocol
	}
	return p, nil
}

func (h *vaultFoundationHandler) bitwardenTransfer(ctx context.Context, operation string, raw []byte) (json.RawMessage, error) {
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	var result any
	var err error
	switch operation {
	case "bitwarden-transfer-begin":
		var q localvault.BitwardenTransferRequest
		var epoch, public string
		if len(raw) > 2048 || decodeVaultObject(raw, map[string]any{
			"workspaceId": &q.WorkspaceID, "profileId": &q.ProfileID, "requestId": &q.RequestID,
			"epoch": &epoch, "action": &q.Action, "sourceRevision": &q.SourceRevision, "restorePublicKey": &public,
		}, "workspaceId", "profileId", "requestId", "epoch", "action", "sourceRevision", "restorePublicKey") != nil {
			return nil, vaultwire.ErrProtocol
		}
		q.Epoch, err = strconv.ParseUint(epoch, 10, 53)
		if err != nil || q.Epoch == 0 || strconv.FormatUint(q.Epoch, 10) != epoch {
			return nil, vaultwire.ErrProtocol
		}
		q.RestorePublicKey, err = browserTransferBytes(public, 32, 32)
		if err != nil {
			return nil, err
		}
		result, err = h.owner.BeginBitwardenTransfer(ctx, q)
	case "bitwarden-transfer-push":
		var packet vault.BrowserTransferPacket
		packet, err = decodeBrowserTransferPacket(raw)
		if err != nil {
			return nil, err
		}
		defer vault.Wipe(packet.Bundle.Enc)
		defer vault.Wipe(packet.Bundle.Ciphertext)
		err = h.owner.PushBitwardenTransfer(ctx, packet)
		result = struct {
			Accepted bool `json:"accepted"`
			Index    int  `json:"index"`
		}{true, packet.Index}
	case "bitwarden-transfer-commit", "bitwarden-transfer-take", "bitwarden-transfer-cancel":
		var contextRaw json.RawMessage
		defer func() { vault.Wipe(contextRaw) }()
		var index int
		targets := map[string]any{"context": &contextRaw}
		required := []string{"context"}
		if operation == "bitwarden-transfer-take" {
			targets["index"] = &index
			required = append(required, "index")
		}
		if len(raw) > 2304 || decodeVaultObject(raw, targets, required...) != nil {
			return nil, vaultwire.ErrProtocol
		}
		var c vault.BrowserTransferContext
		c, err = decodeBrowserTransferContext(contextRaw)
		if err != nil {
			return nil, err
		}
		switch operation {
		case "bitwarden-transfer-commit":
			var manifest vault.BrowserTransferManifest
			manifest, err = h.owner.CommitBitwardenTransfer(ctx, c)
			result = struct {
				Manifest vault.BrowserTransferManifest `json:"manifest"`
			}{manifest}
		case "bitwarden-transfer-take":
			var packet vault.BrowserTransferPacket
			packet, err = h.owner.TakeBitwardenTransfer(ctx, c, index)
			defer vault.Wipe(packet.Bundle.Enc)
			defer vault.Wipe(packet.Bundle.Ciphertext)
			result = packet
		case "bitwarden-transfer-cancel":
			err = h.owner.CancelBitwardenTransfer(c)
			result = struct {
				Cancelled bool `json:"cancelled"`
			}{true}
		}
	case "bitwarden-profile-close":
		var profile string
		if len(raw) > 512 || decodeVaultObject(raw, map[string]any{"profileId": &profile}, "profileId") != nil || !vaultCredentialID(profile) {
			return nil, vaultwire.ErrProtocol
		}
		err = h.owner.CloseBitwardenBrowserProfile(profile)
		result = struct {
			Closed bool `json:"closed"`
		}{true}
	default:
		return nil, vaultwire.ErrProtocol
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
