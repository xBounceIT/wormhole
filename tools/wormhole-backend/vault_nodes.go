package main

import (
	"context"
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
	"math"
	"strconv"
)

type vaultNodeView struct {
	vaultstore.NodeMetadata
	SortOrder         string `json:"sortOrder"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	RowVersion        string `json:"rowVersion"`
	HasNotes          bool   `json:"hasNotes"`
	HasInlinePassword bool   `json:"hasInlinePassword"`
}

func nodeView(n vaultstore.Node) vaultNodeView {
	view := vaultNodeView{NodeMetadata: n.NodeMetadata, SortOrder: strconv.FormatInt(n.SortOrder, 10), CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, RowVersion: strconv.FormatUint(n.RowVersion, 10)}
	for _, f := range n.Fields {
		if f.Field == "notes" {
			view.HasNotes = f.Present
		} else if f.Field == "inlinePassword" {
			view.HasInlinePassword = f.Present
		}
	}
	return view
}

func decodeVaultNodeMetadata(raw []byte) (m vaultstore.NodeMetadata, err error) {
	if len(raw) > 512*1024 {
		return m, vaultwire.ErrProtocol
	}
	var order string
	targets := map[string]any{"id": &m.ID, "parentId": &m.ParentID, "ownerUserId": &m.OwnerUserID, "name": &m.Name, "kind": &m.Kind, "sortOrder": &order, "protocol": &m.Protocol, "host": &m.Host, "port": &m.Port, "httpPath": &m.HTTPPath, "username": &m.Username, "credentialId": &m.CredentialID, "credentialMode": &m.CredentialMode, "credentialSlotId": &m.CredentialSlotID, "useInlinePassword": &m.UseInlinePassword, "sshAutoSudo": &m.SshAutoSudo, "httpIgnoreCertErrors": &m.HTTPIgnoreCertErrors, "tunnelEnabled": &m.TunnelEnabled, "tunnelConfigId": &m.TunnelConfigID, "serialBaudRate": &m.SerialBaudRate, "serialDataBits": &m.SerialDataBits, "serialStopBits": &m.SerialStopBits, "serialParity": &m.SerialParity, "serialFlowControl": &m.SerialFlowControl, "sshKeyFileName": &m.SshKeyFileName, "sshKnownHostFingerprint": &m.SshKnownHostFingerprint, "rdpDomain": &m.RDPDomain, "rdpScreenSize": &m.RDPScreenSize, "rdpFullScreen": &m.RDPFullScreen, "rdpColorDepth": &m.RDPColorDepth, "rdpUseAllMonitors": &m.RDPUseAllMonitors, "rdpAudioMode": &m.RDPAudioMode, "rdpAudioCaptureMode": &m.RDPAudioCaptureMode, "rdpKeyboardHookMode": &m.RDPKeyboardHookMode, "rdpRedirectClipboard": &m.RDPRedirectClipboard, "rdpRedirectPrinters": &m.RDPRedirectPrinters, "rdpRedirectSmartCards": &m.RDPRedirectSmartCards, "rdpRedirectPorts": &m.RDPRedirectPorts, "rdpRedirectDevices": &m.RDPRedirectDevices, "rdpRedirectDrives": &m.RDPRedirectDrives, "rdpConnectionSpeed": &m.RDPConnectionSpeed, "rdpDesktopBackground": &m.RDPDesktopBackground, "rdpFontSmoothing": &m.RDPFontSmoothing, "rdpDesktopComposition": &m.RDPDesktopComposition, "rdpWindowDrag": &m.RDPWindowDrag, "rdpMenuAnimation": &m.RDPMenuAnimation, "rdpVisualStyles": &m.RDPVisualStyles, "rdpBitmapCaching": &m.RDPBitmapCaching, "rdpAutoReconnect": &m.RDPAutoReconnect, "rdpServerAuthentication": &m.RDPServerAuthentication, "rdpGatewayUsageMethod": &m.RDPGatewayUsageMethod, "rdpGatewayHostname": &m.RDPGatewayHostname, "rdpGatewayCredentialId": &m.RDPGatewayCredentialID, "rdpGatewayBypassLocal": &m.RDPGatewayBypassLocal, "rdpGatewayUseSameCreds": &m.RDPGatewayUseSameCreds, "rdpUseExternalClient": &m.RDPUseExternalClient}
	nullable := map[string]bool{"parentId": true, "ownerUserId": true, "protocol": true, "host": true, "port": true, "httpPath": true, "username": true, "credentialId": true, "credentialMode": true, "credentialSlotId": true, "useInlinePassword": true, "sshAutoSudo": true, "httpIgnoreCertErrors": true, "tunnelEnabled": true, "tunnelConfigId": true, "serialBaudRate": true, "serialDataBits": true, "serialStopBits": true, "serialParity": true, "serialFlowControl": true, "sshKeyFileName": true, "sshKnownHostFingerprint": true, "rdpDomain": true, "rdpScreenSize": true, "rdpFullScreen": true, "rdpColorDepth": true, "rdpUseAllMonitors": true, "rdpAudioMode": true, "rdpAudioCaptureMode": true, "rdpKeyboardHookMode": true, "rdpRedirectClipboard": true, "rdpRedirectPrinters": true, "rdpRedirectSmartCards": true, "rdpRedirectPorts": true, "rdpRedirectDevices": true, "rdpRedirectDrives": true, "rdpConnectionSpeed": true, "rdpDesktopBackground": true, "rdpFontSmoothing": true, "rdpDesktopComposition": true, "rdpWindowDrag": true, "rdpMenuAnimation": true, "rdpVisualStyles": true, "rdpBitmapCaching": true, "rdpAutoReconnect": true, "rdpServerAuthentication": true, "rdpGatewayUsageMethod": true, "rdpGatewayHostname": true, "rdpGatewayCredentialId": true, "rdpGatewayBypassLocal": true, "rdpGatewayUseSameCreds": true, "rdpUseExternalClient": true}
	err = decodeVaultNullableObject(raw, targets, nullable, "id", "name", "kind", "sortOrder")
	if err != nil {
		return m, err
	}
	m.SortOrder, err = strconv.ParseInt(order, 10, 64)
	if err != nil || strconv.FormatInt(m.SortOrder, 10) != order || m.Validate() != nil {
		return m, vaultwire.ErrProtocol
	}
	// Shared ownership/slots require their authenticated catalogs and permissions.
	if m.OwnerUserID != nil || (m.CredentialMode != nil && *m.CredentialMode == 3) {
		return m, vaultwire.ErrProtocol
	}
	return m, nil
}

func (h *vaultFoundationHandler) node(ctx context.Context, operation string, payload []byte) (json.RawMessage, error) {
	if h.owner == nil {
		return nil, vaultwire.ErrProtocol
	}
	var result any
	var err error
	switch operation {
	case "node-list":
		var after string
		var limit int
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"after": &after, "limit": &limit}, "after", "limit") != nil || (after != "" && !vaultCredentialID(after)) || limit < 1 || limit > 16 {
			return nil, vaultwire.ErrProtocol
		}
		var values []vaultstore.Node
		values, err = h.owner.ListNodes(ctx, after, limit)
		views := make([]vaultNodeView, 0, len(values))
		for _, n := range values {
			views = append(views, nodeView(n))
		}
		result = struct {
			Nodes []vaultNodeView `json:"nodes"`
		}{views}
	case "node-read", "node-delete", "node-delete-tree":
		var id, version string
		if len(payload) > 1024 || decodeVaultObject(payload, map[string]any{"id": &id, "rowVersion": &version}, "id", "rowVersion") != nil || !vaultCredentialID(id) {
			return nil, vaultwire.ErrProtocol
		}
		revision, e := vaultCredentialRevision(version, operation == "node-read")
		if e != nil || (operation != "node-read" && revision == math.MaxInt64) {
			return nil, vaultwire.ErrProtocol
		}
		if operation == "node-read" {
			var value vaultstore.Node
			value, err = h.owner.ReadNode(ctx, id, revision)
			result = nodeView(value)
		} else if operation == "node-delete-tree" {
			var count uint64
			count, err = h.owner.DeleteNodeTree(ctx, id, revision)
			result = struct {
				ID           string `json:"id"`
				RowVersion   string `json:"rowVersion"`
				DeletedCount string `json:"deletedCount"`
			}{id, strconv.FormatUint(revision+1, 10), strconv.FormatUint(count, 10)}
		} else {
			err = h.owner.DeleteNode(ctx, id, revision)
			result = struct {
				ID         string `json:"id"`
				RowVersion string `json:"rowVersion"`
				Deleted    bool   `json:"deleted"`
			}{id, strconv.FormatUint(revision+1, 10), true}
		}
	case "node-save":
		var metadata, rawChanges json.RawMessage
		var version string
		e := decodeVaultObject(payload, map[string]any{"metadata": &metadata, "changes": &rawChanges, "rowVersion": &version}, "metadata", "changes", "rowVersion")
		defer vault.Wipe(metadata)
		defer vault.Wipe(rawChanges)
		if e != nil {
			return nil, e
		}
		revision, e := vaultCredentialRevision(version, true)
		if e != nil || revision == math.MaxInt64 {
			return nil, vaultwire.ErrProtocol
		}
		m, e := decodeVaultNodeMetadata(metadata)
		if e != nil {
			return nil, e
		}
		changes, e := decodeVaultSecretChanges(rawChanges, vaultstore.NodeEditableField, 2)
		defer wipeVaultCredentialChanges(changes)
		if e != nil {
			return nil, e
		}
		var value vaultstore.Node
		value, err = h.owner.PutNode(ctx, m, changes, revision)
		result = nodeView(value)
	default:
		return nil, vaultwire.ErrProtocol
	}
	return h.domainResult(result, err)
}
