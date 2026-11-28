package main

import (
	"encoding/json"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

func decodeVaultConnectionMetadata(raw []byte) (request workspaceNodeWriteRequest, err error) {
	var rdp json.RawMessage
	targets := map[string]any{"id": &request.ID, "parentId": &request.ParentID, "name": &request.Name, "protocol": &request.Protocol, "host": &request.Host, "port": &request.Port, "username": &request.Username, "inlinePasswordAction": &request.InlinePasswordAction, "sshAutoSudo": &request.SshAutoSudo, "httpIgnoreCertErrors": &request.HTTPIgnoreCertErrors, "tunnelEnabled": &request.TunnelEnabled, "tunnelConfigId": &request.TunnelConfigID, "credentialMode": &request.CredentialMode, "credentialId": &request.CredentialID, "serialBaudRate": &request.SerialBaudRate, "serialDataBits": &request.SerialDataBits, "serialStopBits": &request.SerialStopBits, "serialParity": &request.SerialParity, "serialFlowControl": &request.SerialFlowControl, "rdp": &rdp}
	nullable := map[string]bool{"sshAutoSudo": true, "httpIgnoreCertErrors": true, "tunnelEnabled": true, "rdp": true}
	if len(raw) > 64*1024 || decodeVaultNullableObject(raw, targets, nullable, "id", "parentId", "name", "protocol", "host", "port", "username", "inlinePasswordAction", "sshAutoSudo", "httpIgnoreCertErrors", "tunnelEnabled", "tunnelConfigId", "credentialMode", "credentialId", "serialBaudRate", "serialDataBits", "serialStopBits", "serialParity", "serialFlowControl", "rdp") != nil {
		return request, vaultwire.ErrProtocol
	}
	for _, id := range []string{request.ID, request.ParentID, request.CredentialID, request.TunnelConfigID} {
		if id != "" && !vaultCredentialID(id) {
			return request, vaultwire.ErrProtocol
		}
	}
	if request.CredentialMode != 2 && request.CredentialID != "" {
		return request, vaultwire.ErrProtocol
	}
	request.Kind = "connection"
	if request.Protocol == "rdp" {
		settings, err := decodeVaultRDPSettings(rdp)
		if err != nil {
			return request, err
		}
		request.RDP = &settings
	} else if string(rdp) != "null" {
		return request, vaultwire.ErrProtocol
	}
	return request, nil
}

func vaultConnectionMetadata(m vaultstore.NodeMetadata, n normalizedWorkspaceNode) vaultstore.NodeMetadata {
	m.ID, m.Name, m.Kind = n.id, n.name, 1
	m.ParentID = nil
	if n.parentID != "" {
		m.ParentID = &n.parentID
	}
	protocol := int(n.protocol.Int64)
	m.Protocol = &protocol
	m.Host = &n.host.String
	m.Port = nil
	if n.port.Valid {
		port := int(n.port.Int64)
		m.Port = &port
	}
	m.CredentialMode = &n.credentialMode
	m.CredentialSlotID = nil
	m.HTTPPath = vaultNodeString(n.httpPath)
	m.Username = vaultNodeString(n.username)
	m.CredentialID = vaultNodeString(n.credentialID)
	m.TunnelConfigID = vaultNodeString(n.tunnelConfigID)
	m.UseInlinePassword = vaultNodeBool(n.useInlinePassword)
	m.SshAutoSudo = vaultNodeBool(n.sshAutoSudo)
	m.HTTPIgnoreCertErrors = vaultNodeBool(n.httpIgnoreCertErrors)
	m.TunnelEnabled = vaultNodeBool(n.tunnelEnabled)
	m.SerialBaudRate = vaultNodeInt(n.serialBaudRate)
	m.SerialDataBits = vaultNodeInt(n.serialDataBits)
	m.SerialStopBits = vaultNodeInt(n.serialStopBits)
	m.SerialParity = vaultNodeInt(n.serialParity)
	m.SerialFlowControl = vaultNodeInt(n.serialFlowControl)
	if n.rdp != nil {
		m.RDPDomain = &n.rdp.Domain
		m.RDPScreenSize = &n.rdp.ScreenSize
		m.RDPFullScreen = &n.rdp.FullScreen
		m.RDPColorDepth = &n.rdp.ColorDepth
		m.RDPUseAllMonitors = &n.rdp.UseAllMonitors
		m.RDPAudioMode = &n.rdp.AudioMode
		m.RDPAudioCaptureMode = &n.rdp.AudioCaptureMode
		m.RDPKeyboardHookMode = &n.rdp.KeyboardHookMode
		m.RDPRedirectClipboard = &n.rdp.RedirectClipboard
		m.RDPRedirectPrinters = &n.rdp.RedirectPrinters
		m.RDPRedirectSmartCards = &n.rdp.RedirectSmartCards
		m.RDPRedirectPorts = &n.rdp.RedirectPorts
		m.RDPRedirectDevices = &n.rdp.RedirectDevices
		m.RDPRedirectDrives = &n.rdp.RedirectDrives
		m.RDPConnectionSpeed = &n.rdp.ConnectionSpeed
		m.RDPDesktopBackground = &n.rdp.DesktopBackground
		m.RDPFontSmoothing = &n.rdp.FontSmoothing
		m.RDPDesktopComposition = &n.rdp.DesktopComposition
		m.RDPWindowDrag = &n.rdp.WindowDrag
		m.RDPMenuAnimation = &n.rdp.MenuAnimation
		m.RDPVisualStyles = &n.rdp.VisualStyles
		m.RDPBitmapCaching = &n.rdp.BitmapCaching
		m.RDPAutoReconnect = &n.rdp.AutoReconnect
		m.RDPServerAuthentication = &n.rdp.ServerAuthentication
		m.RDPGatewayUsageMethod = &n.rdp.GatewayUsageMethod
		m.RDPGatewayHostname = &n.rdp.GatewayHostname
		m.RDPGatewayCredentialID = nil
		if n.rdp.GatewayCredentialID != "" {
			m.RDPGatewayCredentialID = &n.rdp.GatewayCredentialID
		}
		m.RDPGatewayBypassLocal = &n.rdp.GatewayBypassLocal
		m.RDPGatewayUseSameCreds = &n.rdp.GatewayUseSameCreds
		m.RDPUseExternalClient = &n.rdp.UseExternalClient
	}
	return m
}
func vaultNodeString(value any) *string {
	if text, ok := value.(string); ok {
		return &text
	}
	return nil
}
func vaultNodeBool(value any) *bool {
	if number, ok := value.(int64); ok {
		flag := number != 0
		return &flag
	}
	return nil
}
func vaultNodeInt(value any) *int {
	if number, ok := value.(int); ok {
		return &number
	}
	return nil
}
