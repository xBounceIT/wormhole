package main

import (
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultwire"
)

// Saved and temporary inputs use the same complete native options schema.
// Key order is immaterial; duplicate/missing/unknown keys are not.
func decodeVaultRDPSettings(rdp []byte) (vault.RDPSettings, error) {
	var settings vault.RDPSettings
	targets := map[string]any{"domain": &settings.Domain, "screenSize": &settings.ScreenSize, "fullScreen": &settings.FullScreen, "colorDepth": &settings.ColorDepth, "useAllMonitors": &settings.UseAllMonitors, "audioMode": &settings.AudioMode, "audioCaptureMode": &settings.AudioCaptureMode, "keyboardHookMode": &settings.KeyboardHookMode, "redirectClipboard": &settings.RedirectClipboard, "redirectPrinters": &settings.RedirectPrinters, "redirectSmartCards": &settings.RedirectSmartCards, "redirectPorts": &settings.RedirectPorts, "redirectDevices": &settings.RedirectDevices, "redirectDrives": &settings.RedirectDrives, "connectionSpeed": &settings.ConnectionSpeed, "desktopBackground": &settings.DesktopBackground, "fontSmoothing": &settings.FontSmoothing, "desktopComposition": &settings.DesktopComposition, "windowDrag": &settings.WindowDrag, "menuAnimation": &settings.MenuAnimation, "visualStyles": &settings.VisualStyles, "bitmapCaching": &settings.BitmapCaching, "autoReconnect": &settings.AutoReconnect, "serverAuthentication": &settings.ServerAuthentication, "gatewayUsageMethod": &settings.GatewayUsageMethod, "gatewayHostname": &settings.GatewayHostname, "gatewayCredentialId": &settings.GatewayCredentialID, "gatewayBypassLocal": &settings.GatewayBypassLocal, "gatewayUseSameCreds": &settings.GatewayUseSameCreds, "useExternalClient": &settings.UseExternalClient}
	if decodeVaultObject(rdp, targets, "domain", "screenSize", "fullScreen", "colorDepth", "useAllMonitors", "audioMode", "audioCaptureMode", "keyboardHookMode", "redirectClipboard", "redirectPrinters", "redirectSmartCards", "redirectPorts", "redirectDevices", "redirectDrives", "connectionSpeed", "desktopBackground", "fontSmoothing", "desktopComposition", "windowDrag", "menuAnimation", "visualStyles", "bitmapCaching", "autoReconnect", "serverAuthentication", "gatewayUsageMethod", "gatewayHostname", "gatewayCredentialId", "gatewayBypassLocal", "gatewayUseSameCreds", "useExternalClient") != nil {
		return settings, vaultwire.ErrProtocol
	}
	if settings.GatewayCredentialID != "" && !vaultCredentialID(settings.GatewayCredentialID) {
		return settings, vaultwire.ErrProtocol
	}

	return settings, nil
}
