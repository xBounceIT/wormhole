package resolver

import (
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

// ProjectRDPSettings projects a complete leaf-to-root chain without granting
// authority. Callers authenticate/authorize the chain and validate the result.
func ProjectRDPSettings(chain []vaultstore.NodeMetadata) vault.RDPSettings {
	settings := vault.DefaultRDPSettings()
	for i := len(chain) - 1; i >= 0; i-- {
		n := chain[i]
		rdpSet(&settings.Domain, n.RDPDomain)
		rdpSet(&settings.ScreenSize, n.RDPScreenSize)
		rdpSet(&settings.FullScreen, n.RDPFullScreen)
		rdpSet(&settings.ColorDepth, n.RDPColorDepth)
		rdpSet(&settings.UseAllMonitors, n.RDPUseAllMonitors)
		rdpSet(&settings.AudioMode, n.RDPAudioMode)
		rdpSet(&settings.AudioCaptureMode, n.RDPAudioCaptureMode)
		rdpSet(&settings.KeyboardHookMode, n.RDPKeyboardHookMode)
		rdpSet(&settings.RedirectClipboard, n.RDPRedirectClipboard)
		rdpSet(&settings.RedirectPrinters, n.RDPRedirectPrinters)
		rdpSet(&settings.RedirectSmartCards, n.RDPRedirectSmartCards)
		rdpSet(&settings.RedirectPorts, n.RDPRedirectPorts)
		rdpSet(&settings.RedirectDevices, n.RDPRedirectDevices)
		rdpSet(&settings.RedirectDrives, n.RDPRedirectDrives)
		rdpSet(&settings.ConnectionSpeed, n.RDPConnectionSpeed)
		rdpSet(&settings.DesktopBackground, n.RDPDesktopBackground)
		rdpSet(&settings.FontSmoothing, n.RDPFontSmoothing)
		rdpSet(&settings.DesktopComposition, n.RDPDesktopComposition)
		rdpSet(&settings.WindowDrag, n.RDPWindowDrag)
		rdpSet(&settings.MenuAnimation, n.RDPMenuAnimation)
		rdpSet(&settings.VisualStyles, n.RDPVisualStyles)
		rdpSet(&settings.BitmapCaching, n.RDPBitmapCaching)
		rdpSet(&settings.AutoReconnect, n.RDPAutoReconnect)
		rdpSet(&settings.ServerAuthentication, n.RDPServerAuthentication)
		rdpSet(&settings.GatewayUsageMethod, n.RDPGatewayUsageMethod)
		rdpSet(&settings.GatewayHostname, n.RDPGatewayHostname)
		rdpSet(&settings.GatewayCredentialID, n.RDPGatewayCredentialID)
		rdpSet(&settings.GatewayBypassLocal, n.RDPGatewayBypassLocal)
		rdpSet(&settings.GatewayUseSameCreds, n.RDPGatewayUseSameCreds)
		rdpSet(&settings.UseExternalClient, n.RDPUseExternalClient)
	}
	return settings
}

func rdpSet[T any](target *T, value *T) {
	if value != nil {
		*target = *value
	}
}
