namespace Wormhole.Models;

internal sealed record RdpConnectionProfile
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public string? Username { get; init; }
    public string? RdpDomain { get; init; }
    public string? RdpScreenSize { get; init; }
    public bool RdpFullScreen { get; init; }
    public int RdpColorDepth { get; init; } = 32;
    public bool RdpUseAllMonitors { get; init; }
    public int RdpAudioMode { get; init; }
    public int RdpAudioCaptureMode { get; init; }
    public int RdpKeyboardHookMode { get; init; } = 2;
    public bool RdpRedirectClipboard { get; init; } = true;
    public bool RdpRedirectPrinters { get; init; }
    public bool RdpRedirectSmartCards { get; init; }
    public bool RdpRedirectPorts { get; init; }
    public bool RdpRedirectDevices { get; init; }
    public string RdpRedirectDrives { get; init; } = string.Empty;
    public int RdpConnectionSpeed { get; init; } = 7;
    public bool RdpDesktopBackground { get; init; } = true;
    public bool RdpFontSmoothing { get; init; } = true;
    public bool RdpDesktopComposition { get; init; } = true;
    public bool RdpWindowDrag { get; init; } = true;
    public bool RdpMenuAnimation { get; init; } = true;
    public bool RdpVisualStyles { get; init; } = true;
    public bool RdpBitmapCaching { get; init; } = true;
    public bool RdpAutoReconnect { get; init; } = true;
    public int RdpServerAuthentication { get; init; } = 2;
    public int RdpGatewayUsageMethod { get; init; }
    public string? RdpGatewayHostname { get; init; }
    public bool RdpGatewayUseSameCreds { get; init; }
}
