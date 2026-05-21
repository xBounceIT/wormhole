namespace Wormhole.Models;

public sealed record ConnectionProfile
{
    public required Guid NodeId { get; init; }
    public required string Name { get; init; }
    public required ProtocolType Protocol { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public string? Username { get; init; }
    public Guid? CredentialId { get; init; }

    public string? RdpDomain { get; init; }
    public string? RdpScreenSize { get; init; }
    public bool RdpFullScreen { get; init; }

    // Display
    public int RdpColorDepth { get; init; } = 32;
    public bool RdpUseAllMonitors { get; init; }

    // Local Resources
    public int RdpAudioMode { get; init; }                 // 0=PlayHere, 1=DoNotPlay, 2=PlayRemote
    public int RdpAudioCaptureMode { get; init; }          // 0=DoNotRecord, 1=Record
    public int RdpKeyboardHookMode { get; init; } = 2;     // 0=Local, 1=Remote, 2=FullScreenOnly
    public bool RdpRedirectClipboard { get; init; } = true;
    public bool RdpRedirectPrinters { get; init; }
    public bool RdpRedirectSmartCards { get; init; }
    public bool RdpRedirectPorts { get; init; }
    public bool RdpRedirectDevices { get; init; }
    public string RdpRedirectDrives { get; init; } = string.Empty; // "" | "all" | "C,D,..."

    // Experience
    public int RdpConnectionSpeed { get; init; } = 7;       // 7 = auto-detect / LAN per IMsRdpClientAdvancedSettings6
    public bool RdpDesktopBackground { get; init; } = true;
    public bool RdpFontSmoothing { get; init; } = true;
    public bool RdpDesktopComposition { get; init; } = true;
    public bool RdpWindowDrag { get; init; } = true;
    public bool RdpMenuAnimation { get; init; } = true;
    public bool RdpVisualStyles { get; init; } = true;
    public bool RdpBitmapCaching { get; init; } = true;
    public bool RdpAutoReconnect { get; init; } = true;

    // Advanced
    public int RdpServerAuthentication { get; init; }       // 0=Warn, 1=Require, 2=DoNotConnect
    public int RdpGatewayUsageMethod { get; init; }         // 0=Direct, 1=Always, 2=Detect, 3=DefaultRdg
    public string? RdpGatewayHostname { get; init; }
    public Guid? RdpGatewayCredentialId { get; init; }
    public bool RdpGatewayBypassLocal { get; init; } = true;
    public bool RdpGatewayUseSameCreds { get; init; }

    public string? SshKeyFileName { get; init; }
    public string? SshKnownHostFingerprint { get; init; }
}
