namespace Wormhole.Models;

public sealed record ConnectionProfile
{
    public required Guid NodeId { get; init; }
    public required string Name { get; init; }
    public string? ParentFolderName { get; init; }
    public required ProtocolType Protocol { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public string? Username { get; init; }
    public Guid? CredentialId { get; init; }

    /// <summary>
    /// When true, the SSH login password is read from Credential Manager keyed by
    /// <see cref="NodeId"/> rather than a saved credential or a prompt. Resolved from the
    /// leaf node only — inline passwords never inherit from a folder.
    /// </summary>
    public bool UseInlinePassword { get; init; }

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
    public int RdpServerAuthentication { get; init; } = 2;  // 0=NoAuth, 1=Require, 2=Warn/prompt
    public int RdpGatewayUsageMethod { get; init; }         // 0=Direct, 1=Always, 2=Detect, 3=DefaultRdg
    public string? RdpGatewayHostname { get; init; }
    public Guid? RdpGatewayCredentialId { get; init; }
    public bool RdpGatewayBypassLocal { get; init; } = true;
    public bool RdpGatewayUseSameCreds { get; init; }

    /// <summary>
    /// When true, skip the embedded mstscax ActiveX control and launch the system
    /// Remote Desktop client (mstsc.exe) in a separate process instead. The motivating
    /// case is Azure-AD-joined targets: WAM/AAD broker DLLs are delay-loaded by mstscax
    /// during AAD auth, and our unpackaged WinUI process can't load them — the failure
    /// surfaces as SEH 0xC06D007F and kills the process. mstsc.exe is a packaged-trusted
    /// system binary that can load WAM. Users with AAD targets opt in here and lose the
    /// embedded experience in exchange for a stable connection.
    /// </summary>
    public bool RdpUseExternalClient { get; init; }

    public string? SshKeyFileName { get; init; }
    public string? SshKnownHostFingerprint { get; init; }
    public bool SshAutoSudo { get; init; }

    /// <summary>
    /// For the <see cref="ProtocolType.Https"/> web protocol: accept certificate errors
    /// (self-signed, name mismatch, untrusted chain) when navigating. Targets appliance GUIs —
    /// firewalls etc. — that commonly serve self-signed certs. Ignored for non-web protocols.
    /// </summary>
    public bool HttpIgnoreCertErrors { get; init; }

    public bool TunnelEnabled { get; init; }
    public Guid? TunnelConfigId { get; init; }
}
