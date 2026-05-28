namespace Wormhole.Models;

public class ConnectionNode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? ParentId { get; set; }
    public string Name { get; set; } = string.Empty;
    public NodeKind Kind { get; set; }
    public int SortOrder { get; set; }

    public ProtocolType? Protocol { get; set; }
    public string? Host { get; set; }
    public int? Port { get; set; }
    public string? Username { get; set; }
    public Guid? CredentialId { get; set; }

    public string? RdpDomain { get; set; }
    public string? RdpScreenSize { get; set; }
    public bool? RdpFullScreen { get; set; }

    // Display
    public int? RdpColorDepth { get; set; }
    public bool? RdpUseAllMonitors { get; set; }

    // Local Resources
    public int? RdpAudioMode { get; set; }
    public int? RdpAudioCaptureMode { get; set; }
    public int? RdpKeyboardHookMode { get; set; }
    public bool? RdpRedirectClipboard { get; set; }
    public bool? RdpRedirectPrinters { get; set; }
    public bool? RdpRedirectSmartCards { get; set; }
    public bool? RdpRedirectPorts { get; set; }
    public bool? RdpRedirectDevices { get; set; }
    public string? RdpRedirectDrives { get; set; }

    // Experience
    public int? RdpConnectionSpeed { get; set; }
    public bool? RdpDesktopBackground { get; set; }
    public bool? RdpFontSmoothing { get; set; }
    public bool? RdpDesktopComposition { get; set; }
    public bool? RdpWindowDrag { get; set; }
    public bool? RdpMenuAnimation { get; set; }
    public bool? RdpVisualStyles { get; set; }
    public bool? RdpBitmapCaching { get; set; }
    public bool? RdpAutoReconnect { get; set; }

    // Advanced
    public int? RdpServerAuthentication { get; set; }
    public int? RdpGatewayUsageMethod { get; set; }
    public string? RdpGatewayHostname { get; set; }
    public Guid? RdpGatewayCredentialId { get; set; }
    public bool? RdpGatewayBypassLocal { get; set; }
    public bool? RdpGatewayUseSameCreds { get; set; }
    public bool? RdpUseExternalClient { get; set; }

    public string? SshKeyFileName { get; set; }
    public string? SshKnownHostFingerprint { get; set; }
    public bool? SshAutoSudo { get; set; }

    public bool? TunnelEnabled { get; set; }
    public Guid? TunnelConfigId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Return a new node preserving the source's identity (Id, parent linkage, audit
    /// timestamps, and SSH host-key state) but no editable fields. Used by the connection
    /// editor (which writes every editable field back) to materialise the "Save" result
    /// without mutating the input. Folder edits use <see cref="Clone"/> instead — folders
    /// can hold any field as an inheritance default (mRemoteNG import populates Protocol /
    /// Host / Username / CredentialId / RdpDomain on container nodes), and the folder
    /// editor only touches Name + tunnel fields, so it MUST preserve everything else.
    /// </summary>
    public static ConnectionNode CloneIdentityFrom(ConnectionNode source) => new()
    {
        Id = source.Id,
        ParentId = source.ParentId,
        Kind = source.Kind,
        SortOrder = source.SortOrder,
        CreatedAt = source.CreatedAt,
        UpdatedAt = source.UpdatedAt,
        SshKeyFileName = source.SshKeyFileName,
        SshKnownHostFingerprint = source.SshKnownHostFingerprint,
    };

    /// <summary>
    /// Full shallow copy of every field. Use this when an editor only writes a subset of
    /// fields and must preserve everything else — primarily the folder editor, which
    /// exposes Name + tunnel but must not clobber inheritance defaults like Protocol /
    /// Host / CredentialId that mRemoteNG-imported folders carry for their descendants.
    /// </summary>
    public ConnectionNode Clone() => new()
    {
        Id = Id,
        ParentId = ParentId,
        Name = Name,
        Kind = Kind,
        SortOrder = SortOrder,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        CredentialId = CredentialId,
        RdpDomain = RdpDomain,
        RdpScreenSize = RdpScreenSize,
        RdpFullScreen = RdpFullScreen,
        RdpColorDepth = RdpColorDepth,
        RdpUseAllMonitors = RdpUseAllMonitors,
        RdpAudioMode = RdpAudioMode,
        RdpAudioCaptureMode = RdpAudioCaptureMode,
        RdpKeyboardHookMode = RdpKeyboardHookMode,
        RdpRedirectClipboard = RdpRedirectClipboard,
        RdpRedirectPrinters = RdpRedirectPrinters,
        RdpRedirectSmartCards = RdpRedirectSmartCards,
        RdpRedirectPorts = RdpRedirectPorts,
        RdpRedirectDevices = RdpRedirectDevices,
        RdpRedirectDrives = RdpRedirectDrives,
        RdpConnectionSpeed = RdpConnectionSpeed,
        RdpDesktopBackground = RdpDesktopBackground,
        RdpFontSmoothing = RdpFontSmoothing,
        RdpDesktopComposition = RdpDesktopComposition,
        RdpWindowDrag = RdpWindowDrag,
        RdpMenuAnimation = RdpMenuAnimation,
        RdpVisualStyles = RdpVisualStyles,
        RdpBitmapCaching = RdpBitmapCaching,
        RdpAutoReconnect = RdpAutoReconnect,
        RdpServerAuthentication = RdpServerAuthentication,
        RdpGatewayUsageMethod = RdpGatewayUsageMethod,
        RdpGatewayHostname = RdpGatewayHostname,
        RdpGatewayCredentialId = RdpGatewayCredentialId,
        RdpGatewayBypassLocal = RdpGatewayBypassLocal,
        RdpGatewayUseSameCreds = RdpGatewayUseSameCreds,
        RdpUseExternalClient = RdpUseExternalClient,
        SshKeyFileName = SshKeyFileName,
        SshKnownHostFingerprint = SshKnownHostFingerprint,
        SshAutoSudo = SshAutoSudo,
        TunnelEnabled = TunnelEnabled,
        TunnelConfigId = TunnelConfigId,
        CreatedAt = CreatedAt,
        UpdatedAt = UpdatedAt,
    };
}
