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

    public bool? TunnelEnabled { get; set; }
    public Guid? TunnelConfigId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Return a new node preserving the source's identity (Id, parent linkage, audit
    /// timestamps, and SSH host-key state) but no editable fields. Used by the editor
    /// dialog (and its test fake) to materialise the "Save" result without mutating
    /// the input. Keep in sync with the field list — both the production
    /// <c>DialogService.EditConnectionAsync</c> and the test <c>FakeDialogService</c>
    /// rely on this single source of truth.
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
}
