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
    /// <summary>
    /// Tri-state binding for saved credentials: inherit from ancestors, explicitly use no saved
    /// credential, or use <see cref="CredentialId"/>. Null is the legacy shape:
    /// null + CredentialId = saved credential; null + no CredentialId = inherit.
    /// </summary>
    public CredentialBindingMode? CredentialMode { get; set; }

    /// <summary>
    /// When true, the connection authenticates with an inline, per-connection password the
    /// user typed in the editor rather than a saved <see cref="CredentialId"/> or a
    /// connect-time prompt. The password is stored in Windows Credential Manager keyed by
    /// <see cref="Id"/> (NOT in this row); this flag only records that such a secret exists.
    /// Applies to SSH/RDP; mutually exclusive with <see cref="CredentialId"/>. Null/false means
    /// "no inline password". Not inherited from folders (resolved from the leaf node only).
    /// </summary>
    public bool? UseInlinePassword { get; set; }

    /// <summary>
    /// Transient (NEVER persisted) hand-off of the inline login password from the connection
    /// editor to <c>ConnectionTreeViewModel</c>, which writes it to Credential Manager keyed by
    /// <see cref="Id"/> AFTER the DB row commits. Deliberately absent from
    /// <c>ConnectionRepository.Columns</c> so it is never written to or projected from SQLite,
    /// and cleared once the secret has been stored. Never logged.
    /// </summary>
    public string? PendingInlinePassword { get; set; }

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

    public int? SerialBaudRate { get; set; }
    public int? SerialDataBits { get; set; }
    public SerialStopBitsMode? SerialStopBits { get; set; }
    public SerialParityMode? SerialParity { get; set; }
    public SerialFlowControlMode? SerialFlowControl { get; set; }

    /// <summary>
    /// For the HTTPS web protocol: when true, accept certificate errors (self-signed, name
    /// mismatch, untrusted chain) when navigating. Per-connection (leaf-only) — NOT inherited from a
    /// parent folder (the editor surfaces it as a 2-state checkbox that can't express "inherit", so
    /// inheriting it would let an unrelated edit silently sever it). Null/false means "validate
    /// certificates". Ignored for non-web protocols.
    /// </summary>
    public bool? HttpIgnoreCertErrors { get; set; }

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
        CredentialMode = CredentialMode,
        UseInlinePassword = UseInlinePassword,
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
        SerialBaudRate = SerialBaudRate,
        SerialDataBits = SerialDataBits,
        SerialStopBits = SerialStopBits,
        SerialParity = SerialParity,
        SerialFlowControl = SerialFlowControl,
        HttpIgnoreCertErrors = HttpIgnoreCertErrors,
        TunnelEnabled = TunnelEnabled,
        TunnelConfigId = TunnelConfigId,
        CreatedAt = CreatedAt,
        UpdatedAt = UpdatedAt,
    };

    /// <summary>
    /// Full copy of every field but with a fresh <see cref="Id"/> and no per-host pinned
    /// state — used to duplicate a connection. Contrast <see cref="CloneIdentityFrom"/>, which
    /// keeps the source's Id and SSH host-key because an edit stays on the same host: a
    /// duplicate is a NEW identity the user typically repoints at a different host, so
    /// host-scoped state like <see cref="SshKnownHostFingerprint"/> must NOT carry over —
    /// otherwise <c>SshHostKeyValidator</c> rejects the new host as a Mismatch instead of
    /// TOFU-pinning on first connect. Add any future per-host/identity-scoped field reset here
    /// so the duplicate path can't silently keep copying it. Placement concerns (Name, ParentId,
    /// SortOrder) stay with the caller, which knows the tree context.
    /// </summary>
    public ConnectionNode CloneAsNewIdentity()
    {
        var copy = Clone();
        copy.Id = Guid.NewGuid();
        copy.SshKnownHostFingerprint = null;
        // Inline passwords are stored in Credential Manager keyed by Id, so they're scoped to
        // this identity exactly like host-key pinning. A fresh Id has no stored secret — drop
        // the flag so the duplicate doesn't claim an inline password it can't resolve.
        copy.UseInlinePassword = false;
        return copy;
    }
}
