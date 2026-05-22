using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.ViewModels;

/// <summary>
/// Backs the multi-tab connection editor dialog. Holds every editable field, exposes
/// LoadFrom/WriteTo for round-tripping with the persistence model, and surfaces validation
/// errors for the dialog to display inline. Protocol-specific tabs (Display / Local Resources /
/// Experience / Advanced) hide themselves when Protocol != Rdp via the IsRdp computed property.
/// </summary>
public partial class ConnectionEditorViewModel : ObservableObject
{
    private readonly ICredentialRepository _credentialRepository;
    private readonly List<CredentialProfile> _allCredentials = new();
    private bool _suppressPresetSync;

    public ConnectionEditorViewModel(ICredentialRepository credentialRepository)
    {
        _credentialRepository = credentialRepository;
    }

    /// <summary>
    /// Filtered view over <see cref="_allCredentials"/> for the current <see cref="Protocol"/>:
    /// SFTP connections show SSH credentials, SSH shows SSH, RDP shows RDP — and RDP excludes
    /// <see cref="CredentialKind.SshKey"/> since the RDP host only consumes the password secret.
    /// Rebuilt on load and whenever Protocol changes.
    /// </summary>
    public ObservableCollection<CredentialProfile> AvailableCredentials { get; } = new();

    #region General

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private string name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRdp), nameof(IsSsh), nameof(IsValid))]
    private ProtocolType protocol = ProtocolType.Ssh;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private string host = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private int? port;

    [ObservableProperty]
    private string username = string.Empty;

    [ObservableProperty]
    private string rdpDomain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedCredential))]
    private Guid? credentialId;

    public CredentialProfile? SelectedCredential
    {
        get => GetCredentialById(CredentialId);
        set => CredentialId = value?.Id;
    }

    public bool IsRdp => Protocol == ProtocolType.Rdp;
    public bool IsSsh => Protocol == ProtocolType.Ssh;

    #endregion

    #region Display

    /// <summary>Mstsc-style preset string ("640x480" … "Full screen"). Null/empty means
    /// "auto" (use the monitor work area, see <c>RdpHostForm.ResolveDesktopSize</c>).</summary>
    [ObservableProperty]
    private string? rdpScreenSize;

    [ObservableProperty]
    private bool rdpFullScreen;

    [ObservableProperty]
    private int rdpColorDepth = 32;

    [ObservableProperty]
    private bool rdpUseAllMonitors;

    public IReadOnlyList<int> ColorDepthChoices { get; } = new[] { 15, 16, 24, 32 };

    public IReadOnlyList<string> ScreenSizeChoices => RdpScreenSizes.Presets;

    #endregion

    #region Local Resources

    /// <summary>0=PlayHere, 1=DoNotPlay, 2=PlayRemote (mstsc default = 0).</summary>
    [ObservableProperty]
    private int rdpAudioMode;

    /// <summary>0=DoNotRecord, 1=Record (mstsc default = 0).</summary>
    [ObservableProperty]
    private int rdpAudioCaptureMode;

    /// <summary>0=Local, 1=Remote, 2=FullScreenOnly (mstsc default = 2).</summary>
    [ObservableProperty]
    private int rdpKeyboardHookMode = 2;

    [ObservableProperty]
    private bool rdpRedirectClipboard = true;

    [ObservableProperty]
    private bool rdpRedirectPrinters;

    [ObservableProperty]
    private bool rdpRedirectSmartCards;

    [ObservableProperty]
    private bool rdpRedirectPorts;

    [ObservableProperty]
    private bool rdpRedirectDevices;

    /// <summary>"none" | "all" | "custom". Drives the editor's radio group; persisted value
    /// is composed in <see cref="WriteTo"/>. Matches the sentinel pair in <see cref="RdpDriveList"/>.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCustomDriveList), nameof(CustomDriveListError), nameof(IsCustomDriveListErrorOpen), nameof(IsValid))]
    private string rdpDriveRedirectMode = "none";

    public bool IsCustomDriveList => string.Equals(RdpDriveRedirectMode, "custom", StringComparison.OrdinalIgnoreCase);

    /// <summary>Comma-separated upper-case letters when mode is "custom".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CustomDriveListError), nameof(IsCustomDriveListErrorOpen), nameof(IsValid))]
    private string rdpCustomDriveList = string.Empty;

    public string? CustomDriveListError => IsCustomDriveList ? RdpDriveList.Validate(RdpCustomDriveList) : null;

    public bool IsCustomDriveListErrorOpen => CustomDriveListError is not null;

    #endregion

    #region Experience

    /// <summary>1..7 matching IMsRdpClientAdvancedSettings6.NetworkConnectionType.
    /// 1=Modem, 2=BroadbandLow, 3=Satellite, 4=BroadbandHigh, 5=WAN, 6=LAN, 7=AutoDetect.</summary>
    [ObservableProperty]
    private int rdpConnectionSpeed = 7;

    partial void OnRdpConnectionSpeedChanged(int value)
    {
        if (_suppressPresetSync) return;
        ApplyExperiencePreset(value);
    }

    [ObservableProperty]
    private bool rdpDesktopBackground = true;
    [ObservableProperty]
    private bool rdpFontSmoothing = true;
    [ObservableProperty]
    private bool rdpDesktopComposition = true;
    [ObservableProperty]
    private bool rdpWindowDrag = true;
    [ObservableProperty]
    private bool rdpMenuAnimation = true;
    [ObservableProperty]
    private bool rdpVisualStyles = true;
    [ObservableProperty]
    private bool rdpBitmapCaching = true;
    [ObservableProperty]
    private bool rdpAutoReconnect = true;

    public IReadOnlyList<KeyValuePair<int, string>> ConnectionSpeedChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(1, "Modem (56 Kbps)"),
        new KeyValuePair<int, string>(2, "Low-speed broadband (256 Kbps – 2 Mbps)"),
        new KeyValuePair<int, string>(3, "Satellite (2 – 16 Mbps with high latency)"),
        new KeyValuePair<int, string>(4, "High-speed broadband (2 – 10 Mbps)"),
        new KeyValuePair<int, string>(5, "WAN (10 Mbps or higher with high latency)"),
        new KeyValuePair<int, string>(6, "LAN (10 Mbps or higher)"),
        new KeyValuePair<int, string>(7, "Detect connection quality automatically"),
    };

    #endregion

    #region Advanced

    /// <summary>0=Warn, 1=Require / fail-closed, 2=DoNotConnect.</summary>
    [ObservableProperty]
    private int rdpServerAuthentication;

    /// <summary>0=Direct (no gateway), 1=AlwaysUseGateway, 2=AutoDetect, 3=DefaultRdg.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsGatewayEnabled), nameof(GatewayHostnameError), nameof(IsGatewayHostnameErrorOpen), nameof(IsValid))]
    private int rdpGatewayUsageMethod;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(GatewayHostnameError), nameof(IsGatewayHostnameErrorOpen), nameof(IsValid))]
    private string rdpGatewayHostname = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedGatewayCredential))]
    private Guid? rdpGatewayCredentialId;

    public CredentialProfile? SelectedGatewayCredential
    {
        get => GetCredentialById(RdpGatewayCredentialId);
        set => RdpGatewayCredentialId = value?.Id;
    }

    private CredentialProfile? GetCredentialById(Guid? id) =>
        id is null ? null : AvailableCredentials.FirstOrDefault(c => c.Id == id);

    [ObservableProperty]
    private bool rdpGatewayBypassLocal = true;

    [ObservableProperty]
    private bool rdpGatewayUseSameCreds;

    public bool IsGatewayEnabled => RdpGatewayUsageMethod != 0;

    /// <summary>
    /// Only mode 1 ("Always use an RD Gateway server") requires the user to supply a hostname.
    /// Mode 2 ("Detect automatically") resolves the gateway from network/admin policy and mode 3
    /// ("Use default RD Gateway server settings") inherits the hostname from the system default
    /// profile — both are valid configurations with an empty hostname.
    /// </summary>
    public string? GatewayHostnameError =>
        RdpGatewayUsageMethod == 1 && string.IsNullOrWhiteSpace(RdpGatewayHostname)
            ? "Gateway hostname is required when 'Always use an RD Gateway server' is selected."
            : null;

    public bool IsGatewayHostnameErrorOpen => GatewayHostnameError is not null;

    public IReadOnlyList<KeyValuePair<int, string>> GatewayUsageChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(0, "Direct connection (no gateway)"),
        new KeyValuePair<int, string>(1, "Always use an RD Gateway server"),
        new KeyValuePair<int, string>(2, "Detect RD Gateway server settings automatically"),
        new KeyValuePair<int, string>(3, "Use default RD Gateway server settings"),
    };

    public IReadOnlyList<KeyValuePair<int, string>> AudioModeChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(0, "Play on this computer"),
        new KeyValuePair<int, string>(1, "Do not play"),
        new KeyValuePair<int, string>(2, "Play on remote computer"),
    };

    public IReadOnlyList<KeyValuePair<int, string>> AudioCaptureChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(0, "Do not record"),
        new KeyValuePair<int, string>(1, "Record from this computer"),
    };

    public IReadOnlyList<KeyValuePair<int, string>> KeyboardHookChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(0, "On the local computer"),
        new KeyValuePair<int, string>(1, "On the remote computer"),
        new KeyValuePair<int, string>(2, "Only when using the full screen"),
    };

    public IReadOnlyList<KeyValuePair<int, string>> ServerAuthChoices { get; } = new[]
    {
        new KeyValuePair<int, string>(0, "Warn me about server authentication failures"),
        new KeyValuePair<int, string>(1, "Require server authentication"),
        new KeyValuePair<int, string>(2, "Do not connect if authentication fails"),
    };

    #endregion

    public bool IsValid
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Name)) return false;
            if (string.IsNullOrWhiteSpace(Host)) return false;
            // Port is int?: null means "use the inherited / protocol-default port" (the
            // "Default for protocol" NumberBox placeholder). C# property pattern matching
            // treats null as not matching either side, so this only rejects an explicit
            // out-of-range value — not null.
            if (Port is < 1 or > 65535) return false;
            if (IsRdp)
            {
                if (GatewayHostnameError is not null) return false;
                if (CustomDriveListError is not null) return false;
            }
            return true;
        }
    }

    public async Task LoadCredentialsAsync()
    {
        var creds = await _credentialRepository.GetAllAsync().ConfigureAwait(true);
        _allCredentials.Clear();
        _allCredentials.AddRange(creds);
        RebuildAvailableCredentials();
    }

    /// <summary>
    /// Rebuild <see cref="AvailableCredentials"/> from <see cref="_allCredentials"/> using the
    /// current Protocol. A currently-selected credential whose protocol no longer matches the
    /// filter is preserved as a "stale" entry so edit-round-tripping doesn't silently drop the
    /// binding — but new credentials offered to the user are filtered to compatible ones only.
    /// </summary>
    private void RebuildAvailableCredentials()
    {
        var credentialProtocol = CredentialProtocolFor(Protocol);
        var connectionIsRdp = Protocol == ProtocolType.Rdp;

        AvailableCredentials.Clear();
        foreach (var c in _allCredentials)
        {
            if (c.Protocol != credentialProtocol) continue;
            // RDP login only consumes the password secret — SSH-key credentials would force the
            // user into a misleading prompt path. Filter them out.
            if (connectionIsRdp && c.Kind == CredentialKind.SshKey) continue;
            AvailableCredentials.Add(c);
        }

        // Preserve the existing main + gateway selections when they no longer match the filter
        // so edit round-trip doesn't lose the binding on a saved node.
        AppendStaleSelection(CredentialId);
        AppendStaleSelection(RdpGatewayCredentialId);

        OnPropertyChanged(nameof(SelectedCredential));
        OnPropertyChanged(nameof(SelectedGatewayCredential));
    }

    private void AppendStaleSelection(Guid? id)
    {
        if (id is not { } guid) return;
        if (AvailableCredentials.Any(c => c.Id == guid)) return;
        var stale = _allCredentials.FirstOrDefault(c => c.Id == guid);
        if (stale is not null) AvailableCredentials.Add(stale);
    }

    /// <summary>SFTP connections reuse SSH credentials per the project's credential model
    /// (the credential dialog doesn't even let users create SFTP-tagged credentials).</summary>
    private static ProtocolType CredentialProtocolFor(ProtocolType connectionProtocol) =>
        connectionProtocol == ProtocolType.Sftp ? ProtocolType.Ssh : connectionProtocol;

    partial void OnProtocolChanged(ProtocolType value)
    {
        // When the user explicitly switches the connection protocol, drop a previously-bound
        // credential that no longer matches the new filter. The alternative — preserving it as
        // a stale entry — would silently expose a protocol-incompatible binding on save.
        if (CredentialId is { } id && _allCredentials.FirstOrDefault(c => c.Id == id) is { } cred)
        {
            var expectedProtocol = CredentialProtocolFor(value);
            var connectionIsRdp = value == ProtocolType.Rdp;
            var stillCompatible = cred.Protocol == expectedProtocol
                && (!connectionIsRdp || cred.Kind != CredentialKind.SshKey);
            if (!stillCompatible) CredentialId = null;
        }
        // Gateway credential is RDP-only — switching away from RDP makes it meaningless.
        if (value != ProtocolType.Rdp) RdpGatewayCredentialId = null;

        RebuildAvailableCredentials();
    }

    // Pull a stale (protocol-mismatched) credential into AvailableCredentials when LoadFrom
    // assigns one — without this, the ComboBox round-trips to its placeholder on edit and the
    // user loses sight of the saved binding.
    partial void OnCredentialIdChanged(Guid? value)
    {
        if (value is { } id && !AvailableCredentials.Any(c => c.Id == id))
        {
            AppendStaleSelection(id);
            OnPropertyChanged(nameof(SelectedCredential));
        }
    }

    partial void OnRdpGatewayCredentialIdChanged(Guid? value)
    {
        if (value is { } id && !AvailableCredentials.Any(c => c.Id == id))
        {
            AppendStaleSelection(id);
            OnPropertyChanged(nameof(SelectedGatewayCredential));
        }
    }

    public void LoadFrom(ConnectionNode node)
    {
        Name = node.Name;
        Protocol = node.Protocol ?? ProtocolType.Ssh;
        Host = node.Host ?? string.Empty;
        Port = node.Port;
        Username = node.Username ?? string.Empty;
        RdpDomain = node.RdpDomain ?? string.Empty;
        CredentialId = node.CredentialId;

        RdpScreenSize = node.RdpScreenSize;
        RdpFullScreen = node.RdpFullScreen ?? false;
        RdpColorDepth = node.RdpColorDepth ?? 32;
        RdpUseAllMonitors = node.RdpUseAllMonitors ?? false;

        RdpAudioMode = node.RdpAudioMode ?? 0;
        RdpAudioCaptureMode = node.RdpAudioCaptureMode ?? 0;
        RdpKeyboardHookMode = node.RdpKeyboardHookMode ?? 2;
        RdpRedirectClipboard = node.RdpRedirectClipboard ?? true;
        RdpRedirectPrinters = node.RdpRedirectPrinters ?? false;
        RdpRedirectSmartCards = node.RdpRedirectSmartCards ?? false;
        RdpRedirectPorts = node.RdpRedirectPorts ?? false;
        RdpRedirectDevices = node.RdpRedirectDevices ?? false;
        var drives = node.RdpRedirectDrives ?? string.Empty;
        if (string.IsNullOrEmpty(drives))
        {
            RdpDriveRedirectMode = "none";
            RdpCustomDriveList = string.Empty;
        }
        else if (string.Equals(drives, RdpDriveList.AllSentinel, StringComparison.OrdinalIgnoreCase))
        {
            RdpDriveRedirectMode = "all";
            RdpCustomDriveList = string.Empty;
        }
        else
        {
            RdpDriveRedirectMode = "custom";
            RdpCustomDriveList = drives;
        }

        // Avoid the preset side-effect during bulk load — the persisted experience flags below
        // are the source of truth. try/finally ensures the flag is cleared even if a future
        // setter throws.
        _suppressPresetSync = true;
        try { RdpConnectionSpeed = node.RdpConnectionSpeed ?? 7; }
        finally { _suppressPresetSync = false; }

        RdpDesktopBackground = node.RdpDesktopBackground ?? true;
        RdpFontSmoothing = node.RdpFontSmoothing ?? true;
        RdpDesktopComposition = node.RdpDesktopComposition ?? true;
        RdpWindowDrag = node.RdpWindowDrag ?? true;
        RdpMenuAnimation = node.RdpMenuAnimation ?? true;
        RdpVisualStyles = node.RdpVisualStyles ?? true;
        RdpBitmapCaching = node.RdpBitmapCaching ?? true;
        RdpAutoReconnect = node.RdpAutoReconnect ?? true;

        RdpServerAuthentication = node.RdpServerAuthentication ?? 0;
        RdpGatewayUsageMethod = node.RdpGatewayUsageMethod ?? 0;
        RdpGatewayHostname = node.RdpGatewayHostname ?? string.Empty;
        RdpGatewayCredentialId = node.RdpGatewayCredentialId;
        RdpGatewayBypassLocal = node.RdpGatewayBypassLocal ?? true;
        RdpGatewayUseSameCreds = node.RdpGatewayUseSameCreds ?? false;
    }

    public void WriteTo(ConnectionNode node)
    {
        node.Name = Name.Trim();
        node.Protocol = Protocol;
        node.Host = Host.Trim();
        node.Port = Port;
        // The free-text Username field is shown alongside the credential picker so users can
        // override the credential's stored username on a per-connection basis. When the field
        // is blank, fall back to the selected credential's username — without this fallback,
        // a credential-backed SSH connection with a blank Username field would persist a
        // null username and SshSessionService would reject the connect.
        if (!string.IsNullOrWhiteSpace(Username))
        {
            node.Username = Username.Trim();
        }
        else if (SelectedCredential is { Username: var credUser } && !string.IsNullOrWhiteSpace(credUser))
        {
            node.Username = credUser;
        }
        else
        {
            node.Username = null;
        }
        node.CredentialId = CredentialId;

        if (IsRdp)
        {
            node.RdpDomain = string.IsNullOrWhiteSpace(RdpDomain) ? null : RdpDomain.Trim();
            node.RdpScreenSize = string.IsNullOrWhiteSpace(RdpScreenSize) ? null : RdpScreenSize;
            node.RdpFullScreen = RdpFullScreen;
            node.RdpColorDepth = RdpColorDepth;
            node.RdpUseAllMonitors = RdpUseAllMonitors;

            node.RdpAudioMode = RdpAudioMode;
            node.RdpAudioCaptureMode = RdpAudioCaptureMode;
            node.RdpKeyboardHookMode = RdpKeyboardHookMode;
            node.RdpRedirectClipboard = RdpRedirectClipboard;
            node.RdpRedirectPrinters = RdpRedirectPrinters;
            node.RdpRedirectSmartCards = RdpRedirectSmartCards;
            node.RdpRedirectPorts = RdpRedirectPorts;
            node.RdpRedirectDevices = RdpRedirectDevices;
            node.RdpRedirectDrives = RdpDriveRedirectMode switch
            {
                "all" => RdpDriveList.AllSentinel,
                "custom" => RdpDriveList.Normalise(RdpCustomDriveList),
                _ => string.Empty,
            };

            node.RdpConnectionSpeed = RdpConnectionSpeed;
            node.RdpDesktopBackground = RdpDesktopBackground;
            node.RdpFontSmoothing = RdpFontSmoothing;
            node.RdpDesktopComposition = RdpDesktopComposition;
            node.RdpWindowDrag = RdpWindowDrag;
            node.RdpMenuAnimation = RdpMenuAnimation;
            node.RdpVisualStyles = RdpVisualStyles;
            node.RdpBitmapCaching = RdpBitmapCaching;
            node.RdpAutoReconnect = RdpAutoReconnect;

            node.RdpServerAuthentication = RdpServerAuthentication;
            node.RdpGatewayUsageMethod = RdpGatewayUsageMethod;
            node.RdpGatewayHostname = string.IsNullOrWhiteSpace(RdpGatewayHostname) ? null : RdpGatewayHostname.Trim();
            node.RdpGatewayCredentialId = RdpGatewayCredentialId;
            node.RdpGatewayBypassLocal = RdpGatewayBypassLocal;
            node.RdpGatewayUseSameCreds = RdpGatewayUseSameCreds;
        }
    }

    /// <summary>
    /// Apply the mstsc experience preset for a given NetworkConnectionType. Modem disables
    /// every visual feature except bitmap caching; LAN/AutoDetect enables everything.
    /// </summary>
    public void ApplyExperiencePreset(int speed)
    {
        switch (speed)
        {
            case 1: // Modem
                RdpDesktopBackground = false;
                RdpFontSmoothing = false;
                RdpDesktopComposition = false;
                RdpWindowDrag = false;
                RdpMenuAnimation = false;
                RdpVisualStyles = false;
                RdpBitmapCaching = true;
                break;
            case 2: // Low-broadband
                RdpDesktopBackground = false;
                RdpFontSmoothing = false;
                RdpDesktopComposition = false;
                RdpWindowDrag = false;
                RdpMenuAnimation = false;
                RdpVisualStyles = true;
                RdpBitmapCaching = true;
                break;
            case 3: // Satellite
                RdpDesktopBackground = false;
                RdpFontSmoothing = false;
                RdpDesktopComposition = true;
                RdpWindowDrag = false;
                RdpMenuAnimation = false;
                RdpVisualStyles = true;
                RdpBitmapCaching = true;
                break;
            case 4: // High-broadband
                RdpDesktopBackground = false;
                RdpFontSmoothing = true;
                RdpDesktopComposition = true;
                RdpWindowDrag = true;
                RdpMenuAnimation = true;
                RdpVisualStyles = true;
                RdpBitmapCaching = true;
                break;
            case 5: // WAN
            case 6: // LAN
            case 7: // Auto-detect → LAN baseline
                RdpDesktopBackground = true;
                RdpFontSmoothing = true;
                RdpDesktopComposition = true;
                RdpWindowDrag = true;
                RdpMenuAnimation = true;
                RdpVisualStyles = true;
                RdpBitmapCaching = true;
                break;
        }
    }

    /// <summary>Convenience pass-through so tests don't need to know about <see cref="RdpDriveList"/>.</summary>
    public static string? ValidateDriveList(string raw) => RdpDriveList.Validate(raw);

    /// <summary>Convenience pass-through so tests don't need to know about <see cref="RdpDriveList"/>.</summary>
    public static string NormaliseDriveList(string raw) => RdpDriveList.Normalise(raw);
}
