using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;

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
    private readonly ICredentialService _credentialService;
    private readonly List<CredentialProfile> _allCredentials = new();
    private readonly Dictionary<Guid, CredentialProfile> _allCredentialsById = new();
    private readonly Dictionary<Guid, CredentialProfile> _availableCredentialsById = new();
    private readonly Dictionary<Guid, CredentialProfile> _availableGatewayCredentialsById = new();
    private bool _suppressPresetSync;
    private bool _suppressAadAutoFlag;
    // True when the editor (not the user, not the persisted DB value) set RdpUseExternalClient
    // to true via the AAD auto-flag handlers. Tracks ownership so we can auto-untick when the
    // last AAD signal is cleared — otherwise the user is left with a ticked-and-editable
    // checkbox they never asked for after correcting a typo'd "AzureAD" Domain value.
    private bool _autoFlagAppliedByAad;
    // The node's own SshAutoSudo value as loaded (null = inherits a folder default). Remembered
    // so WriteTo can leave an untouched checkbox alone instead of baking the displayed default
    // (false) back over an inherited value — otherwise merely renaming an inheriting connection
    // would sever its inheritance. Null for a brand-new connection (LoadFrom never ran).
    private bool? _loadedSshAutoSudo;
    // The node being edited, captured in LoadFrom so the dialog can read this connection's
    // inline password (keyed by node Id) for an edit. Guid.Empty for a brand-new connection.
    private Guid _editingNodeId;
    // The node's own UseInlinePassword as loaded, so LoadInlineSecretAsync only reads a secret
    // for a connection that actually has one.
    private bool _loadedUseInlinePassword;

    public ConnectionEditorViewModel(
        ICredentialRepository credentialRepository,
        ITunnelConfigRepository tunnelConfigRepository,
        ICredentialService credentialService)
    {
        _credentialRepository = credentialRepository;
        _credentialService = credentialService;
        TunnelPicker = new TunnelPickerViewModel(tunnelConfigRepository);
    }

    /// <summary>Tri-state VPN picker — bound by the General tab. Shared with FolderEditorViewModel
    /// via the extracted sub-VM; the connection editor uses the default "(Inherit from folder)"
    /// inherit-label.</summary>
    public TunnelPickerViewModel TunnelPicker { get; }

    /// <summary>
    /// Filtered view over <see cref="_allCredentials"/> for the current <see cref="Protocol"/>:
    /// SSH shows SSH, RDP shows RDP — and RDP excludes <see cref="CredentialKind.SshKey"/> since
    /// the RDP host only consumes the password secret. Rebuilt on load and whenever Protocol changes.
    /// </summary>
    public BulkObservableCollection<CredentialProfile> AvailableCredentials { get; } = new();

    /// <summary>
    /// RD Gateway uses the same protocol-filtered credential pool, but it has no folder
    /// inheritance state. Keep its picker separate so the main connection picker can offer
    /// "(Inherit from folder)" without leaking that sentinel into gateway credentials.
    /// </summary>
    public BulkObservableCollection<CredentialProfile> AvailableGatewayCredentials { get; } = new();

    #region General

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private string name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRdp), nameof(IsSsh), nameof(IsVnc), nameof(IsSerial), nameof(IsHttp), nameof(IsHttps), nameof(ShowCredentialSection), nameof(ShowTunnelSection), nameof(ShowPortBox), nameof(HostHeader), nameof(HostPlaceholder), nameof(IsValid), nameof(CanUseSshAutoSudo), nameof(ShowInlinePassword), nameof(ShowConnectionUsername), nameof(ShowRdpDomain), nameof(HttpAddressError), nameof(IsHttpAddressErrorOpen))]
    private ProtocolType protocol = ProtocolType.Ssh;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid), nameof(HttpAddressError), nameof(IsHttpAddressErrorOpen))]
    private string host = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private int? port;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsAzureAdCredential), nameof(IsRdpUseExternalClientEditable))]
    private string username = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsAzureAdCredential), nameof(IsRdpUseExternalClientEditable), nameof(ShowRdpDomain))]
    private string rdpDomain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedCredential), nameof(IsAzureAdCredential), nameof(IsRdpUseExternalClientEditable), nameof(CanUseSshAutoSudo), nameof(ShowRdpDomain))]
    private Guid? credentialId;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedCredential), nameof(IsAzureAdCredential), nameof(IsRdpUseExternalClientEditable), nameof(CanUseSshAutoSudo), nameof(ShowRdpDomain))]
    private CredentialBindingMode? credentialMode;

    /// <summary>
    /// Drives the credential mode toggle. When true (default), the connection uses a saved
    /// credential (the picker is shown, the inline Username/Password hidden). When false, the
    /// user supplies an inline Username and, for SSH/RDP, an inline <see cref="InlinePassword"/>.
    /// Maps to <see cref="ConnectionNode.UseInlinePassword"/> (inverted) in WriteTo.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowInlinePassword), nameof(ShowConnectionUsername), nameof(ShowRdpDomain), nameof(CanUseSshAutoSudo))]
    private bool useSavedCredentials = true;

    /// <summary>The inline login password (bound to the editor's PasswordBox). SSH/RDP,
    /// persisted to Credential Manager keyed by the node Id. Never logged.</summary>
    [ObservableProperty]
    private string inlinePassword = string.Empty;

    /// <summary>The inline Password field is shown for SSH/RDP connections that aren't using a
    /// saved credential. Web protocols do not use credentials.</summary>
    public bool ShowInlinePassword => (IsSsh || IsRdp) && !UseSavedCredentials;

    /// <summary>
    /// Connection-level username is meaningful for SSH/RDP prompt mode. VNC v1 uses no-auth or
    /// password-only auth, so the username field stays hidden even when saved credentials are off.
    /// </summary>
    public bool ShowConnectionUsername => !UseSavedCredentials && (IsSsh || IsRdp);

    /// <summary>
    /// Drives the connection-level Domain field's visibility. Hidden only when a resolved RDP
    /// credential fully supplies the domain and the node adds nothing — an RDP connection using a
    /// real RDP saved credential (<see cref="HasResolvedRdpCredential"/>) whose node-level
    /// <see cref="RdpDomain"/> is empty or merely duplicates that credential's domain. An RDP saved
    /// credential always carries its own (mandatory) domain, so a redundant node-level value is just
    /// clutter; hiding the field here mirrors how the Username field hides under a saved credential.
    /// <para>
    /// It stays visible whenever the node holds a value the user still needs to see or fix: inline /
    /// connect-time-prompt mode (<see cref="UseSavedCredentials"/> false); the "(None) — prompt every
    /// time" selection; a non-null <see cref="CredentialId"/> that doesn't resolve to a real RDP
    /// credential — deleted, unloaded, or a stale protocol-mismatched credential
    /// (<see cref="HasResolvedRdpCredential"/>); and a distinct override that differs from the
    /// credential's own domain (<see cref="HasDistinctRdpDomainOverride"/>). Keeping a distinct
    /// override visible is what stops a value that wins at connect (<c>explicitDomain ?? credentialDomain</c>
    /// in <see cref="Sessions.RdpSessionViewModel"/>) from becoming an invisible override the user
    /// can't discover or clear. The "(None)" case is also load-bearing for the AzureAD "prompt every
    /// time" workflow, where the user types <c>AzureAD</c> into this field to route RDP externally.
    /// </para>
    /// </summary>
    public bool ShowRdpDomain =>
        IsRdp && (!UseSavedCredentials || !HasResolvedRdpCredential || HasDistinctRdpDomainOverride);

    /// <summary>
    /// Tri-state Auto sudo selection: "inherit" (null — follow the folder default), "on" (true —
    /// run "sudo su" and send the saved password on connect), or "off" (false — explicit override).
    /// Modelled as a string to reuse the editor's existing radio/combo binding style; mapped to a
    /// <c>bool?</c> in <see cref="WriteTo"/>. A plain checkbox couldn't express "inherit" vs an
    /// explicit "off", so a child that inherits Auto sudo on from a folder could neither be shown
    /// honestly nor be overridden off — hence the tri-state, mirroring the inheritable tunnel
    /// setting.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SshAutoSudoDescription))]
    private string sshAutoSudoMode = SshAutoSudoInherit;

    internal const string SshAutoSudoInherit = "inherit";
    internal const string SshAutoSudoOn = "on";
    internal const string SshAutoSudoOff = "off";

    public IReadOnlyList<KeyValuePair<string, string>> SshAutoSudoChoices { get; } = new[]
    {
        new KeyValuePair<string, string>(SshAutoSudoInherit, "Inherit from folder"),
        new KeyValuePair<string, string>(SshAutoSudoOn, "On"),
        new KeyValuePair<string, string>(SshAutoSudoOff, "Off"),
    };

    /// <summary>
    /// Short, value-specific help for the Auto sudo control, shown under the picker and updated
    /// as the selection changes (vs. the old single static paragraph covering all three values).
    /// The "on" text keeps the load-bearing caveat that the password isn't sent when sudo
    /// doesn't actually prompt.
    /// </summary>
    public string SshAutoSudoDescription => SshAutoSudoMode switch
    {
        SshAutoSudoOn => "Runs “sudo su” on connect and sends the saved password at the prompt. " +
                         "If sudo doesn’t prompt (NOPASSWD or cached), nothing is sent.",
        SshAutoSudoOff => "Never runs sudo automatically on connect.",
        _ => "Follows the parent folder’s Auto sudo setting.",
    };

    /// <summary>
    /// Drives the Auto sudo control's visibility. Shown for an SSH connection unless the node's own
    /// selected credential is an SSH <em>key</em> — the one case with provably no login password
    /// (the secret is a key passphrase, so <see cref="SshCredentialResolver"/> never yields a
    /// password and the runtime driver can't run). Every other case keeps the control visible
    /// because the runtime resolves a usable password: an own password credential, an inherited
    /// credential (own CredentialId is null here since the editor doesn't resolve folder
    /// inheritance — the "(None)" sentinel is <see cref="CredentialKind.Password"/>), or
    /// "prompt every time" (the resolver prompts and captures a password). Hiding only the
    /// definitely-no-password case lets a child override an inherited Auto sudo on/off; when hidden,
    /// WriteTo leaves the loaded value untouched rather than clobbering it.
    /// <para>
    /// In inline-password mode (<see cref="UseSavedCredentials"/> false) the saved credential is
    /// irrelevant — the inline password (or a connect-time prompt) supplies a usable password — so
    /// the control is shown regardless of any now-unused selected credential, even an SSH key. This
    /// keys off <see cref="UseSavedCredentials"/> (not the stale <see cref="CredentialId"/>) so
    /// switching an SSH-key connection to an inline password reveals Auto sudo immediately.
    /// </para>
    /// </summary>
    public bool CanUseSshAutoSudo => IsSsh && (!UseSavedCredentials || SelectedCredential?.Kind != CredentialKind.SshKey);

    /// <summary>Sentinel for "inherit from folder". AutoSuggestBox.PlaceholderText
    /// isn't selectable, so the picker needs a real item to round-trip to.</summary>
    internal static readonly CredentialProfile InheritCredential = new()
    {
        Id = CredentialBindingSentinelIds.Inherit,
        Name = "(Inherit from folder)",
    };

    /// <summary>Sentinel for "no credential — prompt every time". ComboBox.PlaceholderText
    /// isn't selectable, so the picker needs a real item to round-trip to. Both selection
    /// getters return this when the underlying id is null; setters map it back to null.</summary>
    internal static readonly CredentialProfile NoneCredential = new()
    {
        Id = CredentialBindingSentinelIds.ConnectionNone,
        Name = "(None — prompt every time)",
    };

    public CredentialProfile? SelectedCredential
    {
        get
        {
            return EffectiveCredentialMode switch
            {
                CredentialBindingMode.Inherit => InheritCredential,
                CredentialBindingMode.None => NoneCredential,
                CredentialBindingMode.Saved => CredentialId is { } id ? GetCredentialById(id) : null,
                _ => InheritCredential,
            };
        }
        set
        {
            if (value is null || value.Id == InheritCredential.Id)
            {
                CredentialId = null;
                CredentialMode = CredentialBindingMode.Inherit;
            }
            else if (value.Id == NoneCredential.Id)
            {
                CredentialId = null;
                CredentialMode = CredentialBindingMode.None;
            }
            else
            {
                CredentialId = value.Id;
                CredentialMode = CredentialBindingMode.Saved;
            }
        }
    }

    private CredentialBindingMode EffectiveCredentialMode =>
        CredentialMode ?? (CredentialId is null ? CredentialBindingMode.Inherit : CredentialBindingMode.Saved);

    /// <summary>
    /// True only when <see cref="CredentialId"/> resolves to a saved credential that actually carries
    /// the RDP domain: a real <see cref="ProtocolType.Rdp"/> credential whose secret is a password
    /// (only those store a domain — see <c>CredentialDialog.BuildDraft</c>, and they're the same
    /// credentials <see cref="RebuildAvailableCredentials"/> offers for RDP). This excludes three
    /// look-alikes that supply no domain and must therefore leave the Domain field editable: the
    /// "(None) — prompt every time" sentinel; a dangling id whose credential was deleted or never
    /// loaded (<see cref="SelectedCredential"/> is null); and a stale, protocol-mismatched credential
    /// that <see cref="AppendStaleSelection"/> preserved for round-tripping (e.g. an SSH credential
    /// bound to an RDP node). Gates hiding the node-level Domain field — using this rather than a bare
    /// <c>CredentialId is not null</c> keeps that field available whenever nothing authoritative can
    /// supply the domain.
    /// </summary>
    private bool HasResolvedRdpCredential =>
        SelectedCredential is { Protocol: ProtocolType.Rdp, Kind: not CredentialKind.SshKey };

    /// <summary>
    /// True when the node-level <see cref="RdpDomain"/> is a meaningful override of the resolved RDP
    /// credential's own domain: non-empty and different (case-insensitively) from
    /// <see cref="SelectedCredential"/>'s domain. Such a value wins at connect
    /// (<c>explicitDomain ?? credentialDomain</c>), so the Domain field stays visible for it even with
    /// a credential selected — whereas a value that only duplicates the credential's domain is
    /// redundant and hides. Comparing against the credential's domain (rather than merely checking
    /// "non-empty") is what lets the original decluttering goal — hide a redundant duplicate — coexist
    /// with never hiding a value that actually changes the connection.
    /// </summary>
    private bool HasDistinctRdpDomainOverride =>
        !string.IsNullOrWhiteSpace(RdpDomain)
        && !string.Equals(RdpDomain.Trim(), SelectedCredential?.Domain?.Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when any AAD signal is present: the linked saved credential's Domain/Username,
    /// or the node-level <see cref="Username"/>/<see cref="RdpDomain"/> fields the user types
    /// into directly (covers "Prompt every time" connections that have no saved credential).
    /// Drives the editor's auto-flag of <see cref="RdpUseExternalClient"/> on credential change
    /// (see <see cref="OnCredentialIdChanged"/>), the InfoBar shown next to the credential
    /// picker, and the disabled state of the external-client checkbox.
    /// </summary>
    public bool IsAzureAdCredential =>
        AzureAdCredentialDetector.IsAzureAd(SelectedCredential)
        || AzureAdCredentialDetector.HasAzureAdDomain(RdpDomain)
        || AzureAdCredentialDetector.HasAzureAdPrefix(Username);

    /// <summary>
    /// False when the AAD heuristic matched — the embedded host would crash on connect, so
    /// <see cref="ViewModels.Sessions.RdpSessionViewModel"/> routes external regardless of
    /// <see cref="RdpUseExternalClient"/>. The checkbox is disabled so the user understands
    /// the override is unavailable for AAD targets (vs. silently ignored). For non-AAD targets
    /// it stays editable as the manual opt-in.
    /// </summary>
    public bool IsRdpUseExternalClientEditable => !IsAzureAdCredential;

    public bool IsRdp => Protocol == ProtocolType.Rdp;
    public bool IsSsh => Protocol == ProtocolType.Ssh;
    public bool IsVnc => Protocol == ProtocolType.Vnc;
    public bool IsSerial => Protocol == ProtocolType.Serial;

    /// <summary>True for the web protocols (<see cref="ProtocolType.Http"/> / <see cref="ProtocolType.Https"/>),
    /// which render in an embedded browser and need no credentials.</summary>
    public bool IsHttp => Protocol is ProtocolType.Http or ProtocolType.Https;

    /// <summary>True only for HTTPS — gates the "ignore certificate errors" control.</summary>
    public bool IsHttps => Protocol == ProtocolType.Https;

    public bool ShowPortBox => !IsHttp && !IsSerial;

    public string HostHeader => IsSerial ? "Serial line" : IsHttp ? "Address" : "Host";

    public string HostPlaceholder => IsSerial ? "COM1" : IsHttp ? "10.0.0.1:8443" : "example.com";

    /// <summary>The credential block (saved credentials, inline username/password, domain, auto-sudo) is
    /// shown for SSH/RDP/VNC but hidden for credential-less web and serial protocols.</summary>
    public bool ShowCredentialSection => IsSsh || IsRdp || IsVnc;

    /// <summary>VPN routing is meaningful for network protocols only; serial ports are local devices.</summary>
    public bool ShowTunnelSection => !IsSerial;

    /// <summary>
    /// Validation error for the web "address" field: non-null when the entered host (after stripping any
    /// port/scheme) isn't a usable host name or IP, e.g. ":8443" (no host) or "host:99999" (out-of-range
    /// port folds into the host). Keeps a malformed address from saving and later throwing a
    /// UriFormatException at connect. Null for non-web protocols and for a blank field (the generic
    /// "host required" rule in <see cref="IsValid"/> covers blank).
    /// </summary>
    public string? HttpAddressError
    {
        get
        {
            if (!IsHttp || string.IsNullOrWhiteSpace(Host)) return null;
            var (parsedHost, _) = ParseHttpAddress(Host);
            return string.IsNullOrEmpty(parsedHost) || Uri.CheckHostName(parsedHost) == UriHostNameType.Unknown
                ? "Enter a valid host or IP — optionally with a port, e.g. 10.0.0.1:8443."
                : null;
        }
    }

    public bool IsHttpAddressErrorOpen => HttpAddressError is not null;

    /// <summary>
    /// Accept certificate errors when navigating an HTTPS connection (self-signed appliance certs).
    /// Persisted to <see cref="ConnectionNode.HttpIgnoreCertErrors"/>; only meaningful for HTTPS.
    /// </summary>
    [ObservableProperty]
    private bool httpIgnoreCertErrors;

    #endregion

    #region Serial

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private int serialBaudRate = SerialDefaults.BaudRate;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private bool serialBaudRateInherits;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private int serialDataBits = SerialDefaults.DataBits;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private bool serialDataBitsInherits;

    [ObservableProperty]
    private SerialStopBitsMode serialStopBits = SerialDefaults.StopBits;

    [ObservableProperty]
    private bool serialStopBitsInherits;

    [ObservableProperty]
    private SerialParityMode serialParity = SerialDefaults.Parity;

    [ObservableProperty]
    private bool serialParityInherits;

    [ObservableProperty]
    private SerialFlowControlMode serialFlowControl = SerialDefaults.FlowControl;

    [ObservableProperty]
    private bool serialFlowControlInherits;

    public IReadOnlyList<int> SerialDataBitChoices { get; } = new[] { 5, 6, 7, 8 };

    public IReadOnlyList<KeyValuePair<SerialStopBitsMode, string>> SerialStopBitChoices { get; } = new[]
    {
        new KeyValuePair<SerialStopBitsMode, string>(SerialStopBitsMode.One, "1"),
        new KeyValuePair<SerialStopBitsMode, string>(SerialStopBitsMode.OnePointFive, "1.5"),
        new KeyValuePair<SerialStopBitsMode, string>(SerialStopBitsMode.Two, "2"),
    };

    public IReadOnlyList<KeyValuePair<SerialParityMode, string>> SerialParityChoices { get; } = new[]
    {
        new KeyValuePair<SerialParityMode, string>(SerialParityMode.None, "None"),
        new KeyValuePair<SerialParityMode, string>(SerialParityMode.Odd, "Odd"),
        new KeyValuePair<SerialParityMode, string>(SerialParityMode.Even, "Even"),
        new KeyValuePair<SerialParityMode, string>(SerialParityMode.Mark, "Mark"),
        new KeyValuePair<SerialParityMode, string>(SerialParityMode.Space, "Space"),
    };

    public IReadOnlyList<KeyValuePair<SerialFlowControlMode, string>> SerialFlowControlChoices { get; } = new[]
    {
        new KeyValuePair<SerialFlowControlMode, string>(SerialFlowControlMode.None, "None"),
        new KeyValuePair<SerialFlowControlMode, string>(SerialFlowControlMode.XonXoff, "XON/XOFF"),
        new KeyValuePair<SerialFlowControlMode, string>(SerialFlowControlMode.RtsCts, "RTS/CTS"),
        new KeyValuePair<SerialFlowControlMode, string>(SerialFlowControlMode.DsrDtr, "DSR/DTR"),
    };

    #endregion

    #region Display

    /// <summary>Mstsc-style preset string ("Full connection content", "640x480" ...).
    /// Null/empty means "auto" (fit the embedded tab surface, see
    /// <c>RdpHostForm.ResolveDesktopSize</c>).</summary>
    [ObservableProperty]
    private string? rdpScreenSize;

    [ObservableProperty]
    private bool rdpFullScreen;

    [ObservableProperty]
    private int rdpColorDepth = 32;

    [ObservableProperty]
    private bool rdpUseAllMonitors;

    public IReadOnlyList<int> ColorDepthChoices { get; } = new[] { 15, 16, 24, 32 };

    public IReadOnlyList<string> ScreenSizeChoices { get; } = RdpScreenSizes.Presets;

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

    /// <summary>0=No server authentication, 1=Require / fail-closed, 2=Warn / prompt.</summary>
    [ObservableProperty]
    private int rdpServerAuthentication = 2;

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
        get => RdpGatewayCredentialId is null ? NoneCredential : GetGatewayCredentialById(RdpGatewayCredentialId);
        set => RdpGatewayCredentialId = (value is null || value.Id == Guid.Empty) ? null : value.Id;
    }

    private CredentialProfile? GetCredentialById(Guid? id) =>
        id is { } guid && _availableCredentialsById.TryGetValue(guid, out var credential)
            ? credential
            : null;

    private CredentialProfile? GetGatewayCredentialById(Guid? id) =>
        id is { } guid && _availableGatewayCredentialsById.TryGetValue(guid, out var credential)
            ? credential
            : null;

    [ObservableProperty]
    private bool rdpGatewayBypassLocal = true;

    [ObservableProperty]
    private bool rdpGatewayUseSameCreds;

    /// <summary>
    /// Opt-in: route this connection through the system Remote Desktop client (mstsc.exe)
    /// instead of the embedded ActiveX. Required for Azure-AD-joined targets — the
    /// unpackaged WinUI process can't load WAM broker DLLs that mstscax delay-loads during
    /// AAD auth, so the embedded path crashes with SEH 0xC06D007F. mstsc.exe is a
    /// packaged-trusted system binary and authenticates AAD cleanly.
    /// </summary>
    [ObservableProperty]
    private bool rdpUseExternalClient;

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
        new KeyValuePair<int, string>(2, "Warn me if server authentication fails"),
        new KeyValuePair<int, string>(1, "Require server authentication"),
        new KeyValuePair<int, string>(0, "Do not authenticate the server"),
    };

    #endregion

    public bool IsValid
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Name)) return false;
            if (string.IsNullOrWhiteSpace(Host)) return false;
            if (HttpAddressError is not null) return false;
            // Port is int?: null means "use the inherited / protocol-default port" (the
            // "Default for protocol" NumberBox placeholder). C# property pattern matching
            // treats null as not matching either side, so this only rejects an explicit
            // out-of-range value — not null.
            if (!IsSerial && Port is < 1 or > 65535) return false;
            if (IsSerial && !SerialBaudRateInherits && SerialBaudRate <= 0) return false;
            if (IsSerial && !SerialDataBitsInherits && SerialDataBits is < 5 or > 8) return false;
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
        _allCredentialsById.Clear();
        foreach (var credential in creds)
        {
            _allCredentials.Add(credential);
            _allCredentialsById[credential.Id] = credential;
        }
        RebuildAvailableCredentials();
    }

    /// <summary>
    /// Populate <see cref="InlinePassword"/> from Credential Manager when editing a connection
    /// that already uses an inline password, so the field reflects the stored secret. Called by
    /// the dialog's LoadAsync after <see cref="LoadFrom"/> (which can't read the secret because
    /// it's synchronous). A no-op for new connections and for saved-credential connections.
    /// </summary>
    public async Task LoadInlineSecretAsync()
    {
        if (_loadedUseInlinePassword && _editingNodeId != Guid.Empty)
        {
            InlinePassword = await _credentialService.ReadPasswordAsync(_editingNodeId).ConfigureAwait(true) ?? string.Empty;
        }
    }

    /// <summary>
    /// Rebuild <see cref="AvailableCredentials"/> from <see cref="_allCredentials"/> using the
    /// current Protocol. A currently-selected credential whose protocol no longer matches the
    /// filter is preserved as a "stale" entry so edit-round-tripping doesn't silently drop the
    /// binding — but new credentials offered to the user are filtered to compatible ones only.
    /// </summary>
    private void RebuildAvailableCredentials()
    {
        var connectionNeedsPasswordCredential = Protocol is ProtocolType.Rdp or ProtocolType.Vnc;

        var available = new List<CredentialProfile>(_allCredentials.Count + 3)
        {
            InheritCredential,
            NoneCredential,
        };
        var gatewayAvailable = new List<CredentialProfile>(_allCredentials.Count + 1)
        {
            NoneCredential,
        };
        foreach (var c in _allCredentials)
        {
            if (c.Protocol != Protocol) continue;
            // RDP login only consumes the password secret — SSH-key credentials would force the
            // user into a misleading prompt path. Filter them out.
            if (connectionNeedsPasswordCredential && c.Kind == CredentialKind.SshKey) continue;
            available.Add(c);
            gatewayAvailable.Add(c);
        }

        ReplaceAvailableCredentials(available);
        ReplaceAvailableGatewayCredentials(gatewayAvailable);

        // Preserve the existing main + gateway selections when they no longer match the filter
        // so edit round-trip doesn't lose the binding on a saved node.
        AppendStaleSelection(CredentialId);
        AppendStaleGatewaySelection(RdpGatewayCredentialId);

        OnPropertyChanged(nameof(SelectedCredential));
        OnPropertyChanged(nameof(SelectedGatewayCredential));
    }

    private void AppendStaleSelection(Guid? id)
    {
        if (id is not { } guid) return;
        if (_availableCredentialsById.ContainsKey(guid)) return;
        if (!_allCredentialsById.TryGetValue(guid, out var stale)) return;

        _availableCredentialsById[stale.Id] = stale;
        AvailableCredentials.Add(stale);
    }

    private void AppendStaleGatewaySelection(Guid? id)
    {
        if (id is not { } guid) return;
        if (_availableGatewayCredentialsById.ContainsKey(guid)) return;
        if (!_allCredentialsById.TryGetValue(guid, out var stale)) return;

        _availableGatewayCredentialsById[stale.Id] = stale;
        AvailableGatewayCredentials.Add(stale);
    }

    private void ReplaceAvailableCredentials(IReadOnlyList<CredentialProfile> available)
    {
        _availableCredentialsById.Clear();
        foreach (var credential in available)
        {
            _availableCredentialsById[credential.Id] = credential;
        }
        AvailableCredentials.ReplaceAll(available);
    }

    private void ReplaceAvailableGatewayCredentials(IReadOnlyList<CredentialProfile> available)
    {
        _availableGatewayCredentialsById.Clear();
        foreach (var credential in available)
        {
            _availableGatewayCredentialsById[credential.Id] = credential;
        }
        AvailableGatewayCredentials.ReplaceAll(available);
    }

    /// <summary>
    /// Filter <see cref="AvailableCredentials"/> for the credential pickers' type-to-search.
    /// An empty/whitespace query returns the full list (including the <see cref="NoneCredential"/>
    /// sentinel); otherwise entries match on Name/Username/Domain (case-insensitive substring),
    /// mirroring <see cref="CredentialsViewModel"/>'s search. Returns a snapshot so callers can
    /// bind it straight to AutoSuggestBox.ItemsSource without observing later source mutations.
    /// </summary>
    public IReadOnlyList<CredentialProfile> FilterCredentials(string? query)
        => FilterCredentialList(AvailableCredentials, query);

    public IReadOnlyList<CredentialProfile> FilterGatewayCredentials(string? query)
        => FilterCredentialList(AvailableGatewayCredentials, query);

    private static List<CredentialProfile> FilterCredentialList(
        BulkObservableCollection<CredentialProfile> credentials,
        string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return credentials.ToList();
        }

        var q = query.Trim();
        var matches = new List<CredentialProfile>(credentials.Count);
        foreach (var credential in credentials)
        {
            if (CredentialContains(credential.Name, q) ||
                CredentialContains(credential.Username, q) ||
                CredentialContains(credential.Domain, q))
            {
                matches.Add(credential);
            }
        }

        return matches;
    }

    /// <summary>
    /// Resolve an exact (case-insensitive) credential Name from <see cref="AvailableCredentials"/>,
    /// or null when nothing matches. The picker's commit-on-Enter path uses this so typed text
    /// that doesn't name a real credential leaves the current selection untouched.
    /// </summary>
    public CredentialProfile? ResolveCredentialByText(string? text)
        => ResolveCredentialByText(AvailableCredentials, text);

    public CredentialProfile? ResolveGatewayCredentialByText(string? text)
        => ResolveCredentialByText(AvailableGatewayCredentials, text);

    private static CredentialProfile? ResolveCredentialByText(
        IReadOnlyList<CredentialProfile> credentials,
        string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        var t = text.Trim();
        foreach (var credential in credentials)
        {
            if (string.Equals(credential.Name, t, StringComparison.OrdinalIgnoreCase))
            {
                return credential;
            }
        }

        return null;
    }

    /// <summary>
    /// Resolve typed picker text to a single credential to commit when the box is submitted or
    /// loses focus: an exact (case-insensitive) <c>Name</c> wins; otherwise, if the same
    /// Name/Username/Domain filter the dropdown uses yields exactly one real credential, that one
    /// is taken. Ambiguous (more than one match) or empty/no-match returns null so the picker
    /// leaves the current selection untouched (the caller reverts the stray text). The
    /// <see cref="NoneCredential"/> sentinel is never auto-resolved — clearing is handled by the
    /// caller treating empty text as "select none".
    /// </summary>
    public CredentialProfile? ResolveCredentialForCommit(string? text)
        => ResolveCredentialForCommit(AvailableCredentials, text);

    public CredentialProfile? ResolveGatewayCredentialForCommit(string? text)
        => ResolveCredentialForCommit(AvailableGatewayCredentials, text);

    private static CredentialProfile? ResolveCredentialForCommit(
        IReadOnlyList<CredentialProfile> credentials,
        string? text)
    {
        if (ResolveCredentialByText(credentials, text) is { } exact) return exact;
        if (string.IsNullOrWhiteSpace(text)) return null;

        var q = text.Trim();
        CredentialProfile? single = null;
        foreach (var credential in credentials)
        {
            if (IsCredentialSentinel(credential)) continue;
            if (CredentialContains(credential.Name, q) ||
                CredentialContains(credential.Username, q) ||
                CredentialContains(credential.Domain, q))
            {
                if (single is not null) return null; // ambiguous — don't guess
                single = credential;
            }
        }

        return single;
    }

    private static bool IsCredentialSentinel(CredentialProfile credential) =>
        CredentialBindingSentinelIds.IsSentinel(credential.Id);

    private static bool CredentialContains(string? haystack, string needle) =>
        haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    partial void OnProtocolChanged(ProtocolType value)
    {
        // When the user explicitly switches the connection protocol, drop a previously-bound
        // credential that no longer matches the new filter. The alternative — preserving it as
        // a stale entry — would silently expose a protocol-incompatible binding on save.
        if (CredentialId is { } id && _allCredentialsById.TryGetValue(id, out var cred))
        {
            var connectionNeedsPasswordCredential = value is ProtocolType.Rdp or ProtocolType.Vnc;
            var stillCompatible = cred.Protocol == value
                && (!connectionNeedsPasswordCredential || cred.Kind != CredentialKind.SshKey);
            if (!stillCompatible) SelectedCredential = InheritCredential;
        }
        // Gateway credential is RDP-only — switching away from RDP makes it meaningless.
        if (value != ProtocolType.Rdp) RdpGatewayCredentialId = null;

        RebuildAvailableCredentials();
    }

    // Pull a stale (protocol-mismatched) credential into AvailableCredentials when LoadFrom
    // assigns one — without this, the ComboBox round-trips to its placeholder on edit and the
    // user loses sight of the saved binding. Also drive the AAD auto-flag for credential
    // changes via the shared ApplyAadAutoFlag helper so credential-side and node-side signals
    // (Username, RdpDomain) all use the same auto-tick/auto-untick logic.
    partial void OnCredentialIdChanged(Guid? value)
    {
        if (value is { } id && !_availableCredentialsById.ContainsKey(id))
        {
            AppendStaleSelection(id);
            OnPropertyChanged(nameof(SelectedCredential));
        }

        ApplyAadAutoFlag();
    }

    partial void OnCredentialModeChanged(CredentialBindingMode? value) => ApplyAadAutoFlag();

    partial void OnRdpGatewayCredentialIdChanged(Guid? value)
    {
        if (value is { } id && !_availableGatewayCredentialsById.ContainsKey(id))
        {
            AppendStaleGatewaySelection(id);
            OnPropertyChanged(nameof(SelectedGatewayCredential));
        }
    }

    // Username/Domain handlers funnel into the same ApplyAadAutoFlag helper as
    // OnCredentialIdChanged so every editable AAD input drives auto-tick AND auto-untick
    // consistently. Without auto-untick, a user who typed "AzureAD" by mistake and corrected
    // it would be left with a ticked-and-editable checkbox they never asked for.
    partial void OnUsernameChanged(string value) => ApplyAadAutoFlag();

    partial void OnRdpDomainChanged(string value) => ApplyAadAutoFlag();

    /// <summary>
    /// Reconcile <see cref="RdpUseExternalClient"/> with the current AAD signals. When a
    /// signal is detected and the flag is currently false, set it to true and remember that
    /// the editor (not the user) did so via <see cref="_autoFlagAppliedByAad"/>. When all
    /// signals are gone AND the flag is currently true ONLY because we set it ourselves,
    /// roll it back. Pre-existing user/persisted true values are left alone — we only undo
    /// our own writes. Suppressed during <see cref="LoadFrom"/> so a re-opened profile
    /// doesn't observe transient toggling between assignments.
    /// </summary>
    private void ApplyAadAutoFlag()
    {
        if (_suppressAadAutoFlag) return;

        if (IsAzureAdCredential)
        {
            if (!RdpUseExternalClient)
            {
                RdpUseExternalClient = true;
                _autoFlagAppliedByAad = true;
            }
        }
        else if (_autoFlagAppliedByAad)
        {
            // Last AAD signal cleared and we own the current true value — untick.
            RdpUseExternalClient = false;
            _autoFlagAppliedByAad = false;
        }
    }

    public void LoadFrom(ConnectionNode node)
    {
        // Save-and-restore the suppress flag instead of forcing it to false in finally. The
        // current call-graph never re-enters LoadFrom, but a future protocol-change side
        // effect that triggers a reload would silently leak suppression off for the outer
        // load if we hard-reset here. Treat any persisted RdpUseExternalClient=true value
        // as user-set (we have no audit field that records "auto-flagged by editor"), so
        // _autoFlagAppliedByAad starts at false — the user can still untick manually.
        var previousSuppress = _suppressAadAutoFlag;
        _suppressAadAutoFlag = true;
        _autoFlagAppliedByAad = false;
        try
        {
            Name = node.Name;
            Protocol = node.Protocol ?? ProtocolType.Ssh;
            Host = node.Host ?? string.Empty;
            Port = node.Port;
            // Web protocols: the single address field carries host[:port]. Fold a saved non-default
            // port back into it and clear the (hidden, unused) Port box so the address field is the sole
            // source when WriteTo re-parses it.
            if (Protocol is ProtocolType.Http or ProtocolType.Https)
            {
                var webDefaultPort = Protocol == ProtocolType.Https ? 443 : 80;
                if (node.Port is { } webPort && webPort != webDefaultPort && !string.IsNullOrWhiteSpace(Host))
                {
                    // Bracket a bare IPv6 literal so the folded "host:port" round-trips: an unbracketed
                    // "fd00::1:8443" would re-parse (HostSpecParser's >1-colon branch) as a host with no
                    // port, silently dropping the custom port on the next save.
                    Host = Host.Contains(':', StringComparison.Ordinal)
                        ? $"[{Host}]:{webPort}"
                        : $"{Host}:{webPort}";
                }
                Port = null;
            }
            Username = node.Username ?? string.Empty;
            RdpDomain = node.RdpDomain ?? string.Empty;
            CredentialId = node.CredentialId;
            CredentialMode = node.CredentialMode ?? (node.CredentialId is null
                ? CredentialBindingMode.Inherit
                : CredentialBindingMode.Saved);
            _editingNodeId = node.Id;
            _loadedUseInlinePassword = node.UseInlinePassword ?? false;
            UseSavedCredentials = !_loadedUseInlinePassword;
            // The plaintext is fetched lazily from Credential Manager by LoadInlineSecretAsync
            // (an async call the synchronous LoadFrom can't make); start blank.
            InlinePassword = string.Empty;
            _loadedSshAutoSudo = node.SshAutoSudo;
            SshAutoSudoMode = node.SshAutoSudo switch
            {
                true => SshAutoSudoOn,
                false => SshAutoSudoOff,
                null => SshAutoSudoInherit,
            };

            RdpScreenSize = RdpScreenSizes.NormalizeForPicker(node.RdpScreenSize);
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

            RdpServerAuthentication = node.RdpServerAuthentication ?? 2;
            RdpGatewayUsageMethod = node.RdpGatewayUsageMethod ?? 0;
            RdpGatewayHostname = node.RdpGatewayHostname ?? string.Empty;
            RdpGatewayCredentialId = node.RdpGatewayCredentialId;
            RdpGatewayBypassLocal = node.RdpGatewayBypassLocal ?? true;
            RdpGatewayUseSameCreds = node.RdpGatewayUseSameCreds ?? false;
            RdpUseExternalClient = node.RdpUseExternalClient ?? false;

            SerialBaudRateInherits = node.SerialBaudRate is null;
            SerialDataBitsInherits = node.SerialDataBits is null;
            SerialStopBitsInherits = node.SerialStopBits is null;
            SerialParityInherits = node.SerialParity is null;
            SerialFlowControlInherits = node.SerialFlowControl is null;
            SerialBaudRate = SerialDefaults.NormalizeBaudRate(node.SerialBaudRate);
            SerialDataBits = SerialDefaults.NormalizeDataBits(node.SerialDataBits);
            SerialStopBits = SerialDefaults.NormalizeStopBits(node.SerialStopBits);
            SerialParity = SerialDefaults.NormalizeParity(node.SerialParity);
            SerialFlowControl = SerialDefaults.NormalizeFlowControl(node.SerialFlowControl);

            HttpIgnoreCertErrors = node.HttpIgnoreCertErrors ?? false;

            // Tunnel fields are protocol-agnostic across network connections. Serial stays local.
            // Delegated to TunnelPicker, which owns the atomic two-field write that protects a
            // TwoWay SelectedTunnel binding from observing the intermediate (one-set, one-unset)
            // state.
            TunnelPicker.LoadFrom(node);
        }
        finally
        {
            _suppressAadAutoFlag = previousSuppress;
        }
    }

    public void WriteTo(ConnectionNode node)
    {
        node.Name = Name.Trim();
        node.Protocol = Protocol;
        if (IsHttp)
        {
            // The single address field is the sole source of host + port for web connections (the Port
            // box is hidden). Parse "host", "host:port", or a tolerated scheme/path paste into the two.
            var (httpHost, httpPort) = ParseHttpAddress(Host);
            node.Host = httpHost;
            node.Port = httpPort;
        }
        else if (IsSerial)
        {
            node.Host = Host.Trim();
            node.Port = null;
        }
        else
        {
            node.Host = Host.Trim();
            node.Port = Port;
        }
        // The free-text Username field is meaningful only for SSH/RDP. VNC v1 is password-only,
        // and web/serial sessions are credential-less, so they clear stale username data. For SSH/RDP,
        // when the visible field is blank, fall back to the selected credential's username so a
        // credential-backed connection with a blank Username field does not persist a null username.
        if (IsVnc || IsHttp || IsSerial)
        {
            node.Username = null;
        }
        else if (!string.IsNullOrWhiteSpace(Username))
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

        // Credential mode. "Use saved credentials" unchecked means "don't use a saved credential"
        // for every credential-capable protocol, so the picked CredentialId is always cleared in that
        // case (else a connection would silently keep authenticating with the now-hidden saved
        // credential). SSH/RDP additionally get an inline per-connection password: the plaintext is
        // handed to the tree VM via the transient PendingInlinePassword (it writes Credential Manager
        // after the row commits). VNC unchecked falls back to connect-time prompting/no-auth handling
        // (CredentialId null, no inline). Credential-less protocols clear hidden auth state on save.
        if (!ShowCredentialSection)
        {
            node.CredentialId = null;
            node.CredentialMode = null;
            node.UseInlinePassword = false;
            node.PendingInlinePassword = null;
        }
        else if (!UseSavedCredentials)
        {
            var canUseInlinePassword = IsSsh || IsRdp;
            node.CredentialId = null;
            node.CredentialMode = CredentialBindingMode.None;
            node.UseInlinePassword = canUseInlinePassword;
            node.PendingInlinePassword = canUseInlinePassword ? InlinePassword : null; // never logged
        }
        else
        {
            node.UseInlinePassword = false;
            node.PendingInlinePassword = null;
            var effectiveCredentialMode = EffectiveCredentialMode;
            node.CredentialMode = effectiveCredentialMode;
            node.CredentialId = effectiveCredentialMode == CredentialBindingMode.Saved
                ? CredentialId
                : null;
        }

        // Persist the tri-state Auto sudo choice (inherit→null / on→true / off→false) only for SSH.
        // When the SSH control is hidden because the selected credential cannot supply a password,
        // leave the loaded value untouched so saving never clobbers a value the user could not see.
        // Credential-less protocols clear this hidden SSH-only state instead.
        node.SshAutoSudo = IsSsh
            ? CanUseSshAutoSudo
                ? SshAutoSudoMode switch
                {
                    SshAutoSudoOn => true,
                    SshAutoSudoOff => false,
                    _ => (bool?)null,
                }
                : _loadedSshAutoSudo
            : null;

        if (IsRdp)
        {
            // Persist the node-level domain only while the field is shown (a genuine override that
            // differs from the credential's domain, or no governing credential). When it's hidden —
            // a redundant duplicate of, or empty under, a resolved RDP credential — store null so the
            // credential's domain stays authoritative even if it's later edited; a persisted hidden
            // duplicate would otherwise linger and win at connect (explicitDomain ?? credentialDomain)
            // once the credential diverges. Mirrors the visibility-gated SshAutoSudo write above.
            node.RdpDomain = ShowRdpDomain && !string.IsNullOrWhiteSpace(RdpDomain) ? RdpDomain.Trim() : null;
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
            node.RdpUseExternalClient = RdpUseExternalClient;
        }

        // Only meaningful for HTTPS; store the user's choice there and null it otherwise so a stale flag
        // doesn't linger on a connection switched away from HTTPS.
        node.HttpIgnoreCertErrors = IsHttps ? HttpIgnoreCertErrors : (bool?)null;

        if (IsSerial)
        {
            node.SerialBaudRate = SerialBaudRateInherits ? null : SerialBaudRate;
            node.SerialDataBits = SerialDataBitsInherits ? null : SerialDataBits;
            node.SerialStopBits = SerialStopBitsInherits ? null : SerialStopBits;
            node.SerialParity = SerialParityInherits ? null : SerialParity;
            node.SerialFlowControl = SerialFlowControlInherits ? null : SerialFlowControl;
        }
        else
        {
            node.SerialBaudRate = null;
            node.SerialDataBits = null;
            node.SerialStopBits = null;
            node.SerialParity = null;
            node.SerialFlowControl = null;
        }

        // Tunnel fields apply to network protocols only; serial ports are local devices.
        if (IsSerial)
        {
            node.TunnelEnabled = false;
            node.TunnelConfigId = null;
        }
        else
        {
            TunnelPicker.WriteTo(node);
        }
    }


    /// <summary>
    /// Parse the web "address" field into a bare host + optional port. Accepts <c>host</c>,
    /// <c>host:port</c>, a bracketed IPv6 literal, and tolerates a pasted scheme/path (the protocol
    /// dropdown already fixes the scheme, and the model carries no path). Reuses
    /// <see cref="HostSpecParser"/> for the host:port split. Returns the trimmed input as the host
    /// (port null) if it can't be parsed.
    /// </summary>
    private static readonly System.Buffers.SearchValues<char> HttpAddressTrailers =
        System.Buffers.SearchValues.Create("/?#");

    internal static (string Host, int? Port) ParseHttpAddress(string raw)
    {
        var trimmed = (raw ?? string.Empty).Trim();
        if (trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["https://".Length..];
        }
        else if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["http://".Length..];
        }

        // Drop any path/query/fragment — we navigate to the host root (no path column in the model).
        var cut = trimmed.AsSpan().IndexOfAny(HttpAddressTrailers);
        if (cut >= 0) trimmed = trimmed[..cut];
        if (trimmed.Length == 0) return ((raw ?? string.Empty).Trim(), null);

        try
        {
            var spec = HostSpecParser.Parse(trimmed);
            return (spec.Host, spec.Port);
        }
        catch (FormatException)
        {
            return (trimmed, null);
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
