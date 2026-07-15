using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services.Tunneling.AzureVpn;
using Wormhole.Services.Tunneling.CiscoSecureClient;
using Wormhole.Services.Tunneling.Watchguard;

namespace Wormhole.Views.Dialogs;

public sealed partial class TunnelDialog : UserControl, IDraftForm<TunnelDraft>
{
    public event EventHandler? ValidityChanged;
    private string _watchguardProfileOvpn = string.Empty;

    public TunnelDialog()
    {
        this.InitializeComponent();
        // Sync panel visibility to the default-selected KindBox value. Without this, a
        // fresh create-flow dialog (where DialogService skips LoadDraft) renders panel
        // visibility from XAML defaults only — correct today because TunnelKind.WireGuard
        // is enum value 0, but it would silently desync if the enum is ever reordered.
        UpdateKindPanels();
    }

    public TunnelKind[] Kinds { get; } = Enum.GetValues<TunnelKind>();
    public WatchguardAuthMode[] WatchguardAuthModes { get; } = Enum.GetValues<WatchguardAuthMode>();

    // The horizontal 2-column layout in the XAML needs ~760 px of dialog width to render
    // without clipping — overrides the ContentDialog ~548 px theme cap. DialogService
    // clamps this against XamlRoot.Size so the dialog stays inside narrow host windows.
    public double? PreferredDialogMinWidth => 760;

    private TunnelKind SelectedKind =>
        KindBox.SelectedItem is TunnelKind k ? k : TunnelKind.WireGuard;

    // Index 1 == Import in the StormshieldModeBox ComboBox; everything else (incl. index 0 and the
    // not-yet-selected -1 on a fresh dialog) means Automatic.
    private StormshieldConnectionMode StormshieldSelectedMode =>
        StormshieldModeBox.SelectedIndex == 1 ? StormshieldConnectionMode.Import : StormshieldConnectionMode.Automatic;

    private StormshieldOpenVpnTransportOverride StormshieldSelectedTransportOverride =>
        StormshieldTransportOverrideBox.SelectedIndex switch
        {
            1 => StormshieldOpenVpnTransportOverride.ForceTcp,
            2 => StormshieldOpenVpnTransportOverride.ForceUdp,
            _ => StormshieldOpenVpnTransportOverride.Auto,
        };

    private StormshieldOpenVpnCompressionFramingOverride StormshieldSelectedCompressionFramingOverride =>
        StormshieldCompressionFramingOverrideBox.SelectedIndex switch
        {
            1 => StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub,
            _ => StormshieldOpenVpnCompressionFramingOverride.PreserveProfile,
        };

    private WatchguardAuthMode WatchguardSelectedAuthMode =>
        WatchguardAuthModeBox.SelectedItem is WatchguardAuthMode mode ? mode : WatchguardAuthMode.Automatic;

    // IsValid is derived from the same per-kind required-field scan that powers the live
    // "what's still missing" hint (UpdateValidationHint), so the disabled-Create gate and the
    // explanation the user reads can never drift apart. The button is enabled iff nothing is
    // outstanding.
    public bool IsValid => CollectMissingRequiredFields().Count == 0;

    // Returns the human-readable labels of the required fields not yet satisfied for the
    // selected kind (empty when the form is ready to save). Labels intentionally match the
    // server-side messages in TunnelConfigsViewModel.Validate* so the dialog hint and the
    // post-save error speak the same language.
    private List<string> CollectMissingRequiredFields()
    {
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(NameBox.Text)) missing.Add("Name");
        switch (SelectedKind)
        {
            case TunnelKind.WireGuard:
                if (string.IsNullOrWhiteSpace(InterfacePrivateKeyBox.Text)) missing.Add("Interface private key");
                if (string.IsNullOrWhiteSpace(InterfaceAddressBox.Text)) missing.Add("Interface address");
                if (string.IsNullOrWhiteSpace(PeerPublicKeyBox.Text)) missing.Add("Peer public key");
                if (string.IsNullOrWhiteSpace(PeerEndpointBox.Text)) missing.Add("Peer endpoint");
                break;
            case TunnelKind.OpenVpn:
                if (string.IsNullOrWhiteSpace(ProfileOvpnBox.Text)) missing.Add("OpenVPN profile");
                break;
            case TunnelKind.Fortinet:
                if (string.IsNullOrWhiteSpace(FortinetHostBox.Text)) missing.Add("Host");
                if (!IsValidPort(FortinetPortBox.Text)) missing.Add("Port (1-65535)");
                if (FortinetSsoCheck.IsChecked == true)
                {
                    if (FortinetExternalBrowserCheck.IsChecked == true)
                    {
                        if (!IsValidPort(FortinetSamlRedirectPortBox.Text)) missing.Add("SAML callback port (1-65535)");
                        if (!string.IsNullOrWhiteSpace(FortinetRealmBox.Text)) missing.Add("an empty realm for external-browser SSO");
                    }
                    else if (!string.IsNullOrWhiteSpace(FortinetCertPinBox.Text))
                    {
                        missing.Add("external-browser SSO or an empty server certificate pin");
                    }
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(FortinetUsernameBox.Text)) missing.Add("Username");
                    if (string.IsNullOrWhiteSpace(FortinetPasswordBox.Password)) missing.Add("Password");
                }
                break;
            case TunnelKind.Watchguard:
                if (string.IsNullOrWhiteSpace(WatchguardServerBox.Text)) missing.Add("Server");
                if (!IsValidPort(WatchguardPortBox.Text)) missing.Add("Port (1-65535)");
                if (WatchguardSelectedAuthMode == WatchguardAuthMode.UsernamePassword)
                {
                    if (string.IsNullOrWhiteSpace(WatchguardUsernameBox.Text)) missing.Add("Username");
                    if (string.IsNullOrWhiteSpace(WatchguardPasswordBox.Password)) missing.Add("Password");
                }
                break;
            case TunnelKind.CiscoSecureClient:
                if (string.IsNullOrWhiteSpace(CiscoHostBox.Text)) missing.Add("Host");
                if (!IsValidPort(CiscoPortBox.Text)) missing.Add("Port (1-65535)");
                if (string.IsNullOrWhiteSpace(CiscoUsernameBox.Text)) missing.Add("Username");
                // IsNullOrWhiteSpace mirrors the server-side ValidateCiscoSecureClient check.
                if (string.IsNullOrWhiteSpace(CiscoPasswordBox.Password)) missing.Add("Password");
                break;
            case TunnelKind.AzureVpn:
                if (string.IsNullOrWhiteSpace(AzureVpnServersBox.Text)) missing.Add("Server FQDN");
                if (string.IsNullOrWhiteSpace(AzureVpnTenantBox.Text)) missing.Add("Tenant ID");
                if (string.IsNullOrWhiteSpace(AzureVpnAudienceBox.Text)) missing.Add("Audience");
                // Mirrors the server-side ValidateAzureVpn / AzureVpnProfileBuilder check: a
                // malformed tls-auth key would otherwise pass the dialog and only fail at save
                // (or worse, connect) time with the same wording.
                if (!IsValidAzureServerSecret(AzureVpnServerSecretBox.Text)) missing.Add("Server secret (512 hex chars, or blank)");
                break;
            case TunnelKind.Stormshield:
                if (StormshieldSelectedMode == StormshieldConnectionMode.Import)
                {
                    // Import mode: the pasted .ovpn carries its own remote, so only the profile is
                    // required (Server/Port unused here; auth-user-pass optional).
                    if (string.IsNullOrWhiteSpace(StormshieldProfileOvpnBox.Text)) missing.Add("OpenVPN profile");
                }
                else
                {
                    // Automatic mode: a reachable server + port, plus username + password unless SSO
                    // is used (SSO is disabled/not-yet-supported but kept here for symmetry).
                    if (string.IsNullOrWhiteSpace(StormshieldServerBox.Text)) missing.Add("Server");
                    if (!IsValidPort(StormshieldPortBox.Text)) missing.Add("Port (1-65535)");
                    if (StormshieldSsoCheck.IsChecked != true)
                    {
                        if (string.IsNullOrWhiteSpace(StormshieldUsernameBox.Text)) missing.Add("Username");
                        if (string.IsNullOrWhiteSpace(StormshieldPasswordBox.Password)) missing.Add("Password");
                    }
                }
                break;
            default:
                missing.Add("a supported VPN type");
                break;
        }
        return missing;
    }

    // Reflects the outstanding required fields into the inline InfoBar so a disabled Create
    // button always explains itself. Hidden once the form is valid. Called from everywhere
    // ValidityChanged fires plus UpdateKindPanels (which covers initial load and kind switches).
    private void UpdateValidationHint()
    {
        var missing = CollectMissingRequiredFields();
        if (missing.Count == 0)
        {
            ValidationHintBar.IsOpen = false;
            return;
        }
        ValidationHintBar.Message = "To save this tunnel, fill in: " + string.Join(", ", missing) + ".";
        ValidationHintBar.IsOpen = true;
    }

    private static bool IsValidPort(string text) =>
        int.TryParse(text, out var p) && p is >= 1 and <= 65535;

    // Strip all whitespace first (matching BuildAzureVpn's save-path normalization), then apply the
    // same empty-or-512-hex rule the profile builder enforces at connect time, so the live "what's
    // missing" hint and the persisted value can't disagree.
    private static bool IsValidAzureServerSecret(string text) =>
        AzureVpnProfileBuilder.IsServerSecretHexValid(StripWhitespace(text));

    public void LoadDraft(TunnelDraft initial)
    {
        NameBox.Text = initial.Name;
        KindBox.SelectedItem = initial.Kind;

        var wg = initial.WireGuard ?? new WireGuardSettings();
        InterfacePrivateKeyBox.Text = wg.InterfacePrivateKey;
        InterfaceAddressBox.Text = wg.InterfaceAddress;
        MtuBox.Text = wg.Mtu?.ToString() ?? string.Empty;
        DnsBox.Text = wg.Dns is null ? string.Empty : string.Join(", ", wg.Dns);
        PeerPublicKeyBox.Text = wg.PeerPublicKey;
        PeerPresharedKeyBox.Text = wg.PeerPresharedKey ?? string.Empty;
        PeerEndpointBox.Text = wg.PeerEndpoint;
        AllowedIpsBox.Text = wg.AllowedIps is null ? string.Empty : string.Join(", ", wg.AllowedIps);
        PersistentKeepaliveBox.Text = wg.PersistentKeepaliveSeconds?.ToString() ?? string.Empty;

        var ovpn = initial.OpenVpn ?? new OpenVpnSettings();
        ProfileOvpnBox.Text = ovpn.ProfileOvpn;
        OpenVpnUsernameBox.Text = ovpn.Username ?? string.Empty;
        OpenVpnPasswordBox.Password = ovpn.Password ?? string.Empty;

        var fg = initial.Fortinet ?? new FortinetSettings();
        FortinetHostBox.Text = fg.Host;
        // fg.Port can be 0 when the persisted blob was hand-edited or pre-dates a default —
        // prefer the XAML default of 443 over showing a value the user must wipe before saving.
        FortinetPortBox.Text = (fg.Port is >= 1 and <= 65535 ? fg.Port : 443).ToString();
        FortinetUsernameBox.Text = fg.Username;
        FortinetPasswordBox.Password = fg.Password;
        FortinetRealmBox.Text = fg.Realm ?? string.Empty;
        FortinetTotpSecretBox.Password = fg.TotpSecret ?? string.Empty;
        FortinetSsoCheck.IsChecked = fg.UseSingleSignOn;
        FortinetExternalBrowserCheck.IsChecked = fg.UseExternalBrowser;
        FortinetSamlRedirectPortBox.Text = (fg.SamlRedirectPort is >= 1 and <= 65535
            ? fg.SamlRedirectPort
            : FortinetSettings.DefaultSamlRedirectPort).ToString();
        FortinetTrustCertCheck.IsChecked = fg.TrustServerCertificate;
        FortinetCertPinBox.Text = fg.ServerCertSha256Pin ?? string.Empty;
        UpdateFortinetAuthFields();

        var wgg = initial.Watchguard ?? new WatchguardSettings();
        // Coalesce every string field defensively: System.Text.Json happily assigns null to a
        // non-nullable string property if the on-disk JSON has the key explicitly null, and
        // TextBox.Text = null throws NRE. The Fortinet branch above does the same with `?? string.Empty`
        // / `?? string.Empty` for its nullable fields; the Watchguard fields are non-nullable in
        // the model but the deserializer's behavior makes that a weak guarantee at the boundary.
        WatchguardServerBox.Text = wgg.Server ?? string.Empty;
        WatchguardPortBox.Text = (wgg.Port is >= 1 and <= 65535 ? wgg.Port : 443).ToString();
        WatchguardAuthModeBox.SelectedItem = wgg.AuthMode;
        WatchguardUsernameBox.Text = wgg.Username ?? string.Empty;
        WatchguardPasswordBox.Password = wgg.Password ?? string.Empty;
        WatchguardDomainBox.Text = wgg.Domain ?? string.Empty;
        WatchguardCaPemBox.Text = wgg.CaPem ?? string.Empty;
        WatchguardClientCertPemBox.Text = wgg.ClientCertPem ?? string.Empty;
        WatchguardClientKeyPemBox.Text = wgg.ClientKeyPem ?? string.Empty;
        _watchguardProfileOvpn = wgg.ProfileOvpn ?? string.Empty;
        WatchguardVerifyX509NameBox.Text = wgg.VerifyX509Name ?? string.Empty;
        WatchguardTrustCertCheck.IsChecked = wgg.TrustServerCertificate;

        // Coalesce defensively (same reasoning as the Watchguard block: System.Text.Json can assign
        // null to a non-nullable string property when the on-disk JSON has the key explicitly null,
        // and TextBox.Text = null throws).
        var ss = initial.Stormshield ?? new StormshieldSettings();
        StormshieldModeBox.SelectedIndex = ss.Mode == StormshieldConnectionMode.Import ? 1 : 0;
        StormshieldServerBox.Text = ss.Server ?? string.Empty;
        StormshieldPortBox.Text = (ss.Port is >= 1 and <= 65535 ? ss.Port : 443).ToString();
        StormshieldDescriptionBox.Text = ss.Description ?? string.Empty;
        StormshieldSsoCheck.IsChecked = ss.UseSingleSignOn;
        StormshieldUsernameBox.Text = ss.Username ?? string.Empty;
        StormshieldPasswordBox.Password = ss.Password ?? string.Empty;
        StormshieldUseOtpCheck.IsChecked = ss.UseOtp;
        StormshieldProfileOvpnBox.Text = ss.ProfileOvpn ?? string.Empty;
        StormshieldCaPemBox.Text = ss.CaPem ?? string.Empty;
        StormshieldTrustCertCheck.IsChecked = ss.TrustServerCertificate;
        StormshieldBypassNativeVpnRouteCheck.IsChecked = ss.BypassNativeVpnGatewayRoute;
        StormshieldTransportOverrideBox.SelectedIndex = ss.OpenVpnTransportOverride switch
        {
            StormshieldOpenVpnTransportOverride.ForceTcp => 1,
            StormshieldOpenVpnTransportOverride.ForceUdp => 2,
            _ => 0,
        };
        StormshieldCompressionFramingOverrideBox.SelectedIndex = ss.OpenVpnCompressionFramingOverride switch
        {
            StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub => 1,
            _ => 0,
        };
        StormshieldAppTokenBox.Text = string.IsNullOrWhiteSpace(ss.AppToken) ? StormshieldSettings.DefaultAppToken : ss.AppToken;
        UpdateStormshieldModePanels();

        // Coalesce defensively (same reasoning as the Watchguard/Stormshield blocks above).
        var az = initial.AzureVpn ?? new AzureVpnSettings();
        AzureVpnServersBox.Text = az.Servers is null ? string.Empty : string.Join(", ", az.Servers);
        AzureVpnTransportBox.SelectedIndex = az.Protocol == AzureVpnTransport.Udp ? 1 : 0;
        AzureVpnTenantBox.Text = az.TenantId ?? string.Empty;
        AzureVpnAudienceBox.Text = az.Audience ?? string.Empty;
        AzureVpnApplicationIdBox.Text = az.ApplicationId ?? string.Empty;
        AzureVpnIssuerBox.Text = az.Issuer ?? string.Empty;
        AzureVpnServerSecretBox.Text = az.ServerSecretHex ?? string.Empty;
        AzureVpnCaPemBox.Text = az.CaPem ?? string.Empty;

        // Coalesce defensively (same reasoning as the Watchguard/Stormshield/Azure blocks above).
        var cs = initial.CiscoSecureClient ?? new CiscoSecureClientSettings();
        CiscoHostBox.Text = cs.Host ?? string.Empty;
        CiscoPortBox.Text = (cs.Port is >= 1 and <= 65535 ? cs.Port : 443).ToString();
        CiscoUsernameBox.Text = cs.Username ?? string.Empty;
        CiscoPasswordBox.Password = cs.Password ?? string.Empty;
        CiscoGroupBox.Text = cs.Group ?? string.Empty;
        CiscoTotpSecretBox.Password = cs.TotpSecret ?? string.Empty;
        CiscoSecondaryPasswordBox.Password = cs.SecondaryPassword ?? string.Empty;
        CiscoTrustCertCheck.IsChecked = cs.TrustServerCertificate;
        CiscoCertPinBox.Text = cs.ServerCertSha256Pin ?? string.Empty;

        UpdateKindPanels();
    }

    public TunnelDraft BuildDraft()
    {
        var name = NameBox.Text.Trim();
        var kind = SelectedKind;
        return kind switch
        {
            TunnelKind.WireGuard => new TunnelDraft(name, kind, BuildWireGuard(), OpenVpn: null, Fortinet: null),
            TunnelKind.OpenVpn => new TunnelDraft(name, kind, WireGuard: null, BuildOpenVpn(), Fortinet: null),
            TunnelKind.Fortinet => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, BuildFortinet()),
            TunnelKind.Watchguard => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: BuildWatchguard()),
            TunnelKind.Stormshield => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: null, Stormshield: BuildStormshield()),
            TunnelKind.AzureVpn => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: null, Stormshield: null, AzureVpn: BuildAzureVpn()),
            TunnelKind.CiscoSecureClient => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: null, Stormshield: null, AzureVpn: null, CiscoSecureClient: BuildCiscoSecureClient()),
            _ => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null),
        };
    }

    private CiscoSecureClientSettings BuildCiscoSecureClient()
    {
        // Strip ALL whitespace from the TOTP secret (Base32 enrollment screens often display it
        // in space-separated groups) and the cert pin (often pasted with line wrapping) so the
        // sidecar's Base32 / hex parsing can't trip over copy artifacts — same treatment as the
        // Fortinet branch. (Colon separators in the cert pin are handled by the sidecar itself,
        // which strips ':' before hex-decoding; StripWhitespace only removes whitespace.)
        var totp = StripWhitespace(CiscoTotpSecretBox.Password);
        return new CiscoSecureClientSettings
        {
            Host = CiscoHostBox.Text.Trim(),
            Port = TryParseInt(CiscoPortBox.Text) ?? 443,
            Username = CiscoUsernameBox.Text.Trim(),
            // Strip ONLY trailing CR/LF (paste artifacts the user can't see in a PasswordBox) —
            // leave every other character intact so legitimate whitespace in a password survives.
            Password = CiscoPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
            Group = string.IsNullOrWhiteSpace(CiscoGroupBox.Text) ? null : CiscoGroupBox.Text.Trim(),
            SecondaryPassword = string.IsNullOrEmpty(CiscoSecondaryPasswordBox.Password)
                ? null
                : CiscoSecondaryPasswordBox.Password.TrimEnd('\r', '\n'),
            TotpSecret = string.IsNullOrEmpty(totp) ? null : totp,
            TrustServerCertificate = CiscoTrustCertCheck.IsChecked == true,
            ServerCertSha256Pin = string.IsNullOrWhiteSpace(CiscoCertPinBox.Text) ? null : StripWhitespace(CiscoCertPinBox.Text),
        };
    }

    private AzureVpnSettings BuildAzureVpn() => new()
    {
        Servers = SplitCsv(AzureVpnServersBox.Text),
        Protocol = AzureVpnTransportBox.SelectedIndex == 1 ? AzureVpnTransport.Udp : AzureVpnTransport.Tcp,
        TenantId = AzureVpnTenantBox.Text.Trim(),
        Audience = AzureVpnAudienceBox.Text.Trim(),
        ApplicationId = string.IsNullOrWhiteSpace(AzureVpnApplicationIdBox.Text) ? null : AzureVpnApplicationIdBox.Text.Trim(),
        Issuer = string.IsNullOrWhiteSpace(AzureVpnIssuerBox.Text) ? null : AzureVpnIssuerBox.Text.Trim(),
        // The tls-auth key is hex that some tools wrap/space when copied — strip ALL whitespace
        // (same normalization as the Fortinet TOTP secret).
        ServerSecretHex = StripWhitespace(AzureVpnServerSecretBox.Text) is { Length: > 0 } secret ? secret : null,
        CaPem = string.IsNullOrWhiteSpace(AzureVpnCaPemBox.Text) ? null : AzureVpnCaPemBox.Text,
    };

    private StormshieldSettings BuildStormshield() => new()
    {
        Server = StormshieldServerBox.Text.Trim(),
        Port = TryParseInt(StormshieldPortBox.Text) ?? 443,
        Description = string.IsNullOrWhiteSpace(StormshieldDescriptionBox.Text) ? null : StormshieldDescriptionBox.Text.Trim(),
        Mode = StormshieldSelectedMode,
        UseSingleSignOn = StormshieldSsoCheck.IsChecked == true,
        Username = StormshieldUsernameBox.Text.Trim(),
        // Strip only trailing CR/LF (paste artifacts the user can't see in a PasswordBox) — leave
        // every other character intact so legitimate whitespace in a password survives. Same
        // treatment as the Fortinet/Watchguard password fields.
        Password = StormshieldPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
        UseOtp = StormshieldUseOtpCheck.IsChecked == true,
        // Do NOT trim the profile blob — inline <ca>/<cert>/<key> blocks rely on internal newlines.
        ProfileOvpn = StormshieldProfileOvpnBox.Text,
        CaPem = string.IsNullOrWhiteSpace(StormshieldCaPemBox.Text) ? null : StormshieldCaPemBox.Text,
        TrustServerCertificate = StormshieldTrustCertCheck.IsChecked == true,
        BypassNativeVpnGatewayRoute = StormshieldBypassNativeVpnRouteCheck.IsChecked == true,
        OpenVpnTransportOverride = StormshieldSelectedTransportOverride,
        OpenVpnCompressionFramingOverride = StormshieldSelectedCompressionFramingOverride,
        AppToken = string.IsNullOrWhiteSpace(StormshieldAppTokenBox.Text)
            ? StormshieldSettings.DefaultAppToken
            : StormshieldAppTokenBox.Text.Trim(),
    };

    private WireGuardSettings BuildWireGuard() => new()
    {
        InterfacePrivateKey = InterfacePrivateKeyBox.Text.Trim(),
        InterfaceAddress = InterfaceAddressBox.Text.Trim(),
        Mtu = TryParseInt(MtuBox.Text),
        Dns = SplitCsv(DnsBox.Text),
        PeerPublicKey = PeerPublicKeyBox.Text.Trim(),
        PeerPresharedKey = string.IsNullOrWhiteSpace(PeerPresharedKeyBox.Text) ? null : PeerPresharedKeyBox.Text.Trim(),
        PeerEndpoint = PeerEndpointBox.Text.Trim(),
        AllowedIps = SplitCsv(AllowedIpsBox.Text),
        PersistentKeepaliveSeconds = TryParseInt(PersistentKeepaliveBox.Text),
    };

    private OpenVpnSettings BuildOpenVpn() => new()
    {
        // Do NOT trim the profile blob — leading/trailing whitespace is fine, but inline
        // <ca>/<cert>/<key> blocks rely on internal newlines that String.Trim() never touches.
        // The username gets a Trim because OpenVPN servers commonly reject leading whitespace
        // in usernames; the password stays verbatim (whitespace can be a legitimate character).
        ProfileOvpn = ProfileOvpnBox.Text,
        Username = string.IsNullOrWhiteSpace(OpenVpnUsernameBox.Text) ? null : OpenVpnUsernameBox.Text.Trim(),
        Password = string.IsNullOrEmpty(OpenVpnPasswordBox.Password) ? null : OpenVpnPasswordBox.Password,
    };

    private WatchguardSettings BuildWatchguard()
    {
        return new WatchguardSettings
        {
            Server = WatchguardServerBox.Text.Trim(),
            Port = TryParseInt(WatchguardPortBox.Text) ?? 443,
            AuthMode = WatchguardSelectedAuthMode,
            Username = WatchguardUsernameBox.Text.Trim(),
            // Same reasoning as Fortinet: strip only trailing CR/LF (paste artifacts) — leave
            // every other character intact so legitimate whitespace in a password survives.
            Password = WatchguardPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
            Domain = string.IsNullOrWhiteSpace(WatchguardDomainBox.Text) ? string.Empty : WatchguardDomainBox.Text.Trim(),
            CaPem = WatchguardCaPemBox.Text,
            ClientCertPem = WatchguardClientCertPemBox.Text,
            ClientKeyPem = WatchguardClientKeyPemBox.Text,
            ProfileOvpn = _watchguardProfileOvpn,
            VerifyX509Name = string.IsNullOrWhiteSpace(WatchguardVerifyX509NameBox.Text)
                ? WatchguardSettings.DefaultVerifyX509Name
                : WatchguardVerifyX509NameBox.Text.Trim(),
            TrustServerCertificate = WatchguardTrustCertCheck.IsChecked == true,
        };
    }

    private async void OnWatchguardImportClicked(object sender, RoutedEventArgs e)
    {
        // Whole method body in try/catch — the HWND lookup, COM init, and tar parsing can all
        // throw, and async void would otherwise bubble those to App.UnhandledException with
        // the editor still open. Errors surface in the WatchguardImportStatus InfoBar inside
        // the panel, NOT a secondary ContentDialog — TunnelDialog itself is hosted in a
        // ContentDialog and WinUI 3 only permits one ContentDialog per XamlRoot.
        WatchguardImportStatus.IsOpen = false;
        try
        {
            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.Downloads,
            };
            // Accepted extensions match what the importer's content-sniffer handles. The
            // vendor extraction workflow itself renames `.wgssl` → `.tgz` before extracting,
            // so users frequently end up with the renamed bundle on disk — whitelisting
            // `.tgz` (and `.gz` for hand-prepared bundles) keeps the picker usable for those
            // cases instead of forcing them to rename back. Dropping the "*" wildcard avoids
            // a known FileOpenPicker rejection on some Win11 builds where mixing wildcards
            // with extension filters throws at PickSingleFileAsync.
            picker.FileTypeFilter.Add(".wgssl");
            picker.FileTypeFilter.Add(".tgz");
            picker.FileTypeFilter.Add(".tar");
            picker.FileTypeFilter.Add(".gz");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            using var stream = await file.OpenStreamForReadAsync();
            // No explicit dialog-scoped CancellationToken is exposed here, but the importer's
            // per-entry size cap (1 MiB) and entry-count cap protect against OOM.
            var imported = await WatchguardWgsslImporter.ImportAsync(stream);

            WatchguardServerBox.Text = imported.Server;
            WatchguardPortBox.Text = imported.Port.ToString();
            WatchguardCaPemBox.Text = imported.CaPem;
            WatchguardClientCertPemBox.Text = imported.ClientCertPem;
            WatchguardClientKeyPemBox.Text = imported.ClientKeyPem;
            _watchguardProfileOvpn = imported.ProfileOvpn;
            // Reveal the certs the import just loaded (they land inside the expander) and refresh
            // the missing-fields hint now that the three PEMs are populated. Setting each box's
            // Text already fired OnFieldChanged -> UpdateValidationHint, so this is belt-and-
            // suspenders for the hint and the meaningful change for the expander state.
            WatchguardCertsExpander.IsExpanded = true;
            UpdateValidationHint();
            ValidityChanged?.Invoke(this, EventArgs.Empty);

            WatchguardImportStatus.Severity = InfoBarSeverity.Success;
            WatchguardImportStatus.Title = "Imported";
            WatchguardImportStatus.Message = $"Loaded server '{imported.Server}:{imported.Port}' from {file.Name}.";
            WatchguardImportStatus.IsOpen = true;
        }
        catch (Exception ex)
        {
            // Inline error reporting via the InfoBar. The fallback used to be a nested
            // ContentDialog, but WinUI rejects a second ContentDialog inside the same XamlRoot
            // — the parent TunnelDialog ContentDialog is still open here — and the error would
            // be silently swallowed. The InfoBar lives inside our panel so it has no such
            // restriction. Defensive null-check on InfoBar in case the UserControl was unloaded
            // mid-await (e.g. user closed the parent dialog while picker was up).
            try
            {
                if (WatchguardImportStatus is null) return;
                WatchguardImportStatus.Severity = InfoBarSeverity.Error;
                WatchguardImportStatus.Title = "Couldn't import .wgssl";
                WatchguardImportStatus.Message = ex.Message;
                WatchguardImportStatus.IsOpen = true;
            }
            catch
            {
                // Last-resort swallow: nothing meaningful to do if even setting the InfoBar
                // properties fails (the visual tree is gone). The original ex was already
                // surfaced via the failed import; the user re-tries.
            }
        }
    }

    private FortinetSettings BuildFortinet()
    {
        // TOTP shared secrets are conventionally displayed in Base32 with embedded spaces
        // every 4 characters (e.g. "ABCD EFGH IJKL MNOP"). Trim() only strips ends, so a
        // paste from a 2FA enrollment screen with internal spaces would persist verbatim
        // and the sidecar would later fail Base32 decode with a cryptic 'illegal base32'
        // error. Strip ALL whitespace instead so the secret is normalized regardless of
        // how the user copied it. Same treatment for the cert pin which often arrives with
        // ':' separators that the sidecar already strips, but extra whitespace would still
        // break hex parsing.
        var useSso = FortinetSsoCheck.IsChecked == true;
        var useExternalBrowser = FortinetExternalBrowserCheck.IsChecked == true;
        var totp = useSso ? string.Empty : StripWhitespace(FortinetTotpSecretBox.Password);
        return new FortinetSettings
        {
            Host = FortinetHostBox.Text.Trim(),
            Port = TryParseInt(FortinetPortBox.Text) ?? 443,
            Username = useSso ? string.Empty : FortinetUsernameBox.Text.Trim(),
            // Strip ONLY trailing \r/\n. Passwords can legitimately contain leading,
            // embedded, OR trailing whitespace (spaces and tabs are valid password chars),
            // so a blanket TrimEnd() would silently corrupt those. CR/LF however are paste
            // artifacts — `pass` CLI and many browser password managers append them when
            // copying — that the user can't see in the masked PasswordBox and that
            // FortiGate would otherwise reject as part of an "invalid credentials" message.
            Password = useSso ? string.Empty : FortinetPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
            Realm = useSso && useExternalBrowser || string.IsNullOrWhiteSpace(FortinetRealmBox.Text)
                ? null
                : FortinetRealmBox.Text.Trim(),
            TotpSecret = string.IsNullOrEmpty(totp) ? null : totp,
            UseSingleSignOn = useSso,
            UseExternalBrowser = useExternalBrowser,
            SamlRedirectPort = TryParseInt(FortinetSamlRedirectPortBox.Text) ?? FortinetSettings.DefaultSamlRedirectPort,
            TrustServerCertificate = FortinetTrustCertCheck.IsChecked == true,
            ServerCertSha256Pin = string.IsNullOrWhiteSpace(FortinetCertPinBox.Text) ? null : StripWhitespace(FortinetCertPinBox.Text),
        };
    }

    public void FocusNameField()
    {
        NameBox.Focus(FocusState.Programmatic);
        NameBox.SelectAll();
    }

    private void OnFieldChanged(object sender, TextChangedEventArgs e)
    {
        if (ReferenceEquals(sender, FortinetRealmBox))
            UpdateFortinetAuthFields();
        UpdateValidationHint();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    // PasswordBox.PasswordChanged delivers RoutedEventArgs, not TextChangedEventArgs — separate
    // handler so the XAML compiler doesn't reject the type mismatch. Behavior is identical:
    // re-fire ValidityChanged so any future IsValid rule that depends on the password field
    // (e.g. "username requires password") reflects edits live instead of going stale until the
    // user touches a TextBox.
    private void OnPasswordFieldChanged(object sender, RoutedEventArgs e)
    {
        UpdateValidationHint();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void OnFortinetSsoChanged(object sender, RoutedEventArgs e)
    {
        UpdateFortinetAuthFields();
        UpdateValidationHint();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateFortinetAuthFields()
    {
        // Checked/Unchecked can fire while InitializeComponent is still constructing later fields.
        if (FortinetSamlRedirectPortBox is null) return;

        var useSso = FortinetSsoCheck.IsChecked == true;
        var useExternalBrowser = useSso && FortinetExternalBrowserCheck.IsChecked == true;
        FortinetExternalBrowserCheck.IsEnabled = useSso;
        FortinetUsernameBox.IsEnabled = !useSso;
        FortinetPasswordBox.IsEnabled = !useSso;
        FortinetTotpSecretBox.IsEnabled = !useSso;
        FortinetRealmBox.IsEnabled = !useExternalBrowser || !string.IsNullOrWhiteSpace(FortinetRealmBox.Text);
        FortinetSamlRedirectPortBox.Visibility = useExternalBrowser ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnImportOvpnFile(object sender, RoutedEventArgs e)
    {
        // async void + COM-backed FileOpenPicker: any throw here would otherwise hit
        // App.UnhandledException with the host dialog frozen, so the entire body is in
        // try/catch and failures are surfaced through the inline InfoBar.
        try
        {
            OvpnImportErrorBar.IsOpen = false;

            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            };
            picker.FileTypeFilter.Add(".ovpn");
            picker.FileTypeFilter.Add(".conf");
            // "*" lets users pick profiles saved without an extension — some vendor portals
            // serve the file as plain "client" with no suffix.
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            var text = await File.ReadAllTextAsync(file.Path);
            // No trim: inline <ca>/<cert>/<key> blocks rely on internal newlines, and the
            // build path already preserves the blob verbatim — mirror that contract on the
            // way in so a round-trip through import matches a hand-paste.
            ProfileOvpnBox.Text = text;
        }
        catch (Exception ex)
        {
            OvpnImportErrorBar.Message = ex.Message;
            OvpnImportErrorBar.IsOpen = true;
        }
    }

    private void OnStormshieldModeChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateStormshieldModePanels();
        // Required fields differ between modes (profile vs username/password), so refresh both the
        // missing-fields hint and the Save gate — same pairing as OnFieldChanged.
        UpdateValidationHint();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void OnWatchguardAuthModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (WatchguardServerBox is null) return;
        UpdateValidationHint();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateStormshieldModePanels()
    {
        // StormshieldModeBox declares inline ComboBoxItems plus SelectedIndex="0", so the XAML
        // parser raises SelectionChanged (-> OnStormshieldModeChanged -> here) partway through
        // InitializeComponent, before StormshieldImportPanel — declared later in the XAML — has
        // been created and assigned to its backing field. (KindBox dodges this only because its
        // items come from an x:Bind ItemsSource that is still empty when its SelectedIndex is
        // applied.) Bail until the field graph exists: the XAML default already collapses
        // StormshieldImportPanel, which matches the default Automatic mode, and any later user
        // or LoadDraft selection re-runs this with every field present.
        if (StormshieldImportPanel is null) return;

        var isImport = StormshieldSelectedMode == StormshieldConnectionMode.Import;
        StormshieldImportPanel.Visibility = isImport ? Visibility.Visible : Visibility.Collapsed;
        // Clear a stale import error when leaving Import mode so it doesn't reappear on return.
        if (!isImport) StormshieldImportErrorBar.IsOpen = false;
    }

    private async void OnStormshieldImportOvpnFile(object sender, RoutedEventArgs e)
    {
        // async void + COM-backed FileOpenPicker: any throw would otherwise hit
        // App.UnhandledException with the host dialog frozen, so the whole body is guarded and
        // failures surface through the inline InfoBar (a nested ContentDialog is impossible here —
        // TunnelDialog is itself hosted in a ContentDialog).
        try
        {
            StormshieldImportErrorBar.IsOpen = false;

            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            };
            picker.FileTypeFilter.Add(".ovpn");
            picker.FileTypeFilter.Add(".conf");
            // Deliberately NOT adding a "*" wildcard: mixing it with explicit extensions makes
            // FileOpenPicker.PickSingleFileAsync throw on some Win11 builds (the Watchguard importer
            // avoids it for the same reason). A user whose profile has no extension can paste it.
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            // No trim: inline <ca>/<cert>/<key> blocks rely on internal newlines.
            StormshieldProfileOvpnBox.Text = await File.ReadAllTextAsync(file.Path);
            ValidityChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            StormshieldImportErrorBar.Title = "Couldn't read file";
            StormshieldImportErrorBar.Message = ex.Message;
            StormshieldImportErrorBar.IsOpen = true;
        }
    }

    private async void OnAzureVpnImportClicked(object sender, RoutedEventArgs e)
    {
        // async void + COM-backed FileOpenPicker: any throw would otherwise hit
        // App.UnhandledException with the host dialog frozen, so the whole body is guarded and
        // failures surface through the inline InfoBar (a nested ContentDialog is impossible here —
        // TunnelDialog is itself hosted in a ContentDialog).
        try
        {
            AzureVpnImportStatus.IsOpen = false;

            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.Downloads,
            };
            picker.FileTypeFilter.Add(".xml");
            // Deliberately NOT adding a "*" wildcard: mixing it with explicit extensions makes
            // FileOpenPicker.PickSingleFileAsync throw on some Win11 builds.
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            var xml = await File.ReadAllTextAsync(file.Path);
            var imported = AzureVpnProfileParser.Parse(xml);

            AzureVpnServersBox.Text = string.Join(", ", imported.Settings.Servers);
            AzureVpnTransportBox.SelectedIndex = imported.Settings.Protocol == AzureVpnTransport.Udp ? 1 : 0;
            AzureVpnTenantBox.Text = imported.Settings.TenantId;
            AzureVpnAudienceBox.Text = imported.Settings.Audience;
            AzureVpnApplicationIdBox.Text = imported.Settings.ApplicationId ?? string.Empty;
            AzureVpnIssuerBox.Text = imported.Settings.Issuer ?? string.Empty;
            AzureVpnServerSecretBox.Text = imported.Settings.ServerSecretHex ?? string.Empty;
            // Suggest the profile's display name for a fresh tunnel; never clobber a name the
            // user already typed or an existing tunnel's name being edited.
            if (string.IsNullOrWhiteSpace(NameBox.Text) && !string.IsNullOrWhiteSpace(imported.ProfileName))
                NameBox.Text = imported.ProfileName;

            UpdateValidationHint();
            ValidityChanged?.Invoke(this, EventArgs.Empty);

            AzureVpnImportStatus.Severity = InfoBarSeverity.Success;
            AzureVpnImportStatus.Title = "Imported";
            AzureVpnImportStatus.Message = $"Loaded gateway '{imported.Settings.Servers[0]}' from {file.Name}.";
            AzureVpnImportStatus.IsOpen = true;
        }
        catch (Exception ex)
        {
            try
            {
                if (AzureVpnImportStatus is null) return;
                AzureVpnImportStatus.Severity = InfoBarSeverity.Error;
                AzureVpnImportStatus.Title = "Couldn't import azurevpnconfig.xml";
                AzureVpnImportStatus.Message = ex.Message;
                AzureVpnImportStatus.IsOpen = true;
            }
            catch
            {
                // Visual tree gone (parent dialog closed mid-await); nothing meaningful to do.
            }
        }
    }

    private async void OnCiscoSecureClientImportClicked(object sender, RoutedEventArgs e)
    {
        // async void + COM-backed FileOpenPicker: failures surface through the inline InfoBar
        // because TunnelDialog is already hosted inside a ContentDialog.
        try
        {
            CiscoImportStatus.IsOpen = false;

            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.Downloads,
            };
            picker.FileTypeFilter.Add(".xml");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            var xml = await File.ReadAllTextAsync(file.Path);
            var imported = CiscoSecureClientProfileParser.Parse(xml);

            CiscoHostBox.Text = imported.Settings.Host;
            CiscoPortBox.Text = imported.Settings.Port.ToString();
            CiscoGroupBox.Text = imported.Settings.Group ?? string.Empty;
            if (string.IsNullOrWhiteSpace(NameBox.Text) && !string.IsNullOrWhiteSpace(imported.ProfileName))
                NameBox.Text = imported.ProfileName;

            UpdateValidationHint();
            ValidityChanged?.Invoke(this, EventArgs.Empty);

            CiscoImportStatus.Severity = InfoBarSeverity.Success;
            CiscoImportStatus.Title = "Imported";
            CiscoImportStatus.Message = $"Loaded gateway '{imported.Settings.Host}:{imported.Settings.Port}' from {file.Name}.";
            CiscoImportStatus.IsOpen = true;
        }
        catch (Exception ex)
        {
            try
            {
                if (CiscoImportStatus is null) return;
                CiscoImportStatus.Severity = InfoBarSeverity.Error;
                CiscoImportStatus.Title = "Couldn't import AnyConnect profile";
                CiscoImportStatus.Message = ex.Message;
                CiscoImportStatus.IsOpen = true;
            }
            catch
            {
                // Visual tree gone (parent dialog closed mid-await); nothing meaningful to do.
            }
        }
    }

    private void OnKindChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateKindPanels();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateKindPanels()
    {
        WireGuardPanel.Visibility = SelectedKind == TunnelKind.WireGuard
            ? Visibility.Visible
            : Visibility.Collapsed;
        OpenVpnPanel.Visibility = SelectedKind == TunnelKind.OpenVpn
            ? Visibility.Visible
            : Visibility.Collapsed;
        FortinetPanel.Visibility = SelectedKind == TunnelKind.Fortinet
            ? Visibility.Visible
            : Visibility.Collapsed;
        if (SelectedKind == TunnelKind.Fortinet)
            UpdateFortinetAuthFields();
        WatchguardPanel.Visibility = SelectedKind == TunnelKind.Watchguard
            ? Visibility.Visible
            : Visibility.Collapsed;
        StormshieldPanel.Visibility = SelectedKind == TunnelKind.Stormshield
            ? Visibility.Visible
            : Visibility.Collapsed;
        AzureVpnPanel.Visibility = SelectedKind == TunnelKind.AzureVpn
            ? Visibility.Visible
            : Visibility.Collapsed;
        CiscoSecureClientPanel.Visibility = SelectedKind == TunnelKind.CiscoSecureClient
            ? Visibility.Visible
            : Visibility.Collapsed;
        if (SelectedKind == TunnelKind.Watchguard)
        {
            WatchguardCertsExpander.IsExpanded =
                !string.IsNullOrWhiteSpace(WatchguardDomainBox.Text) ||
                !string.IsNullOrWhiteSpace(WatchguardCaPemBox.Text) ||
                !string.IsNullOrWhiteSpace(WatchguardClientCertPemBox.Text) ||
                !string.IsNullOrWhiteSpace(WatchguardClientKeyPemBox.Text);
        }
        // Stale import-error bars from a previous session would otherwise re-surface when the user
        // toggles Kind away and back. They're panel-specific, so reset them on any panel change.
        OvpnImportErrorBar.IsOpen = false;
        StormshieldImportErrorBar.IsOpen = false;
        AzureVpnImportStatus.IsOpen = false;
        CiscoImportStatus.IsOpen = false;
        UpdateValidationHint();
    }

    private static List<string> SplitCsv(string s)
    {
        var values = new List<string>(4);
        var start = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] is ',' or ';')
            {
                AddCsvValue(values, s.AsSpan(start, i - start));
                start = i + 1;
            }
        }

        AddCsvValue(values, s.AsSpan(start));
        return values;
    }

    private static void AddCsvValue(List<string> values, ReadOnlySpan<char> value)
    {
        value = value.Trim();
        if (!value.IsEmpty) values.Add(value.ToString());
    }

    private static int? TryParseInt(string s) =>
        int.TryParse(s, out var n) ? n : (int?)null;

    private static string StripWhitespace(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (!char.IsWhiteSpace(c)) sb.Append(c);
        }
        return sb.ToString();
    }
}
