using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Watchguard;

namespace Wormhole.Views.Dialogs;

public sealed partial class TunnelDialog : UserControl, IDraftForm<TunnelDraft>
{
    public event EventHandler? ValidityChanged;

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

    // The horizontal 2-column layout in the XAML needs ~760 px of dialog width to render
    // without clipping — overrides the ContentDialog ~548 px theme cap. DialogService
    // clamps this against XamlRoot.Size so the dialog stays inside narrow host windows.
    public double? PreferredDialogMinWidth => 760;

    private TunnelKind SelectedKind =>
        KindBox.SelectedItem is TunnelKind k ? k : TunnelKind.WireGuard;

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
                if (string.IsNullOrWhiteSpace(FortinetUsernameBox.Text)) missing.Add("Username");
                // IsNullOrWhiteSpace mirrors the server-side ValidateFortinet check; an
                // all-whitespace password would otherwise pass the dialog gate and fail at the
                // gateway with a generic 'invalid credentials' message.
                if (string.IsNullOrWhiteSpace(FortinetPasswordBox.Password)) missing.Add("Password");
                break;
            case TunnelKind.Watchguard:
                if (string.IsNullOrWhiteSpace(WatchguardServerBox.Text)) missing.Add("Server");
                if (!IsValidPort(WatchguardPortBox.Text)) missing.Add("Port (1-65535)");
                if (string.IsNullOrWhiteSpace(WatchguardUsernameBox.Text)) missing.Add("Username");
                if (string.IsNullOrWhiteSpace(WatchguardPasswordBox.Password)) missing.Add("Password");
                // These three live in the collapsed "Certificates & advanced" expander and are
                // mandatory: the WatchGuard SSL tunnel is OpenVPN-with-client-cert and the
                // synthesized profile can't be built without them (WatchguardProfileBuilder).
                // UpdateKindPanels auto-expands that section while any is empty so they're on
                // screen rather than a hidden reason Create stays disabled.
                if (string.IsNullOrWhiteSpace(WatchguardCaPemBox.Text)) missing.Add("CA certificate (PEM)");
                if (string.IsNullOrWhiteSpace(WatchguardClientCertPemBox.Text)) missing.Add("Client certificate (PEM)");
                if (string.IsNullOrWhiteSpace(WatchguardClientKeyPemBox.Text)) missing.Add("Client private key (PEM)");
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
        FortinetTrustCertCheck.IsChecked = fg.TrustServerCertificate;
        FortinetCertPinBox.Text = fg.ServerCertSha256Pin ?? string.Empty;

        var wgg = initial.Watchguard ?? new WatchguardSettings();
        // Coalesce every string field defensively: System.Text.Json happily assigns null to a
        // non-nullable string property if the on-disk JSON has the key explicitly null, and
        // TextBox.Text = null throws NRE. The Fortinet branch above does the same with `?? string.Empty`
        // / `?? "Firebox-DB"` for its nullable fields; the Watchguard fields are non-nullable in
        // the model but the deserializer's behavior makes that a weak guarantee at the boundary.
        WatchguardServerBox.Text = wgg.Server ?? string.Empty;
        WatchguardPortBox.Text = (wgg.Port is >= 1 and <= 65535 ? wgg.Port : 443).ToString();
        WatchguardUsernameBox.Text = wgg.Username ?? string.Empty;
        WatchguardPasswordBox.Password = wgg.Password ?? string.Empty;
        WatchguardDomainBox.Text = string.IsNullOrEmpty(wgg.Domain) ? "Firebox-DB" : wgg.Domain;
        WatchguardCaPemBox.Text = wgg.CaPem ?? string.Empty;
        WatchguardClientCertPemBox.Text = wgg.ClientCertPem ?? string.Empty;
        WatchguardClientKeyPemBox.Text = wgg.ClientKeyPem ?? string.Empty;
        WatchguardVerifyX509NameBox.Text = wgg.VerifyX509Name ?? string.Empty;
        WatchguardTrustCertCheck.IsChecked = wgg.TrustServerCertificate;

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
            _ => new TunnelDraft(name, kind, WireGuard: null, OpenVpn: null, Fortinet: null),
        };
    }

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
            Username = WatchguardUsernameBox.Text.Trim(),
            // Same reasoning as Fortinet: strip only trailing CR/LF (paste artifacts) — leave
            // every other character intact so legitimate whitespace in a password survives.
            Password = WatchguardPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
            Domain = string.IsNullOrWhiteSpace(WatchguardDomainBox.Text) ? "Firebox-DB" : WatchguardDomainBox.Text.Trim(),
            CaPem = WatchguardCaPemBox.Text,
            ClientCertPem = WatchguardClientCertPemBox.Text,
            ClientKeyPem = WatchguardClientKeyPemBox.Text,
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
        var totp = StripWhitespace(FortinetTotpSecretBox.Password);
        return new FortinetSettings
        {
            Host = FortinetHostBox.Text.Trim(),
            Port = TryParseInt(FortinetPortBox.Text) ?? 443,
            Username = FortinetUsernameBox.Text.Trim(),
            // Strip ONLY trailing \r/\n. Passwords can legitimately contain leading,
            // embedded, OR trailing whitespace (spaces and tabs are valid password chars),
            // so a blanket TrimEnd() would silently corrupt those. CR/LF however are paste
            // artifacts — `pass` CLI and many browser password managers append them when
            // copying — that the user can't see in the masked PasswordBox and that
            // FortiGate would otherwise reject as part of an "invalid credentials" message.
            Password = FortinetPasswordBox.Password?.TrimEnd('\r', '\n') ?? string.Empty,
            Realm = string.IsNullOrWhiteSpace(FortinetRealmBox.Text) ? null : FortinetRealmBox.Text.Trim(),
            TotpSecret = string.IsNullOrEmpty(totp) ? null : totp,
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
        WatchguardPanel.Visibility = SelectedKind == TunnelKind.Watchguard
            ? Visibility.Visible
            : Visibility.Collapsed;
        // The three mandatory PEM fields live inside the "Certificates & advanced" expander.
        // Auto-expand it for Watchguard whenever any is still empty so the required inputs are
        // on screen — a collapsed-by-default expander hiding required fields is exactly what
        // made Create look permanently disabled. Once all three are set, leave the state to the
        // user (this only runs on load / kind switch, not on every keystroke, so it won't snap
        // shut mid-typing).
        if (SelectedKind == TunnelKind.Watchguard)
        {
            WatchguardCertsExpander.IsExpanded =
                string.IsNullOrWhiteSpace(WatchguardCaPemBox.Text) ||
                string.IsNullOrWhiteSpace(WatchguardClientCertPemBox.Text) ||
                string.IsNullOrWhiteSpace(WatchguardClientKeyPemBox.Text);
        }
        // Stale import-error from a previous OpenVPN session would otherwise re-surface when
        // the user toggles Kind away and back. The InfoBar is OpenVPN-specific, so reset it
        // whenever the active panel changes.
        OvpnImportErrorBar.IsOpen = false;
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
