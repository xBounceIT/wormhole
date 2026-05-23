using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class TunnelDialog : UserControl, IDraftForm<TunnelDraft>
{
    private static readonly char[] CsvSeparators = { ',', ';' };

    public event EventHandler? ValidityChanged;

    public TunnelDialog()
    {
        this.InitializeComponent();
    }

    public TunnelKind[] Kinds { get; } = Enum.GetValues<TunnelKind>();

    private TunnelKind SelectedKind =>
        KindBox.SelectedItem is TunnelKind k ? k : TunnelKind.WireGuard;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        SelectedKind switch
        {
            TunnelKind.WireGuard =>
                !string.IsNullOrWhiteSpace(InterfacePrivateKeyBox.Text) &&
                !string.IsNullOrWhiteSpace(InterfaceAddressBox.Text) &&
                !string.IsNullOrWhiteSpace(PeerPublicKeyBox.Text) &&
                !string.IsNullOrWhiteSpace(PeerEndpointBox.Text),
            TunnelKind.OpenVpn =>
                !string.IsNullOrWhiteSpace(ProfileOvpnBox.Text),
            TunnelKind.Fortinet =>
                !string.IsNullOrWhiteSpace(FortinetHostBox.Text) &&
                IsValidPort(FortinetPortBox.Text) &&
                !string.IsNullOrWhiteSpace(FortinetUsernameBox.Text) &&
                // IsNullOrWhiteSpace mirrors the server-side ValidateFortinet check; an
                // all-whitespace password would otherwise pass the dialog gate and fail at the
                // gateway with a generic 'invalid credentials' message.
                !string.IsNullOrWhiteSpace(FortinetPasswordBox.Password),
            _ => false,
        };

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
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    // PasswordBox.PasswordChanged delivers RoutedEventArgs, not TextChangedEventArgs — separate
    // handler so the XAML compiler doesn't reject the type mismatch. Behavior is identical:
    // re-fire ValidityChanged so any future IsValid rule that depends on the password field
    // (e.g. "username requires password") reflects edits live instead of going stale until the
    // user touches a TextBox.
    private void OnPasswordFieldChanged(object sender, RoutedEventArgs e)
    {
        ValidityChanged?.Invoke(this, EventArgs.Empty);
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
    }

    private static List<string> SplitCsv(string s) =>
        s.Split(CsvSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

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
