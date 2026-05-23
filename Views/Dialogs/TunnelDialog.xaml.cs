using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class TunnelDialog : UserControl, IDraftForm<TunnelDraft>
{
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

        var wg = initial.WireGuard;
        InterfacePrivateKeyBox.Text = wg.InterfacePrivateKey;
        InterfaceAddressBox.Text = wg.InterfaceAddress;
        MtuBox.Text = wg.Mtu?.ToString() ?? string.Empty;
        DnsBox.Text = wg.Dns is null ? string.Empty : string.Join(", ", wg.Dns);
        PeerPublicKeyBox.Text = wg.PeerPublicKey;
        PeerPresharedKeyBox.Text = wg.PeerPresharedKey ?? string.Empty;
        PeerEndpointBox.Text = wg.PeerEndpoint;
        AllowedIpsBox.Text = wg.AllowedIps is null ? string.Empty : string.Join(", ", wg.AllowedIps);
        PersistentKeepaliveBox.Text = wg.PersistentKeepaliveSeconds?.ToString() ?? string.Empty;

        var fg = initial.Fortinet;
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
        var wg = new WireGuardSettings
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
        // TOTP shared secrets are conventionally displayed in Base32 with embedded spaces
        // every 4 characters (e.g. "ABCD EFGH IJKL MNOP"). Trim() only strips ends, so a
        // paste from a 2FA enrollment screen with internal spaces would persist verbatim
        // and the sidecar would later fail Base32 decode with a cryptic 'illegal base32'
        // error. Strip ALL whitespace instead so the secret is normalized regardless of
        // how the user copied it. Same treatment for the cert pin which often arrives with
        // ':' separators that the sidecar already strips, but extra whitespace would still
        // break hex parsing.
        var totp = StripWhitespace(FortinetTotpSecretBox.Password);
        var fg = new FortinetSettings
        {
            Host = FortinetHostBox.Text.Trim(),
            Port = TryParseInt(FortinetPortBox.Text) ?? 443,
            Username = FortinetUsernameBox.Text.Trim(),
            // TrimEnd only — passwords can legitimately contain leading or embedded
            // whitespace (rare but real), but pasting from a password manager that adds a
            // trailing newline would otherwise persist invisible whitespace that FortiGate
            // rejects as "invalid credentials" with no actionable feedback to the user.
            Password = FortinetPasswordBox.Password?.TrimEnd() ?? string.Empty,
            Realm = string.IsNullOrWhiteSpace(FortinetRealmBox.Text) ? null : FortinetRealmBox.Text.Trim(),
            TotpSecret = string.IsNullOrEmpty(totp) ? null : totp,
            TrustServerCertificate = FortinetTrustCertCheck.IsChecked == true,
            ServerCertSha256Pin = string.IsNullOrWhiteSpace(FortinetCertPinBox.Text) ? null : StripWhitespace(FortinetCertPinBox.Text),
        };
        return new TunnelDraft(NameBox.Text.Trim(), SelectedKind, wg, fg);
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

    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        // PasswordBox doesn't raise TextChanged; route its PasswordChanged to the same handler
        // so the dialog's Save button enables/disables in lockstep with the other fields.
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
        FortinetPanel.Visibility = SelectedKind == TunnelKind.Fortinet
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private static List<string> SplitCsv(string s) =>
        s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

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
