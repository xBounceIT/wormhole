using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class CredentialDialog : UserControl, IDraftForm<CredentialDraft>
{
    public event EventHandler? ValidityChanged;

    public CredentialDialog()
    {
        this.InitializeComponent();
    }

    // Credentials are scoped per protocol (Ssh/Rdp/Vnc). SFTP is not a protocol — file transfer
    // runs over an SSH session and reuses that connection's SSH credential. The HTTP/HTTPS web
    // protocols are credential-less, so they're deliberately excluded here (an explicit list, NOT
    // Enum.GetValues, so new protocols don't silently appear as credential types).
    public ProtocolType[] Protocols { get; } = { ProtocolType.Ssh, ProtocolType.Rdp, ProtocolType.Vnc };

    private ProtocolType SelectedProtocol =>
        ProtocolBox.SelectedItem is ProtocolType p ? p : ProtocolType.Ssh;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        (SelectedProtocol == ProtocolType.Vnc || !string.IsNullOrWhiteSpace(UsernameBox.Text)) &&
        !string.IsNullOrEmpty(PasswordField.Password) &&
        (SelectedProtocol != ProtocolType.Rdp || !string.IsNullOrWhiteSpace(DomainBox.Text));

    public void LoadDraft(CredentialDraft initial)
    {
        NameBox.Text = initial.Name;
        ProtocolBox.SelectedItem = initial.Protocol;
        UsernameBox.Text = initial.Username;
        DomainBox.Text = initial.Domain ?? string.Empty;
        PasswordField.Password = initial.Password;
        UpdateProtocolFieldVisibility();
    }

    public CredentialDraft BuildDraft()
    {
        var protocol = SelectedProtocol;
        var username = protocol == ProtocolType.Vnc ? string.Empty : UsernameBox.Text.Trim();
        var domain = protocol == ProtocolType.Rdp && !string.IsNullOrWhiteSpace(DomainBox.Text)
            ? DomainBox.Text.Trim()
            : null;

        return new CredentialDraft(
            NameBox.Text.Trim(),
            protocol,
            username,
            domain,
            PasswordField.Password);
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
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void OnProtocolChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateProtocolFieldVisibility();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateProtocolFieldVisibility()
    {
        DomainBox.Visibility = SelectedProtocol == ProtocolType.Rdp
            ? Visibility.Visible
            : Visibility.Collapsed;
        UsernameBox.Visibility = SelectedProtocol == ProtocolType.Vnc
            ? Visibility.Collapsed
            : Visibility.Visible;
    }
}
