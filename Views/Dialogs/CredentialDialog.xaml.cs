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

    // Credentials are scoped per protocol (Ssh/Rdp). SFTP is not a protocol — file transfer
    // runs over an SSH session and reuses that connection's SSH credential.
    public ProtocolType[] Protocols { get; } = Enum.GetValues<ProtocolType>();

    private ProtocolType SelectedProtocol =>
        ProtocolBox.SelectedItem is ProtocolType p ? p : ProtocolType.Ssh;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        !string.IsNullOrWhiteSpace(UsernameBox.Text) &&
        !string.IsNullOrEmpty(PasswordField.Password) &&
        (SelectedProtocol != ProtocolType.Rdp || !string.IsNullOrWhiteSpace(DomainBox.Text));

    public void LoadDraft(CredentialDraft initial)
    {
        NameBox.Text = initial.Name;
        ProtocolBox.SelectedItem = initial.Protocol;
        UsernameBox.Text = initial.Username;
        DomainBox.Text = initial.Domain ?? string.Empty;
        PasswordField.Password = initial.Password;
        UpdateDomainVisibility();
    }

    public CredentialDraft BuildDraft()
    {
        var protocol = SelectedProtocol;
        var domain = protocol == ProtocolType.Rdp && !string.IsNullOrWhiteSpace(DomainBox.Text)
            ? DomainBox.Text.Trim()
            : null;

        return new CredentialDraft(
            NameBox.Text.Trim(),
            protocol,
            UsernameBox.Text.Trim(),
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
        UpdateDomainVisibility();
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateDomainVisibility()
    {
        DomainBox.Visibility = SelectedProtocol == ProtocolType.Rdp
            ? Visibility.Visible
            : Visibility.Collapsed;
    }
}
