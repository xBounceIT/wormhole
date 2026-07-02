using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;

namespace Wormhole.Views.Dialogs;

public sealed partial class CredentialDialog : UserControl, IDraftForm<CredentialDraft>
{
    public event EventHandler? ValidityChanged;

    public CredentialDialog()
    {
        this.InitializeComponent();
        UpdateProviderVisibility();
    }

    // Credentials are scoped per protocol (Ssh/Rdp/Vnc). SFTP is not a protocol — file transfer
    // runs over an SSH session and reuses that connection's SSH credential. The HTTP/HTTPS web
    // protocols are credential-less, so they're deliberately excluded here (an explicit list, NOT
    // Enum.GetValues, so new protocols don't silently appear as credential types).
    public ProtocolType[] Protocols { get; } = { ProtocolType.Ssh, ProtocolType.Rdp, ProtocolType.Vnc };

    public double? PreferredDialogMinWidth => 560;

    private ProtocolType SelectedProtocol =>
        ProtocolBox.SelectedItem is ProtocolType p ? p : ProtocolType.Ssh;

    private CredentialSecretProvider SelectedProvider =>
        ProviderBox.SelectedIndex == 1 ? CredentialSecretProvider.Bitwarden : CredentialSecretProvider.Local;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        (SelectedProtocol == ProtocolType.Vnc || !string.IsNullOrWhiteSpace(UsernameBox.Text)) &&
        (SelectedProvider == CredentialSecretProvider.Bitwarden
            ? !string.IsNullOrWhiteSpace(BitwardenItemIdBox.Text)
            : !string.IsNullOrEmpty(PasswordField.Password)) &&
        (SelectedProtocol != ProtocolType.Rdp || !string.IsNullOrWhiteSpace(DomainBox.Text));

    public void LoadDraft(CredentialDraft initial)
    {
        NameBox.Text = initial.Name;
        ProtocolBox.SelectedItem = initial.Protocol;
        ProviderBox.SelectedIndex = initial.SecretProvider == CredentialSecretProvider.Bitwarden ? 1 : 0;
        UsernameBox.Text = initial.Username;
        DomainBox.Text = initial.Domain ?? string.Empty;
        PasswordField.Password = initial.Password;
        BitwardenItemIdBox.Text = initial.BitwardenItemId ?? string.Empty;
        BitwardenItemNameBox.Text = initial.BitwardenItemName ?? string.Empty;
        UpdateProtocolFieldVisibility();
        UpdateProviderVisibility();
    }

    public CredentialDraft BuildDraft()
    {
        var protocol = SelectedProtocol;
        var username = protocol == ProtocolType.Vnc ? string.Empty : UsernameBox.Text.Trim();
        var domain = protocol == ProtocolType.Rdp && !string.IsNullOrWhiteSpace(DomainBox.Text)
            ? DomainBox.Text.Trim()
            : null;
        var provider = SelectedProvider;

        return new CredentialDraft(
            NameBox.Text.Trim(),
            protocol,
            username,
            domain,
            provider == CredentialSecretProvider.Local ? PasswordField.Password : string.Empty,
            provider,
            provider == CredentialSecretProvider.Bitwarden ? BitwardenItemIdBox.Text.Trim() : null,
            provider == CredentialSecretProvider.Bitwarden ? NullIfWhiteSpace(BitwardenItemNameBox.Text) : null,
            provider == CredentialSecretProvider.Bitwarden ? BitwardenDefaults.PasswordFieldPath : null);
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

    private void OnProviderChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateProviderVisibility();
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

    private void UpdateProviderVisibility()
    {
        var bitwarden = SelectedProvider == CredentialSecretProvider.Bitwarden;
        PasswordField.Visibility = bitwarden ? Visibility.Collapsed : Visibility.Visible;
        BitwardenPanel.Visibility = bitwarden ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnBitwardenSearchClick(object sender, RoutedEventArgs e)
    {
        await SearchBitwardenAsync().ConfigureAwait(true);
    }

    private async void OnBitwardenSearchKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Enter) return;
        e.Handled = true;
        await SearchBitwardenAsync().ConfigureAwait(true);
    }

    private async Task SearchBitwardenAsync()
    {
        var settings = App.Current.Services.GetService<IAppSettingsService>();
        var client = App.Current.Services.GetService<IBitwardenVaultClient>();
        var session = App.Current.Services.GetService<IBitwardenSessionService>();
        if (settings is null || client is null || session is null)
        {
            ShowBitwardenStatus("Bitwarden services are not available.");
            return;
        }
        if (!settings.Current.EnableBitwardenVault)
        {
            ShowBitwardenStatus("Enable Bitwarden in Settings before searching the vault.");
            return;
        }

        BitwardenSearchButton.IsEnabled = false;
        ShowBitwardenStatus("Searching Bitwarden...");
        try
        {
            var items = await SearchWithUnlockRetryAsync(client, session).ConfigureAwait(true);
            if (BitwardenUnlockField.Visibility == Visibility.Visible && string.IsNullOrEmpty(BitwardenUnlockField.Password) && items.Count == 0)
            {
                return;
            }
            var choices = items.Select(item => new BitwardenItemChoice(item)).ToList();
            BitwardenItemsBox.ItemsSource = choices;
            BitwardenItemsBox.SelectedIndex = choices.Count == 1 ? 0 : -1;
            ShowBitwardenStatus(choices.Count == 0 ? "No Bitwarden login items matched." : $"Found {choices.Count} login item(s).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ShowBitwardenStatus(ex.Message);
        }
        finally
        {
            BitwardenSearchButton.IsEnabled = true;
        }
    }

    private async Task<IReadOnlyList<BitwardenLoginItem>> SearchWithUnlockRetryAsync(
        IBitwardenVaultClient client,
        IBitwardenSessionService session)
    {
        try
        {
            return await client.SearchLoginItemsAsync(BitwardenSearchBox.Text, session.SessionKey).ConfigureAwait(true);
        }
        catch (BitwardenVaultException ex) when (ex.IsAuthenticationError)
        {
            if (string.IsNullOrEmpty(BitwardenUnlockField.Password))
            {
                BitwardenUnlockField.Visibility = Visibility.Visible;
                ShowBitwardenStatus("Enter your Bitwarden master password, then search again.");
                return Array.Empty<BitwardenLoginItem>();
            }

            var masterPassword = BitwardenUnlockField.Password;
            BitwardenUnlockField.Password = string.Empty;
            var sessionKey = await client.UnlockAsync(masterPassword).ConfigureAwait(true);
            session.SetSessionKey(sessionKey);
            BitwardenUnlockField.Visibility = Visibility.Collapsed;
            return await client.SearchLoginItemsAsync(BitwardenSearchBox.Text, session.SessionKey).ConfigureAwait(true);
        }
    }

    private void OnBitwardenItemChanged(object sender, SelectionChangedEventArgs e)
    {
        if (BitwardenItemsBox.SelectedItem is not BitwardenItemChoice choice) return;
        BitwardenItemIdBox.Text = choice.Item.Id;
        BitwardenItemNameBox.Text = choice.Item.Name;
        if (SelectedProtocol != ProtocolType.Vnc && string.IsNullOrWhiteSpace(UsernameBox.Text))
        {
            UsernameBox.Text = choice.Item.Username ?? string.Empty;
        }
        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            NameBox.Text = choice.Item.Name;
        }
        ValidityChanged?.Invoke(this, EventArgs.Empty);
    }

    private void ShowBitwardenStatus(string message)
    {
        BitwardenStatusBlock.Text = message;
        BitwardenStatusBlock.Visibility = string.IsNullOrWhiteSpace(message) ? Visibility.Collapsed : Visibility.Visible;
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed class BitwardenItemChoice
    {
        public BitwardenItemChoice(BitwardenLoginItem item)
        {
            Item = item;
            DisplayName = string.IsNullOrWhiteSpace(item.Username)
                ? item.Name
                : $"{item.Name} - {item.Username}";
        }

        public BitwardenLoginItem Item { get; }
        public string DisplayName { get; }
    }
}
