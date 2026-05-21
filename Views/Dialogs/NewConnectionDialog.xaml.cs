using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class NewConnectionDialog : UserControl, IDraftForm<NewConnectionDraft>
{
    public event EventHandler? ValidityChanged;

    private IReadOnlyList<CredentialProfile> _allCredentials = Array.Empty<CredentialProfile>();
    private readonly ObservableCollection<CredentialChoice> _credentialChoices = new();

    public NewConnectionDialog()
    {
        this.InitializeComponent();
        _credentialChoices.Add(CredentialChoice.None);
        CredentialBox.ItemsSource = _credentialChoices;
        CredentialBox.SelectedIndex = 0;
    }

    public ProtocolType[] Protocols { get; } = Enum.GetValues<ProtocolType>();

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        !string.IsNullOrWhiteSpace(HostBox.Text);

    public void SetAvailableCredentials(IReadOnlyList<CredentialProfile> credentials)
    {
        _allCredentials = credentials ?? Array.Empty<CredentialProfile>();
        RebuildCredentialList(preservedSelectionId: null);
    }

    public void LoadDraft(NewConnectionDraft initial)
    {
        NameBox.Text = initial.Name;
        // Detach so the assignment doesn't trigger a now-redundant rebuild before
        // the explicit one below picks up the saved CredentialId.
        ProtocolBox.SelectionChanged -= OnProtocolChanged;
        ProtocolBox.SelectedItem = initial.Protocol;
        ProtocolBox.SelectionChanged += OnProtocolChanged;
        HostBox.Text = initial.Host;
        if (initial.Port is { } port) PortBox.Value = port;
        UsernameBox.Text = initial.Username ?? string.Empty;
        RebuildCredentialList(preservedSelectionId: initial.CredentialId);
    }

    public NewConnectionDraft BuildDraft()
    {
        var protocol = (ProtocolType)ProtocolBox.SelectedItem;
        int? port = double.IsNaN(PortBox.Value) ? null : (int)PortBox.Value;
        var selectedCredential = (CredentialBox.SelectedItem as CredentialChoice)?.Profile;
        // Username field is hidden while a credential is selected; drop its (possibly stale) text.
        string? username = null;
        if (selectedCredential is null && !string.IsNullOrWhiteSpace(UsernameBox.Text))
        {
            username = UsernameBox.Text.Trim();
        }

        return new NewConnectionDraft(
            NameBox.Text.Trim(),
            protocol,
            HostBox.Text.Trim(),
            port,
            username,
            selectedCredential?.Id);
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

    private void OnProtocolChanged(object sender, SelectionChangedEventArgs e)
    {
        // XAML SelectedIndex="0" can fire this before CredentialBox is wired up.
        if (CredentialBox is null) return;
        if (ProtocolBox.SelectedItem is not ProtocolType newProtocol) return;
        // Only carry the selection forward when the credential still matches the new
        // filter — otherwise the stale-splice path below would re-introduce it and
        // silently expose a protocol-incompatible choice (e.g. SSH cred on RDP conn).
        var current = (CredentialBox.SelectedItem as CredentialChoice)?.Profile;
        var preserved = current is not null && current.Protocol == CredentialProtocolFor(newProtocol)
            ? current.Id
            : (Guid?)null;
        RebuildCredentialList(preservedSelectionId: preserved);
    }

    private void OnCredentialChanged(object sender, SelectionChangedEventArgs e)
    {
        if (UsernameBox is null) return;
        UpdateUsernameVisibility();
    }

    // SFTP connections reuse SSH credentials per CLAUDE.md — the credential dialog
    // doesn't even let users create Sftp-tagged credentials.
    private static ProtocolType CredentialProtocolFor(ProtocolType connectionProtocol) =>
        connectionProtocol == ProtocolType.Sftp ? ProtocolType.Ssh : connectionProtocol;

    private void RebuildCredentialList(Guid? preservedSelectionId)
    {
        if (ProtocolBox.SelectedItem is not ProtocolType selectedProtocol) return;
        var credentialProtocol = CredentialProtocolFor(selectedProtocol);

        _credentialChoices.Clear();
        _credentialChoices.Add(CredentialChoice.None);
        foreach (var cred in _allCredentials.Where(c => c.Protocol == credentialProtocol))
        {
            _credentialChoices.Add(new CredentialChoice(cred));
        }

        // If the connection is bound to a credential whose protocol no longer matches
        // the filter, include it anyway so the binding round-trips on edit.
        if (preservedSelectionId is { } id &&
            !_credentialChoices.Any(c => c.Profile?.Id == id))
        {
            var stale = _allCredentials.FirstOrDefault(c => c.Id == id);
            if (stale is not null) _credentialChoices.Add(new CredentialChoice(stale));
        }

        var match = preservedSelectionId is null
            ? null
            : _credentialChoices.FirstOrDefault(c => c.Profile?.Id == preservedSelectionId);
        CredentialBox.SelectedItem = match ?? _credentialChoices[0];
        UpdateUsernameVisibility();
    }

    private void UpdateUsernameVisibility()
    {
        var hasCredential = (CredentialBox.SelectedItem as CredentialChoice)?.Profile is not null;
        UsernameBox.Visibility = hasCredential ? Visibility.Collapsed : Visibility.Visible;
    }

    private sealed class CredentialChoice
    {
        public static CredentialChoice None { get; } = new(null);

        public CredentialChoice(CredentialProfile? profile)
        {
            Profile = profile;
        }

        public CredentialProfile? Profile { get; }
        public string DisplayName => Profile?.Name ?? "(None — enter manually)";
    }
}
