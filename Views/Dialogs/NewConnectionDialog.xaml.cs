using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class NewConnectionDialog : UserControl
{
    public event EventHandler? ValidityChanged;

    public NewConnectionDialog()
    {
        this.InitializeComponent();
    }

    public ProtocolType[] Protocols { get; } = Enum.GetValues<ProtocolType>();

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(NameBox.Text) &&
        !string.IsNullOrWhiteSpace(HostBox.Text);

    public void LoadDraft(NewConnectionDraft initial)
    {
        NameBox.Text = initial.Name;
        ProtocolBox.SelectedItem = initial.Protocol;
        HostBox.Text = initial.Host;
        if (initial.Port is { } port) PortBox.Value = port;
        UsernameBox.Text = initial.Username ?? string.Empty;
    }

    public NewConnectionDraft BuildDraft()
    {
        var protocol = (ProtocolType)ProtocolBox.SelectedItem;
        int? port = double.IsNaN(PortBox.Value) ? null : (int)PortBox.Value;
        var username = string.IsNullOrWhiteSpace(UsernameBox.Text) ? null : UsernameBox.Text.Trim();

        return new NewConnectionDraft(
            NameBox.Text.Trim(),
            protocol,
            HostBox.Text.Trim(),
            port,
            username);
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
}
