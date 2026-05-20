using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;

namespace Wormhole.Views.Dialogs;

public sealed partial class NewConnectionDialog : ContentDialog
{
    public NewConnectionDialog()
    {
        this.InitializeComponent();
    }

    public ProtocolType[] Protocols { get; } = Enum.GetValues<ProtocolType>();

    public NewConnectionDraft? Result { get; private set; }

    public void InitializeForEdit(NewConnectionDraft initial)
    {
        Title = "Edit connection";
        PrimaryButtonText = "Save";
        NameBox.Text = initial.Name;
        ProtocolBox.SelectedItem = initial.Protocol;
        HostBox.Text = initial.Host;
        if (initial.Port is { } port) PortBox.Value = port;
        UsernameBox.Text = initial.Username ?? string.Empty;
        IsPrimaryButtonEnabled = true;
    }

    private void OnOpened(ContentDialog sender, ContentDialogOpenedEventArgs args)
    {
        NameBox.Focus(FocusState.Programmatic);
        NameBox.SelectAll();
    }

    private void OnFieldChanged(object sender, TextChangedEventArgs e)
    {
        IsPrimaryButtonEnabled =
            !string.IsNullOrWhiteSpace(NameBox.Text) &&
            !string.IsNullOrWhiteSpace(HostBox.Text);
    }

    private void OnPrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        var protocol = (ProtocolType)ProtocolBox.SelectedItem;
        int? port = double.IsNaN(PortBox.Value) ? null : (int)PortBox.Value;
        var username = string.IsNullOrWhiteSpace(UsernameBox.Text) ? null : UsernameBox.Text.Trim();

        Result = new NewConnectionDraft(
            NameBox.Text.Trim(),
            protocol,
            HostBox.Text.Trim(),
            port,
            username);
    }
}
