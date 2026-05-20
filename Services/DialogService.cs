using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.Views.Dialogs;

namespace Wormhole.Services;

public sealed class DialogService : IDialogService
{
    public Task ShowMessageAsync(string title, string message)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            CloseButtonText = "OK",
            XamlRoot = RequireXamlRoot(),
        };
        return dialog.ShowAsync().AsTask();
    }

    public async Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No")
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            PrimaryButtonText = primaryText,
            CloseButtonText = closeText,
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
        };
        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary;
    }

    public async Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "")
    {
        var textBox = new TextBox
        {
            Header = label,
            Text = defaultValue,
            MinWidth = 280,
        };

        var dialog = new ContentDialog
        {
            Title = title,
            Content = textBox,
            PrimaryButtonText = "Create",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(defaultValue),
        };

        textBox.TextChanged += (_, _) =>
            dialog.IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(textBox.Text);

        dialog.Opened += (_, _) =>
        {
            textBox.Focus(FocusState.Programmatic);
            textBox.SelectAll();
        };

        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary ? textBox.Text.Trim() : null;
    }

    public async Task<NewConnectionDraft?> PromptForConnectionAsync(NewConnectionDraft? initial = null)
    {
        var dialog = new NewConnectionDialog { XamlRoot = RequireXamlRoot() };
        if (initial is not null) dialog.InitializeForEdit(initial);
        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary ? dialog.Result : null;
    }

    private static XamlRoot RequireXamlRoot() =>
        App.Current.MainWindow?.Content?.XamlRoot
            ?? throw new InvalidOperationException("No active window to host dialog.");
}
