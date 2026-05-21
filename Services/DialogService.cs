using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Views.Dialogs;

namespace Wormhole.Services;

public sealed class DialogService : IDialogService
{
    private readonly ICredentialRepository _credentialRepository;

    public DialogService(ICredentialRepository credentialRepository)
    {
        _credentialRepository = credentialRepository;
    }

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

    public async Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew)
    {
        var form = new NewConnectionDialog();
        await form.LoadAsync(initial);

        var dialog = new ContentDialog
        {
            Title = isNew ? "New connection" : "Edit connection",
            Content = form,
            PrimaryButtonText = isNew ? "Create" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = form.IsValid,
        };

        form.ValidityChanged += (_, _) => dialog.IsPrimaryButtonEnabled = form.IsValid;
        dialog.Opened += (_, _) => form.FocusNameField();

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary) return null;

        // Produce a fresh node mirroring `initial`'s identity/parent so the caller can update
        // storage without mutating the input. WriteTo only touches editable fields.
        var output = ConnectionNode.CloneIdentityFrom(initial);
        form.WriteTo(output);
        return output;
    }

    public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
        ShowFormDialogAsync(new CredentialDialog(), initial, "credential");

    private async Task<TDraft?> ShowFormDialogAsync<TForm, TDraft>(TForm form, TDraft? initial, string entityName)
        where TForm : UserControl, IDraftForm<TDraft>
        where TDraft : class
    {
        if (initial is not null) form.LoadDraft(initial);

        var dialog = new ContentDialog
        {
            Title = initial is null ? $"New {entityName}" : $"Edit {entityName}",
            Content = form,
            PrimaryButtonText = initial is null ? "Create" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = form.IsValid,
        };

        form.ValidityChanged += (_, _) => dialog.IsPrimaryButtonEnabled = form.IsValid;
        dialog.Opened += (_, _) => form.FocusNameField();

        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary ? form.BuildDraft() : null;
    }

    public async Task<string?> PromptPasswordAsync(string title, string message)
    {
        var passwordBox = new PasswordBox
        {
            PlaceholderText = "Password",
            Width = 320,
        };
        var panel = new StackPanel { Spacing = 8 };
        if (!string.IsNullOrEmpty(message))
        {
            panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        }
        panel.Children.Add(passwordBox);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            PrimaryButtonText = "Connect",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
        };

        var submittedViaEnter = false;
        passwordBox.KeyDown += (_, args) =>
        {
            if (args.Key == Windows.System.VirtualKey.Enter)
            {
                submittedViaEnter = true;
                dialog.Hide();
                args.Handled = true;
            }
        };

        dialog.Opened += (_, _) => passwordBox.Focus(FocusState.Programmatic);

        var result = await dialog.ShowAsync();
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        return accepted ? passwordBox.Password : null;
    }

    private static XamlRoot RequireXamlRoot() =>
        App.Current.MainWindow?.Content?.XamlRoot
            ?? throw new InvalidOperationException("No active window to host dialog.");
}
