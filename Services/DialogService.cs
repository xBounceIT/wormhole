using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Services;

public sealed class DialogService : IDialogService
{
    public Task ShowMessageAsync(XamlRoot xamlRoot, string title, string message)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            CloseButtonText = "OK",
            XamlRoot = xamlRoot,
        };
        return dialog.ShowAsync().AsTask();
    }

    public async Task<bool> ConfirmAsync(XamlRoot xamlRoot, string title, string message)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            PrimaryButtonText = "Yes",
            CloseButtonText = "No",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
        };
        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary;
    }

    public async Task<string?> PromptPasswordAsync(XamlRoot xamlRoot, string title, string message)
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
            XamlRoot = xamlRoot,
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
}
