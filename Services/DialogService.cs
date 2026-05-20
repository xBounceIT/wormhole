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
}
