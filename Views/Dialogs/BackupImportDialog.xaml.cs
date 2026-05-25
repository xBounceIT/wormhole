using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Windows.System;
using Wormhole.Helpers;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

public sealed partial class BackupImportDialog : UserControl
{
    public BackupImportDialogViewModel ViewModel { get; }

    public BackupImportDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<BackupImportDialogViewModel>();
        this.InitializeComponent();
    }

    /// <summary>x:Bind helper — show the always-visible Status line only when the dedicated
    /// surfaces (encrypted-prompt panel, progress, result InfoBar) aren't already rendering
    /// the message.</summary>
    public static Visibility OutOfBandStatusVisibility(string status, bool isBusy, bool hasResult, bool isEncrypted)
    {
        if (string.IsNullOrWhiteSpace(status)) return Visibility.Collapsed;
        if (isBusy || hasResult || isEncrypted) return Visibility.Collapsed;
        return Visibility.Visible;
    }

    private async void OnPickFile(object sender, RoutedEventArgs e)
    {
        try
        {
            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            };
            picker.FileTypeFilter.Add(".json");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is not null)
            {
                await ViewModel.ResetForNewFileAsync(file.Path);
                PasswordInput.Password = string.Empty;
            }
        }
        catch (Exception ex)
        {
            ViewModel.Status = $"Couldn't open file picker: {ex.Message}";
        }
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox box)
        {
            ViewModel.Password = box.Password;
            // Clear stale error the moment the user starts re-typing.
            if (!string.IsNullOrEmpty(ViewModel.PasswordError))
            {
                ViewModel.PasswordError = null;
            }
        }
    }

    private void OnPasswordKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        // Intercept Enter so ContentDialog's primary "Close" button doesn't swallow it.
        if (e.Key != VirtualKey.Enter) return;
        e.Handled = true;
        if (ViewModel.StartImportCommand.CanExecute(null))
        {
            ViewModel.StartImportCommand.Execute(null);
        }
    }
}
