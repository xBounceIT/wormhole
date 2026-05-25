using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Wormhole.Helpers;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

public sealed partial class BackupExportDialog : UserControl
{
    public BackupExportDialogViewModel ViewModel { get; }

    public BackupExportDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<BackupExportDialogViewModel>();
        this.InitializeComponent();
    }

    /// <summary>Show the plaintext warning only while the user has no password typed AND the
    /// export hasn't completed AND we aren't currently busy / showing an error. The Status
    /// gate keeps the warning from competing with an error message after a failed attempt.</summary>
    public static Visibility PlaintextWarningVisibility(
        string? password, bool hasResult, bool isBusy, string? status)
    {
        if (!string.IsNullOrEmpty(password)) return Visibility.Collapsed;
        if (hasResult) return Visibility.Collapsed;
        if (isBusy) return Visibility.Collapsed;
        if (!string.IsNullOrWhiteSpace(status)) return Visibility.Collapsed;
        return Visibility.Visible;
    }

    /// <summary>x:Bind helper for the always-visible Status TextBlock; show only when there's
    /// a status string AND neither the progress panel nor the result InfoBar is up.</summary>
    public static Visibility OutOfBandStatusVisibility(string status, bool isBusy, bool hasResult)
    {
        if (string.IsNullOrWhiteSpace(status)) return Visibility.Collapsed;
        if (isBusy || hasResult) return Visibility.Collapsed;
        return Visibility.Visible;
    }

    private async void OnPickFile(object sender, RoutedEventArgs e)
    {
        try
        {
            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = $"wormhole-backup-{DateTime.Now:yyyyMMdd-HHmmss}",
            };
            picker.FileTypeChoices.Add("JSON backup", new List<string> { ".json" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSaveFileAsync();
            if (file is not null)
            {
                ViewModel.ResetForNewFile(file.Path);
                PasswordInput.Password = string.Empty;
                ViewModel.Password = null;
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
        }
    }
}
