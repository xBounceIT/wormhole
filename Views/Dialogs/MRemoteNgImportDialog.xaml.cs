using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using Windows.System;
using Wormhole.Helpers;
using Wormhole.ViewModels;

namespace Wormhole.Views.Dialogs;

public sealed partial class MRemoteNgImportDialog : UserControl
{
    public MRemoteNgImportDialogViewModel ViewModel { get; }

    public MRemoteNgImportDialog()
    {
        ViewModel = App.Current.Services.GetRequiredService<MRemoteNgImportDialogViewModel>();
        this.InitializeComponent();
    }

    /// <summary>x:Bind function used by the dialog XAML to drive the always-visible Status
    /// TextBlock: show it only when there's a Status string AND none of the other dedicated
    /// surfaces (password InfoBar, progress panel, result InfoBar) is already rendering it.
    /// Without this the cancel/error messages would be invisible because all three conditional
    /// sections collapse on cancel.</summary>
    public Visibility ShouldShowOutOfBandStatus(string status, bool isBusy, bool needsPassword, bool hasResult)
    {
        if (string.IsNullOrWhiteSpace(status)) return Visibility.Collapsed;
        if (isBusy || needsPassword || hasResult) return Visibility.Collapsed;
        return Visibility.Visible;
    }

    private async void OnPickFile(object sender, RoutedEventArgs e)
    {
        // Whole method body in try/catch — the HWND lookup and InitializeWithWindow COM call
        // can throw (NRE if MainWindow is null, COMException if hwnd is invalid) and async void
        // would otherwise bubble those to App.UnhandledException with the dialog frozen.
        try
        {
            // FileOpenPicker is COM-backed; in unpackaged WinUI 3 we have to hand it the main
            // window hwnd before it'll show.
            var mainWindow = App.Current.MainWindow
                ?? throw new InvalidOperationException("Main window is not available.");
            var hwnd = mainWindow.GetHwnd();

            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.List,
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            };
            picker.FileTypeFilter.Add(".xml");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file is not null)
            {
                // Single VM method resets ALL stale per-import state — including EnteredPassword,
                // which the code-behind used to skip. Without that, a second import on the same
                // dialog could submit file A's password against file B silently.
                ViewModel.ResetForNewFile(file.Path);
                // Clear the PasswordBox UI control too — it's not data-bound so the previous
                // value sits in the visual state until manually re-touched.
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
        // PasswordBox.Password doesn't support two-way binding; copy on every change so the
        // SubmitPasswordCommand's CanExecute (which gates on a non-empty EnteredPassword)
        // updates live and so the eventual Submit sees the typed value, not a stale one.
        if (sender is PasswordBox box)
        {
            ViewModel.EnteredPassword = box.Password;
            // Clear any stale error the moment the user starts typing a new attempt.
            if (!string.IsNullOrEmpty(ViewModel.PasswordError))
            {
                ViewModel.PasswordError = null;
            }
        }
    }

    private void OnPasswordKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        // Intercept Enter so it never bubbles to ContentDialog's DefaultButton (which is the
        // "Close" primary). If we only set Handled when SubmitPasswordCommand.CanExecute is
        // true, then pressing Enter with an empty password — or while a previous attempt is
        // still verifying — would silently close the import dialog, throwing away the file
        // selection and any progress. Always handle Enter inside the PasswordBox; only
        // dispatch the submit when the command is ready.
        if (e.Key != VirtualKey.Enter) return;
        e.Handled = true;
        if (ViewModel.SubmitPasswordCommand.CanExecute(null))
        {
            ViewModel.SubmitPasswordCommand.Execute(null);
        }
    }
}
