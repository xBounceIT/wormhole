using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.ViewModels;
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

    public async Task<NewConnectionDraft?> PromptForConnectionAsync(NewConnectionDraft? initial = null)
    {
        var dialog = new NewConnectionDialog();
        var credentials = await _credentialRepository.GetAllAsync();
        dialog.SetAvailableCredentials(credentials);
        return await ShowFormDialogAsync(dialog, initial, "connection");
    }

    public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
        ShowFormDialogAsync(new CredentialDialog(), initial, "credential");

    public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null) =>
        ShowFormDialogAsync(new TunnelDialog(), initial, "VPN tunnel");

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

    public async Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync()
    {
        var control = new MRemoteNgImportDialog();
        var vm = control.ViewModel;

        var dialog = new ContentDialog
        {
            Title = "Import from mRemoteNG",
            Content = control,
            // Single close button; the dialog body owns its own Cancel-during-import button
            // via the VM's CancelCommand.
            PrimaryButtonText = "Close",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = vm.CanClose,
        };

        void OnVmPropChanged(object? _, PropertyChangedEventArgs args)
        {
            if (args.PropertyName == nameof(vm.CanClose))
            {
                dialog.IsPrimaryButtonEnabled = vm.CanClose;
            }
        }

        // ContentDialog.Closing is the only hook that lets us defer Esc / Close mid-import.
        // We must NOT let the dialog tear down while CommitAsync is still running, because:
        //   (a) the VM's `Result = result;` assignment happens AFTER the tx commits, and
        //       returning before it fires would surface a `null` result to the caller despite
        //       the data being persisted — the tree would never refresh.
        //   (b) the in-flight task would mutate VM properties post-teardown, leading to no-op
        //       UI updates and possibly orphaned background work touching the DB.
        // So: on the first Closing while busy, cancel the import and DEFER the close. When
        // RunImportAsync's finally block flips IsBusy=false and signals the run-completed TCS,
        // we re-invoke Hide() to let the dialog actually close.
        void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs args)
        {
            if (!vm.IsBusy) return;

            // Defer this Close attempt.
            args.Cancel = true;
            vm.RequestCancelForClose();

            // When the in-flight import unwinds, re-request Hide on the UI thread. Using
            // ContinueWith with the captured dispatcher avoids a deadlock if WaitForImportEnd
            // resolves on a thread-pool thread.
            _ = vm.WaitForImportEnd().ContinueWith(_ =>
            {
                if (sender.XamlRoot?.Content?.DispatcherQueue is { } queue)
                {
                    queue.TryEnqueue(() => sender.Hide());
                }
                else
                {
                    sender.Hide();
                }
            }, TaskScheduler.Default);
        }

        vm.PropertyChanged += OnVmPropChanged;
        dialog.Closing += OnClosing;
        try
        {
            await dialog.ShowAsync();
        }
        finally
        {
            vm.PropertyChanged -= OnVmPropChanged;
            dialog.Closing -= OnClosing;
            // Even though ShowAsync awaits the actual close (Closing handlers may have deferred
            // it), guard against a never-completed import (defensive — should never trip).
            await vm.WaitForImportEnd();
            // Transient VM is tracked by the DI root provider; without this Dispose call its
            // CancellationTokenSource leaks until app exit.
            vm.Dispose();
        }

        return vm.Result;
    }

    private static XamlRoot RequireXamlRoot() =>
        App.Current.MainWindow?.Content?.XamlRoot
            ?? throw new InvalidOperationException("No active window to host dialog.");
}
