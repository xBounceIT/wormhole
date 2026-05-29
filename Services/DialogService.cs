using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Models.Backup;
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
        return ShowDialogAsync(dialog);
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
        var result = await ShowDialogAsync(dialog);
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

        var result = await ShowDialogAsync(dialog);
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

        var result = await ShowDialogAsync(dialog);
        if (result != ContentDialogResult.Primary) return null;

        // Produce a fresh node mirroring `initial`'s identity/parent so the caller can update
        // storage without mutating the input. WriteTo only touches editable fields.
        var output = ConnectionNode.CloneIdentityFrom(initial);
        form.WriteTo(output);
        return output;
    }

    public async Task<ConnectionNode?> EditFolderAsync(ConnectionNode initial, bool isNew)
    {
        var form = new FolderEditorDialog();
        await form.LoadAsync(initial);

        var dialog = new ContentDialog
        {
            Title = isNew ? "New folder" : "Edit folder",
            Content = form,
            PrimaryButtonText = isNew ? "Create" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = form.IsValid,
        };

        form.ValidityChanged += (_, _) => dialog.IsPrimaryButtonEnabled = form.IsValid;
        dialog.Opened += (_, _) => form.FocusNameField();

        var result = await ShowDialogAsync(dialog);
        if (result != ContentDialogResult.Primary) return null;

        // Full Clone — not CloneIdentityFrom. Folders can carry Protocol / Host / Username /
        // CredentialId / RdpDomain etc. as inheritance defaults (mRemoteNG import populates
        // them on container nodes; see MRemoteNgImportService.Walk). The folder editor only
        // writes Name + tunnel, so anything else MUST round-trip untouched or descendants
        // that resolve through this folder lose their defaults.
        var output = initial.Clone();
        form.WriteTo(output);
        return output;
    }

    public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
        ShowFormDialogAsync(new CredentialDialog(), initial, "credential");

    public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null) =>
        ShowFormDialogAsync(new TunnelDialog(), initial, "VPN tunnel");

    private static async Task<TDraft?> ShowFormDialogAsync<TForm, TDraft>(TForm form, TDraft? initial, string entityName)
        where TForm : UserControl, IDraftForm<TDraft>
        where TDraft : class
    {
        if (initial is not null) form.LoadDraft(initial);

        var xamlRoot = RequireXamlRoot();
        var dialog = new ContentDialog
        {
            Title = initial is null ? $"New {entityName}" : $"Edit {entityName}",
            Content = form,
            PrimaryButtonText = initial is null ? "Create" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
            IsPrimaryButtonEnabled = form.IsValid,
        };

        // ContentDialog's default ContentDialogMaxWidth theme resource is ~548 px and
        // FullSizeDesired doesn't lift the cap. Forms that need a wider host (e.g. the
        // 2-column tunnel editor) opt in via PreferredDialogMinWidth; Min == Max locks the
        // width so it doesn't oscillate as the user types into wide TextBoxes.
        // Clamp against XamlRoot.Size so the dialog stays inside narrow host windows
        // (mirrors the pattern in FileTransferDialogService.cs:156-162); the > 0 guard
        // protects against a future implementer returning 0 / negative.
        if (form.PreferredDialogMinWidth is { } requestedWidth && requestedWidth > 0)
        {
            var hostWidth = xamlRoot.Size.Width;
            var targetWidth = hostWidth > 0 ? Math.Min(requestedWidth, hostWidth) : requestedWidth;
            dialog.Resources["ContentDialogMinWidth"] = targetWidth;
            dialog.Resources["ContentDialogMaxWidth"] = targetWidth;
        }

        form.ValidityChanged += (_, _) => dialog.IsPrimaryButtonEnabled = form.IsValid;
        dialog.Opened += (_, _) => form.FocusNameField();

        var result = await ShowDialogAsync(dialog);
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

        var result = await ShowDialogAsync(dialog);
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        return accepted ? passwordBox.Password : null;
    }

    public Task ShowCredentialsAsync(string title, string username, string secretLabel, string secret)
    {
        var panel = new StackPanel { Spacing = 8, MinWidth = 320 };

        if (!string.IsNullOrEmpty(username))
        {
            panel.Children.Add(new TextBox
            {
                Header = "Username",
                Text = username,
                IsReadOnly = true,
                IsSpellCheckEnabled = false,
            });
        }

        // Read-only TextBox (not a PasswordBox) because the whole point is to reveal the
        // secret in plaintext; selectable so the user can also copy manually. The header
        // distinguishes a login password from an SSH key passphrase.
        var secretField = new TextBox
        {
            Header = secretLabel,
            Text = secret,
            IsReadOnly = true,
            IsSpellCheckEnabled = false,
        };
        panel.Children.Add(secretField);

        var copyButton = new Button { Content = "Copy" };
        copyButton.Click += (_, _) => ClipboardHelper.CopyText(secret);
        panel.Children.Add(copyButton);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            CloseButtonText = "Close",
            XamlRoot = RequireXamlRoot(),
        };

        return dialog.ShowAsync().AsTask();
    }

    public async Task<(string Username, string Password)?> PromptCredentialsAsync(string title, string message, string? initialUsername = null)
    {
        var userBox = new TextBox
        {
            Header = "Username",
            PlaceholderText = "user or DOMAIN\\user",
            Text = initialUsername ?? string.Empty,
            Width = 320,
        };
        var passwordBox = new PasswordBox
        {
            Header = "Password",
            PlaceholderText = "Password",
            Width = 320,
        };
        var panel = new StackPanel { Spacing = 8 };
        if (!string.IsNullOrEmpty(message))
        {
            panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        }
        panel.Children.Add(userBox);
        panel.Children.Add(passwordBox);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            PrimaryButtonText = "Connect",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(userBox.Text),
        };

        // Both fields required. The password field is allowed to be blank (some servers
        // accept empty passwords / passwordless accounts), but a blank username with no
        // profile-side fallback is exactly the case this dialog exists to fix — keep
        // Connect disabled until the user types something.
        userBox.TextChanged += (_, _) =>
            dialog.IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(userBox.Text);

        var submittedViaEnter = false;
        userBox.KeyDown += (_, args) =>
        {
            // Enter in the username field advances to the password field rather than
            // submitting — submitting here would hand the OCX a blank password the user
            // never had a chance to type.
            if (args.Key != Windows.System.VirtualKey.Enter) return;
            if (string.IsNullOrWhiteSpace(userBox.Text)) return;
            passwordBox.Focus(FocusState.Programmatic);
            args.Handled = true;
        };
        passwordBox.KeyDown += (_, args) =>
        {
            if (args.Key != Windows.System.VirtualKey.Enter) return;
            if (string.IsNullOrWhiteSpace(userBox.Text)) return;
            submittedViaEnter = true;
            dialog.Hide();
            args.Handled = true;
        };

        dialog.Opened += (_, _) =>
        {
            // Focus the empty field first — username if blank, otherwise password — so the
            // user lands on the field that actually needs input.
            if (string.IsNullOrWhiteSpace(userBox.Text))
                userBox.Focus(FocusState.Programmatic);
            else
                passwordBox.Focus(FocusState.Programmatic);
        };

        var result = await ShowDialogAsync(dialog);
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        if (!accepted) return null;
        var username = userBox.Text.Trim();
        if (string.IsNullOrEmpty(username)) return null;
        return (username, passwordBox.Password);
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
            await ShowDialogAsync(dialog);
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

    public async Task<BackupExportResult?> PromptForBackupExportAsync()
    {
        var control = new BackupExportDialog();
        var vm = control.ViewModel;

        var dialog = new ContentDialog
        {
            Title = "Export backup",
            Content = control,
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

        // Capture the dispatcher on the UI thread NOW, before any deferred-close continuation
        // runs. WaitForRunEnd's continuation fires on the thread pool, and by then
        // sender.XamlRoot may have already been torn down (e.g. window closing during the
        // in-flight export), leaving the original null-conditional access falling through to
        // a bare sender.Hide() called from a worker thread — which throws RPC_E_WRONG_THREAD.
        var dispatcher = dialog.XamlRoot?.Content?.DispatcherQueue;

        // Mirror the mRemoteNG dialog's Closing-defer: Esc/Close during an in-flight export
        // cancels first, then re-issues Hide once the run finishes so Result has been set.
        void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs args)
        {
            if (!vm.IsBusy) return;
            args.Cancel = true;
            vm.RequestCancelForClose();
            _ = vm.WaitForRunEnd().ContinueWith(_ =>
            {
                if (dispatcher is not null)
                {
                    dispatcher.TryEnqueue(() => sender.Hide());
                }
                // If we never captured a dispatcher (extremely unlikely; would mean the dialog
                // was shown without a XamlRoot), there's no safe way to call Hide from this
                // thread. The dialog is already in the "deferred close" state, so the user's
                // next Close click will just close it normally.
            }, TaskScheduler.Default);
        }

        vm.PropertyChanged += OnVmPropChanged;
        dialog.Closing += OnClosing;
        try
        {
            await ShowDialogAsync(dialog);
        }
        finally
        {
            vm.PropertyChanged -= OnVmPropChanged;
            dialog.Closing -= OnClosing;
            await vm.WaitForRunEnd();
            vm.Dispose();
        }
        return vm.Result;
    }

    public async Task<BackupImportResult?> PromptForBackupImportAsync()
    {
        var control = new BackupImportDialog();
        var vm = control.ViewModel;

        var dialog = new ContentDialog
        {
            Title = "Import backup",
            Content = control,
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

        // See PromptForBackupExportAsync for why we capture the dispatcher up-front.
        var dispatcher = dialog.XamlRoot?.Content?.DispatcherQueue;

        void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs args)
        {
            if (!vm.IsBusy) return;
            args.Cancel = true;
            vm.RequestCancelForClose();
            _ = vm.WaitForRunEnd().ContinueWith(_ =>
            {
                if (dispatcher is not null)
                {
                    dispatcher.TryEnqueue(() => sender.Hide());
                }
            }, TaskScheduler.Default);
        }

        vm.PropertyChanged += OnVmPropChanged;
        dialog.Closing += OnClosing;
        try
        {
            await ShowDialogAsync(dialog);
        }
        finally
        {
            vm.PropertyChanged -= OnVmPropChanged;
            dialog.Closing -= OnClosing;
            await vm.WaitForRunEnd();
            vm.Dispose();
        }
        return vm.Result;
    }

    // Every ContentDialog renders centered over the active window's XamlRoot, where an owned
    // RDP overlay (a top-level window composited above the WinUI content) would occlude it.
    // Suppress the overlay for the lifetime of the dialog so dialogs stay visible/usable while
    // an RDP tab is active.
    private static async Task<ContentDialogResult> ShowDialogAsync(ContentDialog dialog)
    {
        using (RdpOverlayCoordinator.Suppress())
        {
            return await dialog.ShowAsync();
        }
    }

    private static XamlRoot RequireXamlRoot() =>
        App.Current.MainWindow?.Content?.XamlRoot
            ?? throw new InvalidOperationException("No active window to host dialog.");
}
