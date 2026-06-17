using System.ComponentModel;
using System.Threading;
using Microsoft.UI.Dispatching;
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

        var xamlRoot = RequireXamlRoot();
        var dialog = new ContentDialog
        {
            Title = isNew ? "New connection" : "Edit connection",
            Content = form,
            PrimaryButtonText = isNew ? "Create" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
            IsPrimaryButtonEnabled = form.IsValid,
        };

        // ContentDialog's default ContentDialogMaxWidth theme resource (~548 px) clips the
        // editor's wider fields (the single Protocol+Host+Port row and the help captions) with
        // no horizontal scrollbar. Lock Min == Max to a wider value so the layout has room and
        // doesn't oscillate as the user types. This path doesn't use ShowFormDialogAsync, so the
        // width is set here directly (mirroring that helper). Clamp to the host so the dialog
        // stays inside a narrow window.
        const double preferredWidth = 640;
        var hostWidth = xamlRoot.Size.Width;
        var targetWidth = hostWidth > 0 ? Math.Min(preferredWidth, hostWidth) : preferredWidth;
        dialog.Resources["ContentDialogMinWidth"] = targetWidth;
        dialog.Resources["ContentDialogMaxWidth"] = targetWidth;

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
        // RdpDomain etc. as inheritance defaults (mRemoteNG import populates them on container
        // nodes; see MRemoteNgImportService.Walk). The folder editor writes only the fields it
        // exposes, so anything else MUST round-trip untouched or descendants that resolve through
        // this folder lose their defaults.
        var output = initial.Clone();
        form.WriteTo(output);
        return output;
    }

    public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
        ShowFormDialogAsync(new CredentialDialog(), initial, "credential");

    public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null) =>
        ShowFormDialogAsync(new TunnelDialog(), initial, "VPN tunnel");

    public async Task ShowTunnelTestAsync(TunnelConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        // Host the test in the shell's modal-overlay layer, NOT a ContentDialog. The Stormshield /
        // WatchGuard establish path opens its own ContentDialog (the OTP / SAML prompt) on the main
        // window's XamlRoot, and WinUI allows only one ContentDialog per XamlRoot — a ContentDialog
        // host here would make that prompt throw "Only a single ContentDialog can be open at any
        // time". The overlay is a plain XAML layer, so the provider prompt opens cleanly over it.
        var mainWindow = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window to host the tunnel test.");

        var control = new TunnelTestDialog();
        var vm = control.ViewModel;

        // Completes when the overlay is actually dismissed, so callers can await this like the old
        // ContentDialog did.
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // Suppress the native RDP surface for the overlay's lifetime so an active RDP tab's
        // top-level window (composited above WinUI content) doesn't paint over the centered card —
        // the old ContentDialog path got this for free via ShowDialogAsync.
        var suppression = RdpOverlayCoordinator.Suppress();
        var torndown = false;

        async void OnCloseRequested()
        {
            // The Close button is only enabled once the run has ended (CanClose == !IsBusy), so this
            // normally fires with the test already finished. Guard defensively: if invoked while a
            // run is somehow still live, cancel it and wait for it to unwind before tearing down so
            // we never leave a diagnostic tunnel running.
            if (torndown) return;
            if (vm.IsBusy)
            {
                vm.RequestCancelForClose();
                await vm.WaitForRunEnd();
            }
            torndown = true;
            control.CloseRequested -= OnCloseRequested;
            mainWindow.HideModalOverlay();
            suppression.Dispose();
            closed.TrySetResult();
        }

        control.CloseRequested += OnCloseRequested;
        mainWindow.ShowModalOverlay(control);
        // Kick the test off. RunAsync never throws — every outcome flows into the bound state — so
        // fire-and-forget is safe. HeaderText is set synchronously at its start, before the first
        // render, so the title shows immediately.
        _ = vm.RunAsync(config);

        try
        {
            await closed.Task;
        }
        finally
        {
            control.CloseRequested -= OnCloseRequested;
            // Guard against a never-completed run (defensive — should never trip).
            await vm.WaitForRunEnd();
            vm.Dispose();
        }
    }

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

    public async Task<string?> PromptPasswordAsync(string title, string message, CancellationToken cancellationToken = default)
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

        var result = await ShowDialogAsync(dialog, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        return accepted ? passwordBox.Password : null;
    }

    public async Task<string?> PromptSecretAsync(
        string title,
        string message,
        string label,
        string primaryText = "OK")
    {
        var passwordBox = new PasswordBox
        {
            Header = label,
            Width = 320,
        };
        var panel = new StackPanel { Spacing = 8 };
        if (!string.IsNullOrWhiteSpace(message))
        {
            panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        }
        panel.Children.Add(passwordBox);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            PrimaryButtonText = primaryText,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = false,
        };

        passwordBox.PasswordChanged += (_, _) =>
            dialog.IsPrimaryButtonEnabled = !string.IsNullOrEmpty(passwordBox.Password);

        var submittedViaEnter = false;
        passwordBox.KeyDown += (_, args) =>
        {
            if (args.Key != Windows.System.VirtualKey.Enter || string.IsNullOrEmpty(passwordBox.Password)) return;
            submittedViaEnter = true;
            dialog.Hide();
            args.Handled = true;
        };

        dialog.Opened += (_, _) => passwordBox.Focus(FocusState.Programmatic);

        var result = await ShowDialogAsync(dialog);
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        return accepted ? passwordBox.Password : null;
    }

    public async Task<(string Secret, string Confirmation)?> PromptNewSecretAsync(
        string title,
        string message,
        string label,
        string primaryText = "Save")
    {
        var firstBox = new PasswordBox
        {
            Header = label,
            Width = 320,
        };
        var confirmBox = new PasswordBox
        {
            Header = "Confirm " + label.ToLowerInvariant(),
            Width = 320,
        };
        var panel = new StackPanel { Spacing = 8 };
        if (!string.IsNullOrWhiteSpace(message))
        {
            panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        }
        panel.Children.Add(firstBox);
        panel.Children.Add(confirmBox);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            PrimaryButtonText = primaryText,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
            IsPrimaryButtonEnabled = false,
        };

        void UpdateEnabled() =>
            dialog.IsPrimaryButtonEnabled =
                !string.IsNullOrEmpty(firstBox.Password) &&
                !string.IsNullOrEmpty(confirmBox.Password);

        firstBox.PasswordChanged += (_, _) => UpdateEnabled();
        confirmBox.PasswordChanged += (_, _) => UpdateEnabled();

        var submittedViaEnter = false;
        confirmBox.KeyDown += (_, args) =>
        {
            if (args.Key != Windows.System.VirtualKey.Enter || !dialog.IsPrimaryButtonEnabled) return;
            submittedViaEnter = true;
            dialog.Hide();
            args.Handled = true;
        };

        dialog.Opened += (_, _) => firstBox.Focus(FocusState.Programmatic);

        var result = await ShowDialogAsync(dialog);
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        return accepted ? (firstBox.Password, confirmBox.Password) : null;
    }

    public async Task<TunnelRouteChoice> PromptTunnelRouteAsync(
        string connectionName,
        string tunnelName,
        CancellationToken cancellationToken = default)
    {
        var dialog = new ContentDialog
        {
            Title = "VPN tunnel",
            Content = new TextBlock
            {
                Text = $"“{connectionName}” is set to connect through the VPN tunnel " +
                       $"“{tunnelName}”.\n\nStart the tunnel and connect through it, or " +
                       "connect directly to the target?",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Use tunnel",
            SecondaryButtonText = "Connect directly",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = RequireXamlRoot(),
        };

        var result = await ShowDialogAsync(dialog, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return result switch
        {
            ContentDialogResult.Primary => TunnelRouteChoice.UseTunnel,
            ContentDialogResult.Secondary => TunnelRouteChoice.Direct,
            _ => TunnelRouteChoice.Cancel,
        };
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

        return ShowDialogAsync(dialog);
    }

    public async Task<(string Username, string Password)?> PromptCredentialsAsync(
        string title,
        string message,
        string? initialUsername = null,
        CancellationToken cancellationToken = default)
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

        var result = await ShowDialogAsync(dialog, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
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

        // Capture the dispatcher on the UI thread NOW, before any deferred-close continuation
        // runs. WaitForImportEnd's continuation fires on the thread pool, and by then
        // sender.XamlRoot may have already been torn down (e.g. window closing during the
        // in-flight import), leaving no safe way to reach back through sender to Hide().
        var dispatcher = dialog.XamlRoot?.Content?.DispatcherQueue;

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
            if (!vm.IsBusy || ContentDialogTracker.IsLockDismissalInProgress) return;

            // Defer this Close attempt.
            args.Cancel = true;
            vm.RequestCancelForClose();

            QueueHideWhenCompleted(vm.WaitForImportEnd(), sender, dispatcher);
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
            if (!vm.IsBusy || ContentDialogTracker.IsLockDismissalInProgress) return;
            args.Cancel = true;
            vm.RequestCancelForClose();
            QueueHideWhenCompleted(vm.WaitForRunEnd(), sender, dispatcher);
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
            if (!vm.IsBusy || ContentDialogTracker.IsLockDismissalInProgress) return;
            args.Cancel = true;
            vm.RequestCancelForClose();
            QueueHideWhenCompleted(vm.WaitForRunEnd(), sender, dispatcher);
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

    // WinUI permits only one ContentDialog per XamlRoot. Queue app-owned dialogs behind the
    // same gate tunnel/auth prompts use so close confirmation attempts wait instead of throwing
    // while another modal is open. Also suppress any connected RDP overlay for the dialog lifetime
    // so dialogs stay visible/usable while an RDP tab is active.
    private static async Task<ContentDialogResult> ShowDialogAsync(
        ContentDialog dialog,
        CancellationToken cancellationToken = default)
    {
        await ContentDialogGate.Shared.WaitAsync(cancellationToken).ConfigureAwait(true);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dispatcher = dialog.XamlRoot?.Content?.DispatcherQueue;
            using var cancellationRegistration = cancellationToken.CanBeCanceled
                ? cancellationToken.Register(() =>
                {
                    dispatcher?.TryEnqueue(() =>
                    {
                        try { dialog.Hide(); } catch { /* dialog already closed */ }
                    });
                })
                : default;
            using (RdpOverlayCoordinator.Suppress())
            {
                return await ContentDialogTracker.ShowAsync(dialog, cancellationToken);
            }
        }
        finally
        {
            ContentDialogGate.Shared.Release();
        }
    }

    private static void QueueHideWhenCompleted(Task task, ContentDialog dialog, DispatcherQueue? dispatcher)
    {
        _ = task.ContinueWith(_ =>
        {
            dispatcher?.TryEnqueue(() => dialog.Hide());
        }, TaskScheduler.Default);
    }

    private static XamlRoot RequireXamlRoot() =>
        App.Current.MainWindow?.Content?.XamlRoot
            ?? throw new InvalidOperationException("No active window to host dialog.");
}
