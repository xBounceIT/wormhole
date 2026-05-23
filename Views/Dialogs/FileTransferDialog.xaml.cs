using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Views.Dialogs;

public sealed partial class FileTransferDialog : UserControl
{
    public FileTransferViewModel? ViewModel { get; private set; }

    /// <summary>Raised when the user clicks the in-content Close button. The hosting
    /// service subscribes and calls <c>ContentDialog.Hide()</c> on the wrapping dialog.</summary>
    public event EventHandler? CloseRequested;

    public FileTransferDialog()
    {
        this.InitializeComponent();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) =>
        CloseRequested?.Invoke(this, EventArgs.Empty);

    public async Task InitializeAsync(FileTransferViewModel vm)
    {
        ViewModel = vm;
        Bindings.Update();

        LocalPaneControl.SetViewModel(vm.LocalPane);
        RemotePaneControl.SetViewModel(vm.RemotePane);

        // Wire drop-handler callbacks: each pane forwards a TransferRequest to the
        // orchestrator.
        LocalPaneControl.OnTransferRequested = HandleTransferAsync;
        RemotePaneControl.OnTransferRequested = HandleTransferAsync;

        await vm.LoadInitialAsync().ConfigureAwait(true);
    }

    private Task HandleTransferAsync(TransferRequest request)
    {
        if (ViewModel is null) return Task.CompletedTask;
        // The conflict resolver is captured as a closure over the dialog so each prompt
        // runs against this XamlRoot. The orchestrator owns the apply-to-all sticky
        // logic — we just answer one prompt at a time.
        return ViewModel.EnqueueAsync(request, PromptConflictAsync, CancellationToken.None);
    }

    // Inline conflict overlay state. The orchestrator's foreach processes one file at a
    // time, so only one prompt is ever in flight; a single TCS is sufficient.
    private TaskCompletionSource<(ConflictDecision, bool)>? _conflictTcs;

    private async Task<(ConflictDecision Decision, bool ApplyToAll)> PromptConflictAsync(ConflictContext ctx, CancellationToken ct)
    {
        // Inline overlay rather than ContentDialog: this UserControl is hosted inside a
        // ContentDialog (FileTransferDialogService) and WinUI 3 forbids two ContentDialogs
        // open simultaneously. Trying to ShowAsync a nested ContentDialog throws
        // COMException "Only a single ContentDialog can be open at any time."
        ConflictMessage.Text = $"\"{ctx.ItemName}\" already exists at the destination.";
        if (ctx.IncomingSize is not null || ctx.ExistingSize is not null)
        {
            ConflictSizes.Text = $"Existing size: {ctx.ExistingSize?.ToString() ?? "?"} bytes — Incoming size: {ctx.IncomingSize?.ToString() ?? "?"} bytes";
            ConflictSizes.Visibility = Visibility.Visible;
        }
        else
        {
            ConflictSizes.Visibility = Visibility.Collapsed;
        }
        ConflictApplyAll.IsChecked = false;

        // Reentrancy guard. The orchestrator's foreach processes one conflict at a time
        // so in normal flow there's never a second invocation while the first is open,
        // but defend anyway: a stranded TCS would deadlock InvokeResolverOnUiAsync's
        // await on tcs.Task.
        _conflictTcs?.TrySetResult((ConflictDecision.Skip, false));
        var tcs = new TaskCompletionSource<(ConflictDecision, bool)>(TaskCreationOptions.RunContinuationsAsynchronously);
        _conflictTcs = tcs;
        ConflictOverlay.Visibility = Visibility.Visible;
        // Focus the accent Skip button so Enter/Escape KeyDown routes through the
        // overlay Grid and a stray Enter on a blank focus state still resolves Skip.
        // FocusState.Pointer (not Programmatic) so ancestor LosingFocus handlers don't
        // intercept — same rationale documented at OnRenameTextBoxLoaded in FilePaneControl.
        _ = DispatcherQueue.TryEnqueue(() => ConflictSkipButton.Focus(FocusState.Pointer));

        // Cancellation (dialog closing / shutdown) defaults to Skip so the batch can
        // unwind cleanly instead of waiting on a TCS that nothing will complete.
        using var ctReg = ct.Register(() => tcs.TrySetResult((ConflictDecision.Skip, false)));
        try
        {
            return await tcs.Task.ConfigureAwait(true);
        }
        finally
        {
            // Identity-check: a reentrant PromptConflictAsync may have already replaced
            // _conflictTcs with a new TCS and made the overlay visible again. Don't
            // collapse the overlay or null the field unless it still refers to OUR tcs.
            if (_conflictTcs == tcs)
            {
                ConflictOverlay.Visibility = Visibility.Collapsed;
                _conflictTcs = null;
            }
        }
    }

    private void OnConflictOverwrite(object sender, RoutedEventArgs e) =>
        _conflictTcs?.TrySetResult((ConflictDecision.Overwrite, ConflictApplyAll.IsChecked == true));

    private void OnConflictSkip(object sender, RoutedEventArgs e) =>
        _conflictTcs?.TrySetResult((ConflictDecision.Skip, ConflictApplyAll.IsChecked == true));

    // Cancel = "abort this prompt without applying the choice to subsequent conflicts."
    // Skip-without-apply-all matches what the user expects: this single file is skipped,
    // and the next conflict still prompts.
    private void OnConflictCancel(object sender, RoutedEventArgs e) =>
        _conflictTcs?.TrySetResult((ConflictDecision.Skip, false));

    // Enter = Skip (the safer default, matching the pre-overlay ContentDialog's
    // DefaultButton=Secondary). Escape = Cancel (Skip without apply-all).
    private void OnConflictKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter)
        {
            e.Handled = true;
            _conflictTcs?.TrySetResult((ConflictDecision.Skip, ConflictApplyAll.IsChecked == true));
        }
        else if (e.Key == Windows.System.VirtualKey.Escape)
        {
            e.Handled = true;
            _conflictTcs?.TrySetResult((ConflictDecision.Skip, false));
        }
    }
}
