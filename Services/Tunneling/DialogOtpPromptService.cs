using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// WinUI 3 ContentDialog impl of <see cref="IOtpPromptService"/>. The provider that needs an
/// OTP runs on a background thread (TunnelManager.EstablishAsync), so PromptAsync marshals
/// onto the main window's DispatcherQueue before touching XamlRoot.
///
/// WinUI 3 only permits ONE ContentDialog at a time per XamlRoot. Multiple concurrent OTP
/// prompts (two parallel tunnel-establishes triggering 2FA at the same time) would race and
/// the second ShowAsync would throw "Only a single ContentDialog can be open at a time".
/// <see cref="_dialogGate"/> serializes prompts so the second caller waits cleanly behind the
/// first instead of crashing.
/// </summary>
public sealed class DialogOtpPromptService : IOtpPromptService, IDisposable
{
    private readonly SemaphoreSlim _dialogGate = new(1, 1);
    // Cancelled when Dispose() runs. Linked to each caller's token so pending WaitAsync /
    // Release calls observe a clean OperationCanceledException at shutdown rather than the
    // ObjectDisposedException SemaphoreSlim raises when disposed mid-wait.
    private readonly CancellationTokenSource _shutdownCts = new();
    private int _disposed;

    public async Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _disposed) != 0)
            throw new OperationCanceledException("OTP prompt service is shutting down.");

        var window = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window to host OTP prompt.");
        var dispatcher = window.DispatcherQueue
            ?? throw new InvalidOperationException("Main window has no DispatcherQueue.");

        // Combine the caller's token with our shutdown token so app close (which cancels the
        // shutdown CTS before disposing the semaphore) unblocks pending waiters cleanly.
        // CreateLinkedTokenSource accesses _shutdownCts.Token — if Dispose has run between
        // the Volatile.Read above and this line, that read throws ObjectDisposedException.
        // Map to OCE so callers see the documented shutdown semantics instead of ODE.
        CancellationTokenSource linked;
        try
        {
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownCts.Token);
        }
        catch (ObjectDisposedException)
        {
            throw new OperationCanceledException("OTP prompt service was disposed during prompt setup.");
        }
        using var _ = linked;
        var linkedToken = linked.Token;

        // Wait for any in-flight OTP prompt to complete before queuing ours. The semaphore wait
        // honors linkedToken — both caller-cancel and shutdown surface as OCE here, never as
        // ObjectDisposedException. If the gate.Dispose() races ahead of our WaitAsync, the OCE
        // path is taken first because we cancel _shutdownCts BEFORE disposing the semaphore.
        try
        {
            await _dialogGate.WaitAsync(linkedToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            // Belt-and-suspenders: if Dispose somehow ran without cancellation reaching us first,
            // map the ODE to OCE so callers don't have to handle a foreign exception type.
            throw new OperationCanceledException("OTP prompt service was disposed during wait.");
        }

        try
        {
            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    var result = await ShowDialogAsync(window, title, subtitle, linkedToken).ConfigureAwait(true);
                    tcs.TrySetResult(result);
                }
                catch (OperationCanceledException) when (linkedToken.IsCancellationRequested)
                {
                    tcs.TrySetCanceled(linkedToken);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }))
            {
                tcs.TrySetException(new InvalidOperationException("Could not enqueue OTP prompt on UI thread."));
            }
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            // Guard Release in case Dispose disposed the semaphore between our acquire and here.
            try { _dialogGate.Release(); }
            catch (ObjectDisposedException) { /* semaphore disposed during shutdown — accept */ }
        }
    }

    private static async Task<string?> ShowDialogAsync(Window window, string title, string subtitle, CancellationToken ct)
    {
        // Re-check cancellation INSIDE the dispatcher work item. PromptAsync's outer check ran
        // before the enqueue and the token can fire between then and now; without this re-check,
        // ct.Register below would invoke its callback synchronously (since ct is already
        // cancelled), queueing dialog.Hide() ahead of ShowAsync — a race against an unshown
        // dialog whose behavior is undefined in WinUI.
        ct.ThrowIfCancellationRequested();

        var xamlRoot = window.Content?.XamlRoot
            ?? throw new InvalidOperationException("Main window content has no XamlRoot.");

        var subtitleBlock = new TextBlock
        {
            Text = subtitle,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8),
        };
        var inputBox = new TextBox
        {
            PlaceholderText = "Code",
            MaxLength = 32,
            Width = 220,
            // AlphanumericPin (not Digits) keeps both digit and letter keys reachable on
            // touch-only devices (tablet mode, Surface in portable use, kiosk). WatchGuard
            // challenges include alphanumeric codes — printed RSA tokens and SMS short-codes
            // with letters — so a digits-only soft keyboard would lock those users out.
            InputScope = new InputScope { Names = { new InputScopeName(InputScopeNameValue.AlphanumericPin) } },
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
        };
        var panel = new StackPanel { Spacing = 4 };
        if (!string.IsNullOrEmpty(subtitle)) panel.Children.Add(subtitleBlock);
        panel.Children.Add(inputBox);

        var dialog = new ContentDialog
        {
            Title = title,
            Content = panel,
            PrimaryButtonText = "Submit",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = xamlRoot,
            IsPrimaryButtonEnabled = false,
        };

        inputBox.TextChanged += (_, _) =>
            dialog.IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(inputBox.Text);

        // Enter submits when the input has content. Mirrors PromptPasswordAsync's KeyDown +
        // submittedViaEnter pattern — WinUI 3 doesn't bubble Enter from a single-line TextBox
        // to the dialog's default button on its own.
        var submittedViaEnter = false;
        inputBox.KeyDown += (_, args) =>
        {
            if (args.Key == Windows.System.VirtualKey.Enter && !string.IsNullOrWhiteSpace(inputBox.Text))
            {
                args.Handled = true;
                submittedViaEnter = true;
                dialog.Hide();
            }
        };

        dialog.Opened += (_, _) => inputBox.Focus(FocusState.Programmatic);

        // Cancellation registration: re-enqueue Hide() onto the dispatcher because dialog.Hide
        // is UI-thread-only. The registration is disposed before we read the result so a late
        // cancel doesn't fire after the dialog has already closed.
        var dispatcher = window.DispatcherQueue;
        using var ctReg = ct.Register(() =>
        {
            dispatcher.TryEnqueue(() =>
            {
                try { dialog.Hide(); } catch { /* dialog already closed */ }
            });
        });

        // Suppress any connected RDP overlay (a top-level window composited above the WinUI
        // content) for the lifetime of this prompt so it can't occlude the centered dialog —
        // an OTP prompt can fire while a different RDP tab is the active, visible one.
        ContentDialogResult result;
        using (Wormhole.Helpers.RdpOverlayCoordinator.Suppress())
        {
            result = await dialog.ShowAsync();
        }

        // If the user has already submitted (Primary button or Enter), honor that even if the
        // token fired in the same dispatch tick — discarding a successful OTP that the gateway
        // has already consumed leaves the gateway holding a one-shot accept that the user
        // can't reuse. Cancel-after-submit races are rare but the user's input is the source
        // of truth.
        var accepted = result == ContentDialogResult.Primary || submittedViaEnter;
        if (accepted) return inputBox.Text.Trim();
        // Only honor cancellation when the user did NOT submit.
        ct.ThrowIfCancellationRequested();
        return null;
    }

    public void Dispose()
    {
        // Idempotent: a second Dispose() is a no-op. Marks the service as shutting down BEFORE
        // disposing internal state so PromptAsync sees the flag and exits early.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        // Cancel first → pending WaitAsync calls observe OCE via the linked token. THEN
        // dispose. This ordering keeps the shutdown race documented at the top of the class
        // from raising ObjectDisposedException.
        try { _shutdownCts.Cancel(); } catch { /* best effort */ }
        try { _shutdownCts.Dispose(); } catch { /* best effort */ }
        try { _dialogGate.Dispose(); } catch { /* best effort */ }
    }
}
