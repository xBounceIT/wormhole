using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// WinUI 3 ContentDialog impl of <see cref="ITlsTrustPromptService"/>. Mirrors
/// <see cref="DialogOtpPromptService"/>'s threading and shutdown discipline: the calling provider
/// runs on a background thread, so ConfirmTrustAsync marshals onto the main window's
/// DispatcherQueue, and the app-wide <see cref="ContentDialogGate"/> serializes this prompt
/// against every other mid-connect ContentDialog (OTP, SAML) — WinUI 3 permits only ONE open
/// ContentDialog per XamlRoot, across all services.
///
/// "Cancel" is the default button: declining an unverified certificate must be the path of least
/// resistance — trusting it requires a deliberate click on "Trust and connect".
/// </summary>
public sealed class DialogTlsTrustPromptService : ITlsTrustPromptService, IDisposable
{
    // Cancelled when Dispose() runs. Linked to each caller's token so prompts pending at app
    // shutdown observe a clean OperationCanceledException. Same pattern as
    // DialogOtpPromptService — see the comments there for the full race walkthrough.
    private readonly CancellationTokenSource _shutdownCts = new();
    private int _disposed;

    public async Task<bool> ConfirmTrustAsync(string title, string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _disposed) != 0)
            throw new OperationCanceledException("TLS trust prompt service is shutting down.");

        var window = App.Current.MainWindow
            ?? throw new InvalidOperationException("No active window to host the TLS trust prompt.");
        var dispatcher = window.DispatcherQueue
            ?? throw new InvalidOperationException("Main window has no DispatcherQueue.");

        CancellationTokenSource linked;
        try
        {
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownCts.Token);
        }
        catch (ObjectDisposedException)
        {
            throw new OperationCanceledException("TLS trust prompt service was disposed during prompt setup.");
        }
        using var _ = linked;
        var linkedToken = linked.Token;

        // ContentDialogGate.Shared is never disposed, so this wait can only complete by acquiring
        // the gate or by linkedToken (caller cancel / service shutdown) throwing OCE.
        await ContentDialogGate.Shared.WaitAsync(linkedToken).ConfigureAwait(false);

        try
        {
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!dispatcher.TryEnqueue(async () =>
            {
                try
                {
                    var result = await ShowDialogAsync(window, title, message, linkedToken).ConfigureAwait(true);
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
                tcs.TrySetException(new InvalidOperationException("Could not enqueue the TLS trust prompt on the UI thread."));
            }
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            ContentDialogGate.Shared.Release();
        }
    }

    private static async Task<bool> ShowDialogAsync(Window window, string title, string message, CancellationToken ct)
    {
        // Re-check inside the dispatcher work item — the token can fire between the enqueue and
        // now, and registering a cancel callback on an already-cancelled token would queue Hide()
        // ahead of ShowAsync (undefined behavior against an unshown dialog).
        ct.ThrowIfCancellationRequested();

        var xamlRoot = window.Content?.XamlRoot
            ?? throw new InvalidOperationException("Main window content has no XamlRoot.");

        var messageBlock = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            // Selectable so the user can copy the thumbprint and verify it against the firewall
            // out-of-band before trusting.
            IsTextSelectionEnabled = true,
        };
        var scroller = new ScrollViewer
        {
            Content = messageBlock,
            MaxHeight = 380,
        };

        var dialog = new ContentDialog
        {
            Title = title,
            Content = scroller,
            PrimaryButtonText = ITlsTrustPromptService.AcceptButtonLabel,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = xamlRoot,
        };

        var dispatcher = window.DispatcherQueue;
        using var ctReg = ct.Register(() =>
        {
            dispatcher.TryEnqueue(() =>
            {
                try { dialog.Hide(); } catch { /* dialog already closed */ }
            });
        });

        // Suppress any connected RDP overlay for the lifetime of this prompt so it can't occlude
        // the centered dialog — a tunnel establish can fire while an RDP tab is the visible one.
        ContentDialogResult result;
        using (Wormhole.Helpers.RdpOverlayCoordinator.Suppress())
        {
            result = await dialog.ShowAsync();
        }

        // An explicit "Trust and connect" click wins over a same-tick cancellation — the user's
        // deliberate choice is the source of truth (mirrors the OTP prompt's submit-vs-cancel rule).
        if (result == ContentDialogResult.Primary) return true;
        ct.ThrowIfCancellationRequested();
        return false;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        // Cancel so prompts pending on the shared gate observe OCE via the linked token. The
        // gate itself is shared and process-lived — never disposed here.
        try { _shutdownCts.Cancel(); } catch { /* best effort */ }
        try { _shutdownCts.Dispose(); } catch { /* best effort */ }
    }
}
