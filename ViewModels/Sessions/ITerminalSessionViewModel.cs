using Microsoft.Web.WebView2.Core;
using Wormhole.Services;

namespace Wormhole.ViewModels.Sessions;

public readonly record struct TerminalRendererRecoveryLease(int LifecycleGeneration);

public interface ITerminalSessionViewModel
{
    event Action? InitializationRetryRequested;
    event Action? TerminalRendererRecoveryRequested;

    void MarkConnecting();
    void UpdateTerminalSize(TerminalSize size);
    Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize);
    TerminalRendererRecoveryLease CaptureTerminalRendererRecoveryLease();

    /// <summary>
    /// Handles a renderer failure only when no page is registered yet or the supplied identity is
    /// the currently registered page.
    /// </summary>
    /// <returns>
    /// A lifecycle lease when accepted; <see langword="null"/> when another page owns the session.
    /// </returns>
    Task<TerminalRendererRecoveryLease?> TryHandleTerminalRendererFailureAsync(
        object? rendererIdentity,
        string message);
    bool IsTerminalRendererRecoveryCurrent(TerminalRendererRecoveryLease lease);
    bool OwnsTerminalRenderer(object? rendererIdentity);
    bool TryTakeTerminalRendererRecoveryRequest(object? rendererIdentity, out string message);

    /// <summary>
    /// Releases the current WebView bridge without tearing down the protocol session.
    /// </summary>
    /// <param name="preserveTerminalContents">
    /// Whether the current xterm page will remain available for this session's next attachment.
    /// Pass <see langword="false"/> when the view will navigate that page for another session.
    /// </param>
    void DetachView(bool preserveTerminalContents = true);

    /// <summary>
    /// Releases the bridge only when <paramref name="rendererIdentity"/> is still the renderer
    /// registered by this view. A stale Unloaded callback must not detach its replacement.
    /// </summary>
    void DetachView(object? rendererIdentity, bool preserveTerminalContents = true);

    /// <summary>
    /// Detaches immediately, then waits until the retiring page has parsed its accepted prefix and
    /// delivered every correlated parser reply. A recycled WebView must await this before navigation.
    /// </summary>
    Task DetachViewAsync(
        object? rendererIdentity,
        bool preserveTerminalContents = true);

    void ReportFailure(string message);
}
