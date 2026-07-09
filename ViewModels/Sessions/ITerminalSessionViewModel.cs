using Microsoft.Web.WebView2.Core;
using Wormhole.Services;

namespace Wormhole.ViewModels.Sessions;

public interface ITerminalSessionViewModel
{
    event Action? InitializationRetryRequested;

    void MarkConnecting();
    Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize);

    /// <summary>
    /// Releases the current WebView bridge without tearing down the protocol session.
    /// </summary>
    /// <param name="preserveTerminalContents">
    /// Whether the current xterm page will remain available for this session's next attachment.
    /// Pass <see langword="false"/> when the view will navigate that page for another session.
    /// </param>
    void DetachView(bool preserveTerminalContents = true);
    void ReportFailure(string message);
}
