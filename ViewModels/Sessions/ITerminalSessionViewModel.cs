using Microsoft.Web.WebView2.Core;
using Wormhole.Services;

namespace Wormhole.ViewModels.Sessions;

public interface ITerminalSessionViewModel
{
    event Action? InitializationRetryRequested;

    void MarkConnecting();
    Task AttachAsync(CoreWebView2 webView, TerminalSize initialSize);
    void DetachView();
    void ReportFailure(string message);
}
