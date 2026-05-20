using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;
using Wormhole.Services;

namespace Wormhole.Interop.Terminal;

public sealed class TerminalBridge : IDisposable
{
    private readonly CoreWebView2 _webView;
    private readonly ISshSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private bool _disposed;

    public TerminalBridge(CoreWebView2 webView, ISshSession session, ILogger<TerminalBridge> logger)
    {
        _webView = webView;
        _session = session;
        _logger = logger;

        _session.DataReceived += OnDataReceived;
        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    private void OnDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        // TODO: throttle/coalesce writes to avoid postMessage backpressure on bursts.
        if (_disposed) return;
        try
        {
            var encoded = Convert.ToBase64String(data.Span);
            _webView.PostWebMessageAsString("d:" + encoded);
        }
        catch (ObjectDisposedException) { /* raced with Dispose */ }
        catch (InvalidOperationException ex)
        {
            // WebView2 throws this when the CoreWebView2 has been closed.
            _logger.LogDebug(ex, "PostWebMessageAsString rejected after WebView shutdown.");
        }
    }

    private async void OnWebMessageReceived(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        // WebView2 raises this through an event, so the handler must be async void.
        // Catch everything so a single bad message can't tear down the process.
        try
        {
            var msg = args.TryGetWebMessageAsString();
            if (string.IsNullOrEmpty(msg)) return;

            if (msg.StartsWith("d:", StringComparison.Ordinal))
            {
                var payload = Encoding.UTF8.GetBytes(msg.AsSpan(2).ToString());
                await _session.WriteAsync(payload);
            }
            else if (msg.StartsWith("r:", StringComparison.Ordinal))
            {
                var parts = msg.AsSpan(2).ToString().Split('x');
                if (parts.Length == 2 &&
                    uint.TryParse(parts[0], out var cols) &&
                    uint.TryParse(parts[1], out var rows))
                {
                    await _session.ResizeAsync(cols, rows);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TerminalBridge: failed to handle a WebView2 message.");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.DataReceived -= OnDataReceived;
        _webView.WebMessageReceived -= OnWebMessageReceived;
    }
}
