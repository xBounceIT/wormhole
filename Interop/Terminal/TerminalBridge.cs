using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.Web.WebView2.Core;
using Wormhole.Services;

namespace Wormhole.Interop.Terminal;

public sealed class TerminalBridge : IDisposable
{
    private const uint MinimumUsableColumns = 20;
    private const uint MinimumUsableRows = 8;

    private readonly CoreWebView2 _webView;
    private readonly ISshSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private readonly DispatcherQueue _dispatcher;
    private bool _disposed;
    private bool _firstOutputLogged;
    private uint _lastColumns;
    private uint _lastRows;

    public TerminalBridge(CoreWebView2 webView, ISshSession session, ILogger<TerminalBridge> logger)
    {
        _webView = webView;
        _session = session;
        _logger = logger;
        // WebView2 is thread-affine to its creator. Capture the dispatcher at construction
        // (always called from the UI thread via SshTerminalView.OnReadyMessage) so we can
        // marshal SSH-pump callbacks back to the UI thread before touching the WebView.
        _dispatcher = DispatcherQueue.GetForCurrentThread()
            ?? throw new InvalidOperationException(
                "TerminalBridge must be constructed on a thread with a DispatcherQueue (the UI thread).");

        _session.DataReceived += OnDataReceived;
        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    private void OnDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        // TODO: throttle/coalesce writes to avoid postMessage backpressure on bursts.
        if (_disposed) return;
        if (!_firstOutputLogged && data.Length > 0)
        {
            _firstOutputLogged = true;
            _logger.LogInformation("First SSH shell output received: {ByteCount} bytes.", data.Length);
        }

        // SSH read pump fires on a background thread; marshal to the UI thread before
        // calling any WebView2 method (they're thread-affine to the creator thread).
        var snapshot = data;
        if (!_dispatcher.TryEnqueue(() => PostBytesToWebView(snapshot)))
        {
            _logger.LogWarning("Failed to enqueue SSH output for WebView posting.");
        }
    }

    public void RequestFocus()
    {
        if (_disposed) return;
        if (!_dispatcher.TryEnqueue(PostFocusToWebView))
        {
            _logger.LogWarning("Failed to enqueue terminal focus request.");
        }
    }

    private void PostBytesToWebView(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        try
        {
            var encoded = Convert.ToBase64String(data.Span);
            _webView.PostWebMessageAsString("d:" + encoded);
        }
        catch (ObjectDisposedException ex)
        {
            _logger.LogDebug(ex, "PostWebMessageAsString raced with WebView disposal.");
        }
        catch (InvalidOperationException ex)
        {
            // WebView2 throws this when the CoreWebView2 has been closed.
            _logger.LogWarning(ex, "PostWebMessageAsString rejected while posting SSH output.");
        }
    }

    private void PostFocusToWebView()
    {
        if (_disposed) return;
        try
        {
            _webView.PostWebMessageAsString("f:");
        }
        catch (ObjectDisposedException ex)
        {
            _logger.LogDebug(ex, "Terminal focus request raced with WebView disposal.");
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "PostWebMessageAsString rejected while requesting terminal focus.");
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
            else if (msg.StartsWith("b:", StringComparison.Ordinal))
            {
                // xterm's onBinary path (e.g. legacy mouse reports): payload is raw bytes
                // base64-encoded by JS, NOT UTF-8 text. Decode and forward verbatim.
                var payload = Convert.FromBase64String(msg.Substring(2));
                await _session.WriteAsync(payload);
            }
            else if (msg.StartsWith("r:", StringComparison.Ordinal))
            {
                var parts = msg.AsSpan(2).ToString().Split('x');
                if (parts.Length == 2 &&
                    uint.TryParse(parts[0], out var cols) &&
                    uint.TryParse(parts[1], out var rows))
                {
                    if (cols < MinimumUsableColumns || rows < MinimumUsableRows)
                    {
                        _logger.LogInformation(
                            "Ignoring collapsed terminal resize request: {Columns}x{Rows}.",
                            cols,
                            rows);
                        return;
                    }

                    if (cols != _lastColumns || rows != _lastRows)
                    {
                        _lastColumns = cols;
                        _lastRows = rows;
                        _logger.LogInformation("Terminal resize requested: {Columns}x{Rows}.", cols, rows);
                    }
                    await _session.ResizeAsync(cols, rows);
                }
            }
            else if (msg.StartsWith("z:collapsed-fit:", StringComparison.Ordinal))
            {
                _logger.LogInformation("Terminal ignored collapsed fit measurement: {Measurement}.", msg.Substring("z:collapsed-fit:".Length));
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
