using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.Web.WebView2.Core;
using Windows.ApplicationModel.DataTransfer;
using Wormhole.Services;

namespace Wormhole.Interop.Terminal;

public sealed class TerminalBridge : IDisposable
{
    private const uint MinimumUsableColumns = 20;
    private const uint MinimumUsableRows = 8;
    // Window chosen to be small enough that interactive output (keystroke echo,
    // single-line prompts) still feels instant, while large enough that a bursty
    // remote (e.g. cat large_file) collapses many SSH packets per ~frame into one
    // WebView2 PostWebMessageAsString. ~12 ms ≈ 80 fps cap on terminal updates.
    private const int CoalesceWindowMs = 12;

    private readonly CoreWebView2 _webView;
    private readonly ISshSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private readonly IAppSettingsService _settingsService;
    private readonly DispatcherQueue _dispatcher;
    private readonly TerminalOutputCoalescer _coalescer;
    private DispatcherQueueTimer? _coalesceTimer;
    private bool _disposed;
    private bool _firstOutputLogged;
    private uint _lastColumns;
    private uint _lastRows;

    public TerminalBridge(
        CoreWebView2 webView,
        ISshSession session,
        ILogger<TerminalBridge> logger,
        IAppSettingsService settingsService)
    {
        _webView = webView;
        _session = session;
        _logger = logger;
        _settingsService = settingsService;
        // WebView2 is thread-affine to its creator. Capture the dispatcher at construction
        // (always called from the UI thread via SshTerminalView.OnReadyMessage) so we can
        // marshal SSH-pump callbacks back to the UI thread before touching the WebView.
        _dispatcher = DispatcherQueue.GetForCurrentThread()
            ?? throw new InvalidOperationException(
                "TerminalBridge must be constructed on a thread with a DispatcherQueue (the UI thread).");

        _coalescer = new TerminalOutputCoalescer(PostCoalescedBytes, ArmCoalesceTimer);

        _session.DataReceived += OnDataReceived;
        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    private void OnDataReceived(object? sender, ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        if (!_firstOutputLogged && data.Length > 0)
        {
            _firstOutputLogged = true;
            _logger.LogInformation("First SSH shell output received: {ByteCount} bytes.", data.Length);
        }

        // SSH read pump fires on a background thread. The coalescer buffers bytes here
        // and arms a one-shot dispatcher timer (one trip to the UI thread per ~12 ms
        // window) instead of one DispatcherQueue.TryEnqueue per chunk — see comment on
        // CoalesceWindowMs above.
        _coalescer.Append(data.Span);
    }

    /// <summary>
    /// Returns true if bytes are sitting in the coalescer waiting for the next tick.
    /// Exposed for tests; production code drives this through <see cref="OnDataReceived"/>.
    /// </summary>
    internal bool HasPendingCoalescedBytes => _coalescer.HasPending;

    public void RequestFocus()
    {
        if (_disposed) return;
        if (!_dispatcher.TryEnqueue(PostFocusToWebView))
        {
            _logger.LogWarning("Failed to enqueue terminal focus request.");
        }
    }

    /// <summary>
    /// Posts a captured run of SSH output bytes to xterm.js using the same protocol
    /// as live output. Used to repaint a freshly-recreated xterm.js with prior
    /// scrollback after a view detach/reattach, since an idle shell won't send
    /// anything new to render against.
    /// </summary>
    public void Replay(ReadOnlyMemory<byte> data)
    {
        if (_disposed || data.Length == 0) return;
        if (!_dispatcher.TryEnqueue(() => PostBytesToWebView(data)))
        {
            _logger.LogWarning("Failed to enqueue terminal replay.");
        }
    }

    private void ArmCoalesceTimer()
    {
        // Called by the coalescer on the SSH read-pump thread on the empty → buffered
        // transition. We must create / start the DispatcherQueueTimer on the dispatcher
        // thread; route through TryEnqueue. Subsequent appends within the window will
        // see _timerArmed=true in the coalescer and skip re-arming.
        if (!_dispatcher.TryEnqueue(StartCoalesceTimer))
        {
            // TryEnqueue only returns false during dispatcher shutdown (window closing /
            // app exit) — a one-way state per the Microsoft.UI.Dispatching docs. Do NOT
            // call _coalescer.Flush() inline here: Flush invokes the post delegate, which
            // touches the thread-affine WebView2, and calling it from the SSH pump thread
            // would throw RPC_E_WRONG_THREAD and possibly corrupt WebView2 state.
            //
            // We must Suspend the coalescer rather than just log: without it, _timerArmed
            // stays true and the buffered bytes are stuck (subsequent Appends skip the
            // arm callback because they see _timerArmed=true, so the buffer grows without
            // bound until disposal). Suspend drops the pending bytes and short-circuits
            // future Appends so the SSH pump stops accumulating output for a dispatcher
            // that will never accept it.
            _logger.LogWarning("Failed to enqueue coalesce-timer arm; suspending coalescer (dispatcher unavailable).");
            _coalescer.Suspend();
        }
    }

    private void StartCoalesceTimer()
    {
        if (_disposed) return;
        if (_coalesceTimer is null)
        {
            _coalesceTimer = _dispatcher.CreateTimer();
            _coalesceTimer.Interval = TimeSpan.FromMilliseconds(CoalesceWindowMs);
            _coalesceTimer.IsRepeating = false;
            _coalesceTimer.Tick += (_, _) => _coalescer.Flush();
        }
        _coalesceTimer.Stop();
        _coalesceTimer.Start();
    }

    private bool PostCoalescedBytes(ReadOnlyMemory<byte> data)
    {
        // Coalescer invokes us on the UI thread via the dispatcher timer tick.
        if (_disposed || data.Length == 0) return false;
        PostStringToWebView("d:" + Convert.ToBase64String(data.Span), "posting SSH output");
        return true;
    }

    private void PostBytesToWebView(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        PostStringToWebView("d:" + Convert.ToBase64String(data.Span), "posting SSH output");
    }

    private void PostFocusToWebView()
    {
        PostStringToWebView("f:", "requesting terminal focus");
    }

    private void PostStringToWebView(string message, string operation)
    {
        if (_disposed) return;
        try
        {
            _webView.PostWebMessageAsString(message);
        }
        catch (ObjectDisposedException ex)
        {
            _logger.LogDebug(ex, "PostWebMessageAsString raced with WebView disposal while {Operation}.", operation);
        }
        catch (InvalidOperationException ex)
        {
            // WebView2 throws this when the CoreWebView2 has been closed.
            _logger.LogWarning(ex, "PostWebMessageAsString rejected while {Operation}.", operation);
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
            else if (msg.StartsWith("c:", StringComparison.Ordinal))
            {
                // Read the toggle fresh every time so flipping it in Settings takes effect
                // immediately without pushing config to JS.
                if (!_settingsService.Current.AutoCopyOnSelect) return;
                try
                {
                    var text = Encoding.UTF8.GetString(Convert.FromBase64String(msg.Substring(2)));
                    if (string.IsNullOrEmpty(text)) return;
                    var pkg = new DataPackage();
                    pkg.SetText(text);
                    // WebMessageReceived fires on the UI thread (WebView2 is thread-affine
                    // to its creator), so Clipboard.SetContent is safe to call directly.
                    Clipboard.SetContent(pkg);
                    // Flush so the data survives the source app closing — otherwise the
                    // DataPackage is invalidated when Wormhole exits and the user can't
                    // paste the just-copied selection anywhere.
                    Clipboard.Flush();
                }
                catch (Exception ex)
                {
                    // Clipboard.SetContent can throw COMException when another app holds
                    // the clipboard. Never let that tear down the SSH session.
                    _logger.LogWarning(ex, "TerminalBridge: failed to copy selection to clipboard.");
                }
            }
            else if (msg.StartsWith("p:", StringComparison.Ordinal))
            {
                try
                {
                    var view = Clipboard.GetContent();
                    if (view is null || !view.Contains(StandardDataFormats.Text)) return;
                    var text = await view.GetTextAsync();
                    if (string.IsNullOrEmpty(text)) return;
                    var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
                    // Echo back to JS so xterm.js applies bracketed-paste mode and CRLF
                    // normalization, rather than writing raw bytes straight to the shell.
                    PostStringToWebView("paste:" + encoded, "replying with paste");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TerminalBridge: failed to read clipboard for paste.");
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
        // Stop pending coalesce ticks first so a late timer doesn't fire after the
        // WebView has been torn down. The coalescer itself is then drained of any
        // residual bytes (which the timer would have flushed).
        _coalesceTimer?.Stop();
        _coalesceTimer = null;
        _coalescer.Dispose();
    }
}
