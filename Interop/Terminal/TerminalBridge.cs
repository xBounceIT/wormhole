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

    // Flow-control watermarks (bytes posted to xterm.js but not yet acked as parsed). xterm parses
    // at only ~5-35 MB/s and silently DISCARDS writes once its internal buffer passes a hard ~50 MB
    // limit — which strands the parser mid-escape-sequence and corrupts the session until a full
    // reset (the "big tcpdump output then everything breaks until CTRL+L" bug). We pause the SSH
    // read pump well before that so the SSH channel window back-pressures the remote producer. The
    // high/low hysteresis avoids pause/resume flapping. 512 KB high keeps xterm's peak buffer to a
    // couple MB even counting in-flight coalesced bytes — two orders of magnitude under the discard
    // limit — while sitting far above interactive echo sizes, so the low-latency echo path never
    // trips it. See https://xtermjs.org/docs/guides/flowcontrol/.
    private const int HighWatermarkBytes = 512 * 1024;
    private const int LowWatermarkBytes = 128 * 1024;

    private readonly CoreWebView2 _webView;
    private readonly ISshSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private readonly IAppSettingsService _settingsService;
    private readonly DispatcherQueue _dispatcher;
    private readonly TerminalOutputCoalescer _coalescer;
    private readonly TerminalFlowController _flowController = new(HighWatermarkBytes, LowWatermarkBytes);
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

        _coalescer = new TerminalOutputCoalescer(PostCoalescedBytes, ArmCoalesceTimer, ArmImmediateFlush);

        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    public void AppendOutput(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        if (!_firstOutputLogged && data.Length > 0)
        {
            _firstOutputLogged = true;
            _logger.LogInformation("First SSH shell output received: {ByteCount} bytes.", data.Length);
        }

        // SSH read pump fires on a background thread. The coalescer posts small prompt /
        // echo-sized chunks on the next dispatcher turn and keeps bursty output behind a
        // short timer, avoiding both the fixed 12 ms echo delay and the old one-marshal-per-
        // SSH-packet flood.
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

    private void ArmImmediateFlush()
    {
        if (!_dispatcher.TryEnqueue(_coalescer.FlushImmediately))
        {
            _logger.LogWarning("Failed to enqueue immediate terminal flush; suspending coalescer (dispatcher unavailable).");
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
        PostDataBytesToWebView(data, "posting SSH output");
        return true;
    }

    private void PostBytesToWebView(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        PostDataBytesToWebView(data, "posting SSH output");
    }

    private void PostFocusToWebView()
    {
        PostStringToWebView("f:", "requesting terminal focus");
    }

    private bool PostStringToWebView(string message, string operation)
    {
        if (_disposed) return false;
        try
        {
            _webView.PostWebMessageAsString(message);
            return true;
        }
        catch (ObjectDisposedException ex)
        {
            _logger.LogDebug(ex, "PostWebMessageAsString raced with WebView disposal while {Operation}.", operation);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            // WebView2 throws this when the CoreWebView2 has been closed.
            _logger.LogWarning(ex, "PostWebMessageAsString rejected while {Operation}.", operation);
            return false;
        }
    }

    private void PostDataBytesToWebView(ReadOnlyMemory<byte> data, string operation)
    {
        if (_disposed || data.Length == 0) return;

        var encodedLength = ((data.Length + 2) / 3) * 4;
        var message = string.Create(encodedLength + 2, data, static (destination, source) =>
        {
            destination[0] = 'd';
            destination[1] = ':';
            if (!Convert.TryToBase64Chars(source.Span, destination[2..], out var written)
                || written != destination.Length - 2)
            {
                throw new FormatException("Failed to encode terminal output for WebView.");
            }
        });
        // Only count bytes that actually reached xterm against the flow-control window: a post that
        // raced WebView teardown is never acked, so counting it would leak the window upward and
        // eventually park the read pump forever. xterm acks every "d:" message (live output AND
        // replay) via its term.write callback, so the accounting stays balanced.
        if (PostStringToWebView(message, operation) && _flowController.OnPosted(data.Length))
        {
            _session.PauseReading();
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

            if (msg.StartsWith("a:", StringComparison.Ordinal))
            {
                // Flow-control ack: xterm finished parsing N output bytes. Decrement the outstanding
                // window; if we'd paused the read pump and it has now drained below the low mark,
                // resume it. Runs on the UI thread (WebView2 is thread-affine) — same thread the
                // posts increment on — so _flowController needs no locking.
                if (long.TryParse(msg.AsSpan(2), out var acked) && _flowController.OnAcked(acked))
                {
                    _session.ResumeReading();
                }
                return;
            }

            if (msg.StartsWith("d:", StringComparison.Ordinal))
            {
                var payload = EncodeUtf8(msg.AsSpan(2));
                await _session.WriteAsync(payload);
            }
            else if (msg.StartsWith("b:", StringComparison.Ordinal))
            {
                // xterm's onBinary path (e.g. legacy mouse reports): payload is raw bytes
                // base64-encoded by JS, NOT UTF-8 text. Decode and forward verbatim.
                var payload = DecodeBase64Bytes(msg.AsSpan(2));
                await _session.WriteAsync(payload);
            }
            else if (msg.StartsWith("r:", StringComparison.Ordinal))
            {
                var size = msg.AsSpan(2);
                var separator = size.IndexOf('x');
                if (separator > 0 &&
                    separator < size.Length - 1 &&
                    uint.TryParse(size[..separator], out var cols) &&
                    uint.TryParse(size[(separator + 1)..], out var rows))
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
                    var text = Encoding.UTF8.GetString(DecodeBase64Bytes(msg.AsSpan(2)));
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

    private static byte[] EncodeUtf8(ReadOnlySpan<char> text)
    {
        var payload = new byte[Encoding.UTF8.GetByteCount(text)];
        Encoding.UTF8.GetBytes(text, payload);
        return payload;
    }

    private static byte[] DecodeBase64Bytes(ReadOnlySpan<char> encoded)
    {
        if (encoded.IsEmpty) return Array.Empty<byte>();

        var decodedLength = GetBase64DecodedLength(encoded);
        if (decodedLength < 0)
        {
            throw new FormatException("Invalid base64 payload from terminal WebView.");
        }

        var buffer = new byte[decodedLength];
        if (!Convert.TryFromBase64Chars(encoded, buffer, out var bytesWritten) ||
            bytesWritten != decodedLength)
        {
            throw new FormatException("Invalid base64 payload from terminal WebView.");
        }

        return buffer;
    }

    private static int GetBase64DecodedLength(ReadOnlySpan<char> encoded)
    {
        if (encoded.Length % 4 != 0) return -1;

        var padding = 0;
        if (encoded[^1] == '=') padding++;
        if (encoded.Length > 1 && encoded[^2] == '=') padding++;

        return (encoded.Length / 4 * 3) - padding;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _webView.WebMessageReceived -= OnWebMessageReceived;
        // Stop pending coalesce ticks first so a late timer doesn't fire concurrently
        // with the final drain below. Already-queued Tick handlers will see
        // _coalescer._disposed==true (set by _coalescer.Dispose() below) and short-circuit.
        _coalesceTimer?.Stop();
        _coalesceTimer = null;
        // Final drain: bytes that arrived in the active ~12ms window haven't been posted
        // yet — without this synchronous flush they're silently dropped when the tab
        // closes immediately after remote output (regression vs. the pre-coalescer
        // one-chunk-per-marshal path that flushed each chunk on arrival). _disposed is
        // still false here so PostCoalescedBytes will actually post to the WebView,
        // which is alive at this point in the teardown (Dispose runs on the UI thread
        // before the WebView2 host is torn down by the view-unload path). Catch any
        // post-time exception so a WebView2 already mid-teardown can't propagate out of
        // Dispose.
        try { _coalescer.Flush(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Final coalescer flush during Dispose failed."); }
        _disposed = true;
        _coalescer.Dispose();
        // If we'd paused the read pump for flow control, release it now. On a view-only detach
        // (background tab) the SSH session keeps running, so a pump left parked on the pause gate
        // would never resume and the session would look frozen on the next reattach. Harmless when
        // the session is also being disposed (ResumeReading is a no-op on a torn-down session).
        if (_flowController.Reset())
        {
            try { _session.ResumeReading(); }
            catch (Exception ex) { _logger.LogDebug(ex, "ResumeReading during bridge Dispose failed."); }
        }
    }
}
