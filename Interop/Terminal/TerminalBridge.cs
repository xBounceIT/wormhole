using System.Globalization;
using System.Runtime.InteropServices;
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
    private const int SharedBufferThresholdBytes = 2 * 1024;
    private const int MaxSharedBufferChunkBytes = 128 * 1024;
    private static readonly TimeSpan PendingSharedBufferDisposeDelay = TimeSpan.FromSeconds(2);

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
    private readonly ITerminalSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private readonly IAppSettingsService _settingsService;
    private readonly DispatcherQueue _dispatcher;
    private readonly TerminalOutputCoalescer _coalescer;
    private readonly TerminalInputWriter _inputWriter;
    private readonly TerminalFlowController _flowController = new(HighWatermarkBytes, LowWatermarkBytes);
    private readonly Dictionary<long, CoreWebView2SharedBuffer> _pendingSharedBuffers = new();
    private DispatcherQueueTimer? _coalesceTimer;
    private long _nextSharedBufferId;
    private bool _sharedBufferOutputDisabled;
    private bool _sharedBufferFallbackLogged;
    private bool _forceBase64Output;
    private bool _disposed;
    private bool _firstOutputLogged;
    private uint _lastColumns;
    private uint _lastRows;

    public TerminalBridge(
        CoreWebView2 webView,
        ITerminalSession session,
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
        _inputWriter = new TerminalInputWriter(
            payload => _session.WriteAsync(payload),
            ex => LogSessionOperationAfterClose(ex, "writing terminal input"));

        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    public void AppendOutput(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        if (!_firstOutputLogged && data.Length > 0)
        {
            _firstOutputLogged = true;
            _logger.LogInformation("First terminal output received: {ByteCount} bytes.", data.Length);
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
    /// Posts captured SSH output bytes to xterm.js using the same protocol as live
    /// output. Used to repaint a freshly-recreated xterm.js, or to replay bytes that
    /// arrived while no bridge was attached during a same-WebView reattach.
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
        PostDataBytesToWebView(data, "posting terminal output");
        return true;
    }

    private void PostBytesToWebView(ReadOnlyMemory<byte> data)
    {
        if (_disposed) return;
        PostDataBytesToWebView(data, "posting terminal output");
    }

    private void PostFocusToWebView()
    {
        PostStringToWebView("f:", "requesting terminal focus/repaint");
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

        if (!_forceBase64Output &&
            !_sharedBufferOutputDisabled &&
            data.Length >= SharedBufferThresholdBytes)
        {
            var offset = 0;
            while (offset < data.Length)
            {
                var chunkLength = Math.Min(MaxSharedBufferChunkBytes, data.Length - offset);
                var chunk = data.Slice(offset, chunkLength);
                if (TryPostSharedBufferToWebView(chunk, operation))
                {
                    offset += chunkLength;
                    continue;
                }

                PostBase64DataBytesToWebView(data.Slice(offset), operation);
                return;
            }

            return;
        }

        PostBase64DataBytesToWebView(data, operation);
    }

    private bool TryPostSharedBufferToWebView(ReadOnlyMemory<byte> data, string operation)
    {
        CoreWebView2SharedBuffer? sharedBuffer = null;
        long id = 0;
        try
        {
            sharedBuffer = _webView.Environment.CreateSharedBuffer((ulong)data.Length);
            CopyToSharedBuffer(sharedBuffer, data.Span);

            id = ++_nextSharedBufferId;
            _pendingSharedBuffers.Add(id, sharedBuffer);
            _webView.PostSharedBufferToScript(
                sharedBuffer,
                CoreWebView2SharedBufferAccess.ReadOnly,
                BuildSharedBufferMetadata(id, data.Length));
            if (_flowController.OnPosted(data.Length))
            {
                _session.PauseReading();
            }
            return true;
        }
        catch (Exception ex)
        {
            if (id != 0)
            {
                _pendingSharedBuffers.Remove(id);
            }
            DisposeSharedBuffer(sharedBuffer);
            DisableSharedBufferOutput(ex, operation);
            return false;
        }
    }

    private void PostBase64DataBytesToWebView(ReadOnlyMemory<byte> data, string operation)
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

    private static string BuildSharedBufferMetadata(long id, int byteCount) =>
        "{\"kind\":\"terminal-output\",\"id\":" +
        id.ToString(CultureInfo.InvariantCulture) +
        ",\"length\":" +
        byteCount.ToString(CultureInfo.InvariantCulture) +
        "}";

    private void DisableSharedBufferOutput(Exception ex, string operation)
    {
        _sharedBufferOutputDisabled = true;
        if (_sharedBufferFallbackLogged || _disposed) return;
        _sharedBufferFallbackLogged = true;
        _logger.LogWarning(
            ex,
            "WebView2 shared-buffer terminal output failed while {Operation}; falling back to base64 messages for this bridge.",
            operation);
    }

    private void ReleaseSharedBuffer(long id)
    {
        if (!_pendingSharedBuffers.Remove(id, out var sharedBuffer)) return;
        DisposeSharedBuffer(sharedBuffer);
    }

    private static void DisposeSharedBuffer(CoreWebView2SharedBuffer? sharedBuffer)
    {
        if (sharedBuffer is null) return;
        try { sharedBuffer.Dispose(); }
        catch { /* best effort */ }
    }

    private static unsafe void CopyToSharedBuffer(CoreWebView2SharedBuffer sharedBuffer, ReadOnlySpan<byte> data)
    {
        using var reference = sharedBuffer.Buffer;
        ((IMemoryBufferByteAccess)reference).GetBuffer(out var destination, out var capacity);
        if (capacity < data.Length)
        {
            throw new InvalidOperationException("WebView2 shared buffer is smaller than the terminal output batch.");
        }
        data.CopyTo(new Span<byte>(destination, data.Length));
    }

    [ComImport]
    [Guid("5B0D3235-4DBA-4D44-865E-8F1D0E4FD04D")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private unsafe interface IMemoryBufferByteAccess
    {
        void GetBuffer(out byte* buffer, out uint capacity);
    }

    private void SchedulePendingSharedBufferDisposal()
    {
        if (_pendingSharedBuffers.Count == 0) return;
        var pending = _pendingSharedBuffers.Values.ToArray();
        _pendingSharedBuffers.Clear();

        _ = Task.Run(async () =>
        {
            await Task.Delay(PendingSharedBufferDisposeDelay).ConfigureAwait(false);
            foreach (var sharedBuffer in pending)
            {
                DisposeSharedBuffer(sharedBuffer);
            }
        });
    }

    private async void OnWebMessageReceived(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        // WebView2 raises this through an event, so the handler must be async void.
        // Catch everything so a single bad message can't tear down the process.
        try
        {
            var msg = args.TryGetWebMessageAsString();
            if (string.IsNullOrEmpty(msg)) return;

            if (TerminalBridgeMessages.TryParseOutputAck(msg.AsSpan(), out var acked, out var sharedBufferId))
            {
                // Flow-control ack: xterm finished parsing N output bytes. Decrement the outstanding
                // window; if we'd paused the read pump and it has now drained below the low mark,
                // resume it. Runs on the UI thread (WebView2 is thread-affine) — same thread the
                // posts increment on — so _flowController needs no locking.
                if (sharedBufferId is long id)
                {
                    ReleaseSharedBuffer(id);
                }
                if (_flowController.OnAcked(acked))
                {
                    _session.ResumeReading();
                }
                return;
            }

            if (msg.StartsWith("d:", StringComparison.Ordinal))
            {
                var payload = TerminalBridgeMessages.EncodeUtf8(msg.AsSpan(2));
                _inputWriter.Enqueue(payload);
            }
            else if (msg.StartsWith("b:", StringComparison.Ordinal))
            {
                // xterm input is base64-encoded raw bytes by JS, not embedded directly
                // in the WebView string. This keeps control keys (Ctrl+O, Enter, Ctrl+L)
                // and legacy mouse reports out of the message framing layer.
                var payload = TerminalBridgeMessages.DecodeBase64Bytes(msg.AsSpan(2));
                _inputWriter.Enqueue(payload);
            }
            else if (msg.StartsWith("r:", StringComparison.Ordinal))
            {
                if (TerminalBridgeMessages.TryParseGeometry(
                    msg.AsSpan(),
                    MinimumUsableColumns,
                    MinimumUsableRows,
                    out var cols,
                    out var rows))
                {
                    if (cols != _lastColumns || rows != _lastRows)
                    {
                        _lastColumns = cols;
                        _lastRows = rows;
                        _logger.LogInformation("Terminal resize requested: {Columns}x{Rows}.", cols, rows);
                    }
                    await ResizeSessionAsync(cols, rows).ConfigureAwait(false);
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
                    var text = Encoding.UTF8.GetString(TerminalBridgeMessages.DecodeBase64Bytes(msg.AsSpan(2)));
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


    private async Task ResizeSessionAsync(uint columns, uint rows)
    {
        try
        {
            await _session.ResizeAsync(columns, rows).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogSessionOperationAfterClose(ex, "resizing terminal");
        }
    }

    private void LogSessionOperationAfterClose(Exception ex, string operation)
    {
        if (_disposed) return;
        _logger.LogDebug(ex, "Terminal session ended while {Operation}; owner will handle the close event.", operation);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _webView.WebMessageReceived -= OnWebMessageReceived;
        _inputWriter.Dispose();
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
        _forceBase64Output = true;
        try { _coalescer.Flush(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Final coalescer flush during Dispose failed."); }
        _disposed = true;
        _coalescer.Dispose();
        SchedulePendingSharedBufferDisposal();
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
