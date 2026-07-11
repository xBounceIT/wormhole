using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.Web.WebView2.Core;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Wormhole.Helpers;
using Wormhole.Services;

namespace Wormhole.Interop.Terminal;

internal sealed class TerminalBridge : ITerminalOutputSink
{
    private const uint MinimumUsableColumns = 20;
    private const uint MinimumUsableRows = 8;
    // Window chosen to be small enough that interactive output (keystroke echo,
    // single-line prompts) still feels instant, while large enough that a bursty
    // remote (e.g. cat large_file) collapses many SSH packets per ~frame into one
    // WebView2 PostWebMessageAsString. ~12 ms ≈ 80 fps cap on terminal updates.
    private const int CoalesceWindowMs = 12;

    // Flow-control watermarks (queued plus posted bytes not yet parsed). xterm parses
    // at only ~5-35 MB/s and silently DISCARDS writes once its internal buffer passes a hard ~50 MB
    // limit — which strands the parser mid-escape-sequence and corrupts the session until a full
    // reset (the "big tcpdump output then everything breaks until CTRL+L" bug). We pause the SSH
    // read pump well before that so the managed output queue stays bounded. SSH.NET can still buffer
    // unread channel data internally, so SshSession separately applies a hard safety limit there. The
    // high/low hysteresis avoids pause/resume flapping. 512 KB high keeps xterm's peak buffer to a
    // couple MB even counting in-flight coalesced bytes — two orders of magnitude under the discard
    // limit — while sitting far above interactive echo sizes, so the low-latency echo path never
    // trips it. See https://xtermjs.org/docs/guides/flowcontrol/.
    private const int HighWatermarkBytes = 512 * 1024;
    private const int LowWatermarkBytes = 128 * 1024;
    private const int MaxFrameBytes = 128 * 1024;
    private const int ImmediateFrameThresholdBytes = 512;
    private const int MaximumClipboardPasteUtf8Bytes = 1024 * 1024;
    // xterm wraps a bracketed paste with ESC[200~ / ESC[201~ (12 bytes total).
    // Leave bounded framing headroom without reducing the documented 1 MiB clipboard limit.
    private const int MaximumInputFrameUtf8Bytes = MaximumClipboardPasteUtf8Bytes + 64;
    private const int MaximumInputFrameBase64Characters = ((MaximumInputFrameUtf8Bytes + 2) / 3) * 4;
    private const int MaximumSelectionUtf8Bytes = 4 * 1024 * 1024;
    private const int MaximumSelectionBase64Characters = ((MaximumSelectionUtf8Bytes + 2) / 3) * 4;
    private const int MaximumPendingWebMessages = 4096;
    private const int MaximumPendingWebMessageCharacters = 8 * 1024 * 1024;
    private const int ClipboardPasteChunkCharacters = 16 * 1024;
    private static readonly TimeSpan OutputAcknowledgementTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SessionlessReplayTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ClipboardReadTimeout = TimeSpan.FromSeconds(10);
    // bridge.js keeps a released paste request alive for 50 seconds. Keep one end-to-end native
    // deadline (output posting + xterm parsing + clipboard I/O) comfortably inside that window so
    // the host can always post paste-cancel before the page retires the correlated request itself.
    internal static readonly TimeSpan ClipboardPasteTransactionTimeout = TimeSpan.FromSeconds(40);
    private static readonly TimeSpan TerminalResizeTimeout = TimeSpan.FromSeconds(10);
    private static long s_nextStreamId;

    private readonly CoreWebView2 _webView;
    private readonly ITerminalSession _session;
    private readonly ILogger<TerminalBridge> _logger;
    private readonly IAppSettingsService _settingsService;
    private readonly Action<TerminalSize, bool>? _onTerminalSizeChanged;
    private readonly Action<string>? _onOutputTransportFailed;
    private readonly DispatcherQueue _dispatcher;
    private readonly TerminalOutputPump _outputPump;
    private readonly TerminalInputWriter _inputWriter;
    private readonly TerminalFocusRequestGate _focusRequestGate = new();
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly Queue<string> _pendingWebMessages = new();
    private readonly object _retirementLock = new();
    private readonly long _streamId;
    private int _pendingWebMessageCharacters;
    private bool _processingWebMessages;
    private DispatcherQueueTimer? _coalesceTimer;
    private DispatcherQueueTimer? _outputAcknowledgementTimer;
    private TaskCompletionSource? _focusCompletion;
    private TaskCompletionSource? _retirementInputCompletion;
    private Task<TerminalOutputRetirement>? _retirementTask;
    private int _outputTransportFailed;
    private int _clipboardPasteInProgress;
    private int _retiring;
    private volatile bool _disposed;
    private bool _firstOutputLogged;
    private uint _lastColumns;
    private uint _lastRows;

    public TerminalBridge(
        CoreWebView2 webView,
        ITerminalSession session,
        ILogger<TerminalBridge> logger,
        IAppSettingsService settingsService,
        TerminalSize initialSize,
        TerminalInputWriter inputWriter,
        Action<TerminalSize, bool>? onTerminalSizeChanged = null,
        Action<string>? onOutputTransportFailed = null)
    {
        _webView = webView;
        _session = session;
        _logger = new NonThrowingLogger<TerminalBridge>(logger);
        _settingsService = settingsService;
        _inputWriter = inputWriter ?? throw new ArgumentNullException(nameof(inputWriter));
        _onTerminalSizeChanged = onTerminalSizeChanged;
        _onOutputTransportFailed = onOutputTransportFailed;
        // The session was created or explicitly resized to this geometry before the bridge is
        // attached. Seeding it prevents the forced focus report from sending an identical second
        // SSH window-change while still allowing a genuinely changed browser fit through.
        _lastColumns = initialSize.Columns;
        _lastRows = initialSize.Rows;
        // WebView2 is thread-affine to its creator. Capture the dispatcher at construction
        // (always called from the UI thread via SshTerminalView.OnReadyMessage) so we can
        // marshal SSH-pump callbacks back to the UI thread before touching the WebView.
        _dispatcher = DispatcherQueue.GetForCurrentThread()
            ?? throw new InvalidOperationException(
                "TerminalBridge must be constructed on a thread with a DispatcherQueue (the UI thread).");

        _streamId = AllocateStreamId();

        _outputPump = new TerminalOutputPump(
            HighWatermarkBytes,
            LowWatermarkBytes,
            MaxFrameBytes,
            ImmediateFrameThresholdBytes,
            PostOutputFrame,
            _session.PauseReading,
            _session.ResumeReading,
            OnOutputPostFailure);
        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    private static long AllocateStreamId()
    {
        var streamId = Interlocked.Increment(ref s_nextStreamId);
        if (streamId <= 0)
        {
            throw new InvalidOperationException("Terminal output stream id space was exhausted.");
        }
        return streamId;
    }

    internal static bool ShouldAcceptInputFrame(
        long bridgeStreamId,
        bool retiring,
        long inputStreamId,
        TerminalInputOrigin origin) =>
        inputStreamId == bridgeStreamId &&
        (!retiring || origin == TerminalInputOrigin.Parser);

    internal static bool ShouldAcceptResizeFrame(long bridgeStreamId, long resizeStreamId) =>
        resizeStreamId == bridgeStreamId;

    internal static IReadOnlyList<string> BuildSessionlessReplayMessages(
        long streamId,
        ReadOnlyMemory<byte> data)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(streamId);
        var frameCount = (data.Length + MaxFrameBytes - 1) / MaxFrameBytes;
        var streamText = streamId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var messages = new List<string>(frameCount + 2) { "clear:" + streamText };
        long frameId = 1;
        for (var offset = 0; offset < data.Length;)
        {
            var length = Math.Min(MaxFrameBytes, data.Length - offset);
            messages.Add(TerminalBridgeMessages.EncodeReplayFrame(
                streamId,
                frameId++,
                data.Slice(offset, length)));
            offset += length;
        }
        messages.Add(
            "k:" + streamText);
        return messages;
    }

    /// <summary>
    /// Reconstructs a terminal after its protocol session has already ended. Historical frames use
    /// the side-effect-free replay channel, while a neutral acknowledgement is the ordered parser
    /// barrier proving that the reset and every preceding frame completed inside xterm.
    /// </summary>
    internal static async Task ReplaySessionlessAsync(
        CoreWebView2 webView,
        ReadOnlyMemory<byte> data,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(webView);
        cancellationToken.ThrowIfCancellationRequested();
        var replayTimeout = timeout is { } requestedTimeout &&
            requestedTimeout < SessionlessReplayTimeout
            ? requestedTimeout
            : SessionlessReplayTimeout;
        if (replayTimeout <= TimeSpan.Zero)
        {
            throw new TimeoutException("No terminal replay deadline remained.");
        }
        var streamId = AllocateStreamId();
        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var recoverableFatalSeen = 0;

        void OnReplayMessage(
            CoreWebView2 sender,
            CoreWebView2WebMessageReceivedEventArgs args)
        {
            try
            {
                var message = args.TryGetWebMessageAsString();
                if (message is null) return;
                switch (TerminalBridgeMessages.ClassifySessionlessReplayMessage(
                    message,
                    streamId))
                {
                    case TerminalSessionlessReplayMessageDisposition.Ready:
                        completion.TrySetResult();
                        break;
                    case TerminalSessionlessReplayMessageDisposition.CurrentFailure:
                        completion.TrySetException(new InvalidOperationException(
                            "The terminal page rejected the preserved output reconstruction."));
                        break;
                    case TerminalSessionlessReplayMessageDisposition.RecoverableFatal:
                        Interlocked.Exchange(ref recoverableFatalSeen, 1);
                        break;
                }
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }
        }

        webView.WebMessageReceived += OnReplayMessage;
        try
        {
            foreach (var message in BuildSessionlessReplayMessages(streamId, data))
            {
                cancellationToken.ThrowIfCancellationRequested();
                webView.PostWebMessageAsString(message);
            }

            try
            {
                await completion.Task.WaitAsync(
                    replayTimeout,
                    cancellationToken).ConfigureAwait(true);
            }
            catch (TimeoutException ex)
            {
                var detail = Volatile.Read(ref recoverableFatalSeen) != 0
                    ? " after a recoverable or stale terminal failure"
                    : string.Empty;
                throw new InvalidOperationException(
                    $"The terminal page did not acknowledge the preserved output replay{detail}.",
                    ex);
            }
        }
        finally
        {
            try { webView.WebMessageReceived -= OnReplayMessage; }
            catch { /* the renderer may have closed while replay was pending */ }
        }
    }

    internal static async Task ResetSessionlessAsync(
        CoreWebView2 webView,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await ReplaySessionlessAsync(
                webView,
                ReadOnlyMemory<byte>.Empty,
                timeout,
                cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "The terminal page did not complete the ordered reset for the new session.",
                ex);
        }
    }

    public bool TryAppendOutput(ReadOnlyMemory<byte> data)
    {
        if (_disposed ||
            Volatile.Read(ref _retiring) != 0 ||
            _outputPump.IsSealed ||
            IsOutputTransportFailed ||
            data.IsEmpty)
        {
            return false;
        }
        if (!_firstOutputLogged)
        {
            _firstOutputLogged = true;
            _logger.LogInformation("First terminal output received: {ByteCount} bytes.", data.Length);
        }

        ScheduleDrain(_outputPump.Enqueue(data.Span));
        // Enqueue can fail closed when the bounded backlog is exhausted. Report rejection to
        // the owner immediately as well as scheduling the renderer-failure callback, otherwise
        // the VM would assume these bytes were accepted and omit them from its detached delta.
        // Once Enqueue accepted the bytes, report success even if dispatcher scheduling failed
        // immediately afterward. Disposal will return that one queued copy for detached replay;
        // returning false here as well would make the owner record the same bytes twice.
        return !_outputPump.IsFailed;
    }


    /// <summary>
    /// Forces every byte accepted before this call into the ordered WebView channel and waits until
    /// xterm's write callback acknowledges the complete prefix. Remote-close paths use this barrier
    /// before retiring the bridge so the final shell/editor repaint cannot be stranded in the native
    /// coalescer. The deadline is caller-owned: a dead renderer must not block session teardown forever.
    /// </summary>
    public async Task<bool> FlushOutputAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The terminal flush timeout must be positive.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (_disposed || IsOutputTransportFailed) return false;

        if (!_dispatcher.HasThreadAccess)
        {
            var marshaled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_dispatcher.TryEnqueue(async () =>
                {
                    try
                    {
                        marshaled.TrySetResult(
                            await FlushOutputAsync(timeout, cancellationToken).ConfigureAwait(true));
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        marshaled.TrySetCanceled(cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        marshaled.TrySetException(ex);
                    }
                }))
            {
                FailOutputTransport("enqueueing terminal output flush");
                return false;
            }
            return await marshaled.Task.ConfigureAwait(false);
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetimeCts.Token);
        timeoutCts.CancelAfter(timeout);
        try
        {
            while (true)
            {
                var outputBarrier = _outputPump.EnqueuedSequence;
                DrainOutput();
                if (!await WaitForOutputParsedBarrierAsync(
                        outputBarrier,
                        timeoutCts.Token).ConfigureAwait(true))
                {
                    return false;
                }

                // A producer racing the close signal may have appended after the first snapshot.
                // Only return once one complete acknowledged prefix is also the current prefix.
                if (_outputPump.EnqueuedSequence == outputBarrier) return true;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            if (!_disposed && !IsOutputTransportFailed && !_lifetimeCts.IsCancellationRequested)
            {
                _logger.LogWarning(
                    "Terminal output flush did not complete within {TimeoutSeconds} seconds.",
                    timeout.TotalSeconds);
            }
            return false;
        }
    }

    public async Task RequestFocusAsync()
    {
        if (_disposed || IsOutputTransportFailed || Volatile.Read(ref _retiring) != 0)
        {
            throw new InvalidOperationException("Terminal renderer is unavailable.");
        }

        if (!_dispatcher.HasThreadAccess)
        {
            var marshaled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_dispatcher.TryEnqueue(async () =>
                {
                    try
                    {
                        await RequestFocusAsync().ConfigureAwait(true);
                        marshaled.TrySetResult();
                    }
                    catch (Exception ex)
                    {
                        marshaled.TrySetException(ex);
                    }
                }))
            {
                FailOutputTransport("enqueueing terminal focus");
                throw new InvalidOperationException("Could not marshal terminal focus to the UI thread.");
            }
            await marshaled.Task.ConfigureAwait(false);
            return;
        }

        await _focusRequestGate.RunAsync(
            RequestFocusCoreAsync,
            _lifetimeCts.Token).ConfigureAwait(true);
    }

    private async Task RequestFocusCoreAsync()
    {
        if (_disposed || IsOutputTransportFailed || Volatile.Read(ref _retiring) != 0)
        {
            throw new InvalidOperationException("Terminal renderer is unavailable.");
        }

        var outputBarrier = _outputPump.EnqueuedSequence;
        DrainOutput();
        if (!await WaitForOutputBarrierAsync(outputBarrier).ConfigureAwait(true))
        {
            throw new InvalidOperationException("Terminal output failed before the focus barrier.");
        }

        if (_disposed || IsOutputTransportFailed || Volatile.Read(ref _retiring) != 0)
        {
            throw new InvalidOperationException("Terminal renderer retired before the focus barrier.");
        }

        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (Interlocked.CompareExchange(ref _focusCompletion, completion, null) is not null)
        {
            throw new InvalidOperationException("A terminal focus request escaped serialization.");
        }

        try
        {
            // Failure can arrive from the protocol producer after the output await but before
            // _focusCompletion is installed. Re-check now so that missed notification cannot
            // strand this request until its timeout while WebView messages are already ignored.
            if (_disposed || IsOutputTransportFailed || Volatile.Read(ref _retiring) != 0)
            {
                completion.TrySetException(
                    new IOException("Terminal output transport failed before the focus barrier."));
            }
            else if (!PostStringToWebView(
                         "f:" + _streamId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                         "requesting ordered terminal focus"))
            {
                FailOutputTransport("requesting terminal focus");
                // Disposal makes FailOutputTransport a no-op, so complete locally as a fallback.
                completion.TrySetException(
                    new IOException("Could not post the terminal focus barrier."));
            }

            await completion.Task.WaitAsync(OutputAcknowledgementTimeout).ConfigureAwait(true);
        }
        catch (TimeoutException)
        {
            FailOutputTransport("waiting for terminal focus acknowledgement");
            throw;
        }
        finally
        {
            Interlocked.CompareExchange(ref _focusCompletion, null, completion);
        }
    }

    /// <summary>
    /// Replays captured output onto xterm. A detached delta is real, previously-undelivered output
    /// and therefore uses the normal acknowledged pipe. A full renderer reconstruction uses
    /// side-effect-free replay frames so historical terminal queries cannot inject replies into
    /// the still-live SSH or serial session.
    /// </summary>
    public void Replay(ReadOnlyMemory<byte> data, bool suppressTerminalResponses)
    {
        if (_disposed || data.IsEmpty) return;
        if (!suppressTerminalResponses)
        {
            ScheduleDrain(_outputPump.Enqueue(data.Span));
            return;
        }

        if (!_dispatcher.HasThreadAccess)
        {
            throw new InvalidOperationException(
                "A full terminal replay must be posted from the WebView UI thread.");
        }

        long replayFrameId = 1;
        for (var offset = 0; offset < data.Length;)
        {
            var length = Math.Min(MaxFrameBytes, data.Length - offset);
            var message = TerminalBridgeMessages.EncodeReplayFrame(
                _streamId,
                replayFrameId++,
                data.Slice(offset, length));
            if (!PostStringToWebView(message, "posting side-effect-free terminal replay"))
            {
                FailOutputTransport("posting side-effect-free terminal replay");
                throw new InvalidOperationException("Could not post terminal replay to the renderer.");
            }
            offset += length;
        }
    }

    private void ScheduleDrain(TerminalDrainRequest request)
    {
        if (_disposed || IsOutputTransportFailed || request == TerminalDrainRequest.None) return;

        var scheduled = request switch
        {
            TerminalDrainRequest.Immediate => _dispatcher.TryEnqueue(DrainOutput),
            TerminalDrainRequest.Delayed => _dispatcher.TryEnqueue(StartCoalesceTimer),
            _ => true,
        };
        if (!scheduled)
        {
            FailOutputTransport("scheduling terminal output");
        }
    }

    private void StartCoalesceTimer()
    {
        if (_disposed || IsOutputTransportFailed) return;
        if (_coalesceTimer is null)
        {
            _coalesceTimer = _dispatcher.CreateTimer();
            _coalesceTimer.Interval = TimeSpan.FromMilliseconds(CoalesceWindowMs);
            _coalesceTimer.IsRepeating = false;
            _coalesceTimer.Tick += OnCoalesceTimerTick;
        }
        _coalesceTimer.Stop();
        _coalesceTimer.Start();
    }

    private void OnCoalesceTimerTick(DispatcherQueueTimer sender, object args) => DrainOutput();

    private void DrainOutput()
    {
        if (_disposed || IsOutputTransportFailed) return;
        ScheduleDrain(_outputPump.Drain());
    }

    private bool PostOutputFrame(long frameId, ReadOnlyMemory<byte> data)
    {
        if (_disposed || IsOutputTransportFailed) return false;

        var message = TerminalBridgeMessages.EncodeOutputFrame(_streamId, frameId, data);
        var posted = PostStringToWebView(message, "posting terminal output");
        if (posted)
        {
            // The pump reserves the ledger entry before calling this sink. Arm only when this
            // frame is the oldest outstanding one; later posts must not postpone its deadline.
            if (_outputPump.OldestInFlightFrameId == frameId)
            {
                RestartOutputAcknowledgementWatchdog();
            }
        }
        else
        {
            // A rejected WebView post cannot recover by spinning the coalesce timer: the page or
            // browser process is gone. Fail closed so the owner tears down the protocol session.
            FailOutputTransport("posting terminal output");
        }
        return posted;
    }

    private void RestartOutputAcknowledgementWatchdog()
    {
        if (_disposed || IsOutputTransportFailed) return;
        try
        {
            if (_outputAcknowledgementTimer is null)
            {
                _outputAcknowledgementTimer = _dispatcher.CreateTimer();
                _outputAcknowledgementTimer.Interval = OutputAcknowledgementTimeout;
                _outputAcknowledgementTimer.IsRepeating = false;
                _outputAcknowledgementTimer.Tick += OnOutputAcknowledgementTimeout;
            }

            _outputAcknowledgementTimer.Stop();
            _outputAcknowledgementTimer.Start();
        }
        catch (Exception ex)
        {
            // PostOutputFrame calls this only after WebView accepted the frame. Never let an
            // ancillary timer failure escape and roll that committed post back in the pump ledger.
            try { _logger.LogError(ex, "Could not arm the terminal output acknowledgement watchdog."); }
            catch { /* failure recovery below remains mandatory */ }
            FailOutputTransport("arming the terminal output acknowledgement watchdog");
        }
    }

    private void StopOutputAcknowledgementWatchdog()
    {
        try { _outputAcknowledgementTimer?.Stop(); }
        catch (Exception ex)
        {
            try { _logger.LogDebug(ex, "Terminal output acknowledgement watchdog was unavailable while stopping."); }
            catch { /* the failed/disposed flags still make future ticks inert */ }
        }
    }

    private void StopOutputAcknowledgementWatchdogThreadSafe()
    {
        try
        {
            if (_dispatcher.HasThreadAccess)
            {
                StopOutputAcknowledgementWatchdog();
            }
            else
            {
                // Dispatcher rejection means the view is already shutting down; the failed flag
                // makes a later timer tick inert, so no unsafe cross-thread access is necessary.
                _dispatcher.TryEnqueue(StopOutputAcknowledgementWatchdog);
            }
        }
        catch (Exception ex)
        {
            try { _logger.LogDebug(ex, "Could not marshal terminal watchdog shutdown."); }
            catch { /* output failure handling must remain non-throwing */ }
        }
    }
    private void OnOutputAcknowledgementTimeout(DispatcherQueueTimer sender, object args)
    {
        sender.Stop();
        if (_disposed || IsOutputTransportFailed || _outputPump.InFlightFrameCount == 0) return;

        try
        {
            _logger.LogError(
                "Terminal renderer did not acknowledge {FrameCount} output frame(s) within {TimeoutSeconds} seconds.",
                _outputPump.InFlightFrameCount,
                OutputAcknowledgementTimeout.TotalSeconds);
        }
        catch { /* recovery must not depend on a logging provider */ }
        FailOutputTransport("waiting for xterm output acknowledgement");
    }

    private void OnOutputPostFailure(Exception exception)
    {
        try { _logger.LogError(exception, "Terminal output pipeline failed."); }
        catch { /* recovery must not depend on a logging provider */ }
        FailOutputTransport("processing terminal output");
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
            _logger.LogWarning(ex, "PostWebMessageAsString rejected while {Operation}.", operation);
            return false;
        }
        catch (COMException ex)
        {
            _logger.LogWarning(ex, "WebView2 rejected a terminal message while {Operation}.", operation);
            return false;
        }
    }

    private void FailOutputTransport(string operation)
    {
        if (_disposed) return;

        // Publish failure before waking proofs. Retirement/focus re-check after installing their TCS;
        // every failure call also wakes the currently installed TCS, closing both missed-wakeup races.
        var isFirstFailure = Interlocked.Exchange(ref _outputTransportFailed, 1) == 0;
        try
        {
            var failure = new IOException("Terminal output transport failed.");
            Volatile.Read(ref _focusCompletion)?.TrySetException(failure);
            Volatile.Read(ref _retirementInputCompletion)?.TrySetException(failure);
        }
        catch { /* barrier recovery is secondary to owner notification */ }

        if (!isFirstFailure) return;
        StopOutputAcknowledgementWatchdogThreadSafe();
        try
        {
            _logger.LogWarning(
                "Terminal output transport became unavailable while {Operation}.",
                operation);
        }
        catch { /* logging must not block recovery */ }

        const string userMessage =
            "The terminal renderer stopped responding. Reconnect to restore a clean terminal state.";
        if (_onOutputTransportFailed is not null)
        {
            // Never enter the owner synchronously while TerminalOutputPump holds its lock. The
            // producer routes output while holding the VM replay lock, so a synchronous callback
            // from the UI drain would invert those locks and deadlock both threads.
            void NotifyOwner()
            {
                try { _onOutputTransportFailed(userMessage); }
                catch (Exception ex)
                {
                    try { _logger.LogError(ex, "Terminal output failure callback threw."); }
                    catch { /* callback isolation is mandatory */ }
                }
            }

            var scheduled = false;
            try { scheduled = _dispatcher.TryEnqueue(NotifyOwner); }
            catch (Exception ex)
            {
                try { _logger.LogDebug(ex, "Could not enqueue terminal output recovery on the UI dispatcher."); }
                catch { /* Task.Run fallback below remains available */ }
            }
            if (!scheduled)
            {
                try { _ = Task.Run(NotifyOwner); }
                catch (Exception ex)
                {
                    try { _logger.LogError(ex, "Could not schedule terminal output recovery."); }
                    catch { /* no synchronous callback: it could invert the pump/VM locks */ }
                    TryResumeProducerAfterFailure();
                }
            }
            return;
        }

        TryResumeProducerAfterFailure();
    }

    private void TryResumeProducerAfterFailure()
    {
        // Owners normally tear down the failed session. Without one (or if scheduling recovery
        // itself failed), never leave a protocol producer parked behind this retired renderer.
        try { _session.ResumeReading(); }
        catch (Exception ex)
        {
            try { _logger.LogDebug(ex, "ResumeReading after terminal transport failure failed."); }
            catch { /* best effort */ }
        }
    }

    private void OnWebMessageReceived(
        CoreWebView2 sender,
        CoreWebView2WebMessageReceivedEventArgs args)
    {
        // WebView2 raises messages on the UI thread. Extract the string while the event args are
        // valid, handle output credit immediately, and serialize all other control/input messages.
        // This preserves resize -> focus -> input and paste -> later-input order without blocking
        // ACKs that the output barrier itself needs in order to make progress.
        try
        {
            if (_disposed || IsOutputTransportFailed) return;
            var msg = args.TryGetWebMessageAsString();
            if (string.IsNullOrEmpty(msg)) return;
            if (msg.Length > MaximumPendingWebMessageCharacters)
            {
                FailOutputTransport("validating an oversized terminal message");
                return;
            }
            if (TryHandleOutputControlMessage(msg)) return;

            var isAcceptedInput = false;
            if (msg.StartsWith("b:", StringComparison.Ordinal))
            {
                if (!TerminalBridgeMessages.TryParseInputFrame(
                        msg.AsSpan(),
                        out var inputStreamId,
                        out var inputOrigin,
                        out _))
                {
                    if (Volatile.Read(ref _retiring) == 0)
                    {
                        FailOutputTransport("validating malformed terminal input");
                    }
                    return;
                }
                if (!ShouldAcceptInputFrame(
                        _streamId,
                        Volatile.Read(ref _retiring) != 0,
                        inputStreamId,
                        inputOrigin))
                {
                    return;
                }
                isAcceptedInput = true;
            }

            var isAcceptedResize = false;
            if (msg.StartsWith("r:", StringComparison.Ordinal))
            {
                if (!TerminalBridgeMessages.TryParseScopedGeometry(
                        msg.AsSpan(),
                        MinimumUsableColumns,
                        MinimumUsableRows,
                        out var resizeStreamId,
                        out _,
                        out _) ||
                    !ShouldAcceptResizeFrame(_streamId, resizeStreamId))
                {
                    return;
                }
                isAcceptedResize = true;
            }

            var isRetirementBarrier =
                Volatile.Read(ref _retiring) != 0 &&
                TerminalBridgeMessages.TryParseParserBarrierReady(
                    msg.AsSpan(),
                    out var barrierStreamId) &&
                barrierStreamId == _streamId;

            // A retiring bridge remains subscribed to finish ACKs, parser replies, same-stream
            // resize work posted before x:, and its final native-FIFO barrier. Keeping resize in this
            // queue guarantees r: is processed before the later barrier emitted for k: can retire the sink.
            if (Volatile.Read(ref _retiring) != 0 &&
                !isAcceptedInput &&
                !isAcceptedResize &&
                !isRetirementBarrier)
            {
                return;
            }

            if (_pendingWebMessages.Count >= MaximumPendingWebMessages ||
                _pendingWebMessageCharacters > MaximumPendingWebMessageCharacters - msg.Length)
            {
                FailOutputTransport("queueing terminal control or input messages");
                return;
            }

            _pendingWebMessages.Enqueue(msg);
            _pendingWebMessageCharacters += msg.Length;
            StartWebMessageProcessor();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TerminalBridge: failed to accept a WebView2 message.");
        }
    }

    private void StartWebMessageProcessor()
    {
        if (_processingWebMessages || _disposed || IsOutputTransportFailed) return;
        _processingWebMessages = true;
        _ = ProcessWebMessageQueueAsync();
    }

    private async Task ProcessWebMessageQueueAsync()
    {
        try
        {
            while (!_disposed &&
                   !IsOutputTransportFailed &&
                   _pendingWebMessages.Count > 0)
            {
                var msg = _pendingWebMessages.Dequeue();
                _pendingWebMessageCharacters -= msg.Length;
                try
                {
                    await ProcessWebMessageAsync(msg).ConfigureAwait(true);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "TerminalBridge: failed to process a WebView2 message.");
                }
            }
        }
        finally
        {
            _processingWebMessages = false;
            if (_disposed || IsOutputTransportFailed)
            {
                _pendingWebMessages.Clear();
                _pendingWebMessageCharacters = 0;
            }
            else if (_pendingWebMessages.Count > 0)
            {
                StartWebMessageProcessor();
            }
        }
    }

    private bool TryHandleOutputControlMessage(string msg)
    {
        if (TerminalBridgeMessages.TryParseOutputAck(msg.AsSpan(), out var streamId, out var frameId))
        {
            // ACKs are scoped to one bridge generation and matched against the pump's exact
            // frame ledger. Stale/duplicate ACKs therefore cannot release another session's
            // credit or resume the producer early.
            if (streamId == _streamId)
            {
                var oldestBefore = _outputPump.OldestInFlightFrameId;
                var drainRequest = _outputPump.Acknowledge(frameId);
                var oldestAfter = _outputPump.OldestInFlightFrameId;
                if (oldestAfter != oldestBefore)
                {
                    if (oldestAfter is null)
                    {
                        StopOutputAcknowledgementWatchdog();
                    }
                    else
                    {
                        // Only progress of the oldest ledger entry earns a fresh deadline.
                        // A late ACK for a newer frame cannot hide one permanently lost ACK.
                        RestartOutputAcknowledgementWatchdog();
                    }
                }
                ScheduleDrain(drainRequest);
            }
            return true;
        }

        if (TerminalBridgeMessages.TryParseOutputWriteFailure(
            msg.AsSpan(),
            out var failedStreamId,
            out var failedFrameId))
        {
            // outputFailed lives at page scope in bridge.js. A late failure from a retired
            // stream therefore poisons the current bridge as well, even though its frame id
            // must not touch this pump's ledger. Fail fast instead of waiting 30 seconds for
            // the replacement stream's watchdog.
            FailOutputTransport("handling a terminal-page write failure");
            _logger.LogError(
                "Terminal page rejected output frame {FrameId} on stream {StreamId} (current stream {CurrentStreamId}).",
                failedFrameId,
                failedStreamId,
                _streamId);
            return true;
        }

        if (TerminalBridgeMessages.TryParseParserBarrierFailure(
                msg.AsSpan(),
                out var failedBarrierStreamId))
        {
            // The page failure flag is global, so every attached bridge fails closed. In
            // particular, the matching retiring bridge must wake its pending barrier now rather
            // than preserving the UI/session handoff for the full retirement timeout.
            FailOutputTransport("handling a terminal-page parser barrier failure");
            _logger.LogError(
                "Terminal page rejected the parser barrier on stream {StreamId} (current stream {CurrentStreamId}).",
                failedBarrierStreamId,
                _streamId);
            return true;
        }

        if (msg is "fatal:protocol" or "fatal:clear")
        {
            FailOutputTransport("handling a terminal-page fatal error");
            _logger.LogError("Terminal page reported a fatal output error: {Frame}", msg);
            return true;
        }

        if (msg.StartsWith("fatal:", StringComparison.Ordinal))
        {
            // Unknown fatal frames still mean bridge.js entered its global outputFailed state.
            // Fail and wake pending page proofs instead of waiting for their watchdogs.
            FailOutputTransport("handling an unknown terminal-page fatal error");
            _logger.LogError(
                "Terminal page reported an unknown or malformed fatal frame: {Frame}",
                msg);
            return true;
        }

        return false;
    }

    private async Task ProcessWebMessageAsync(string msg)
    {
        if (TerminalBridgeMessages.TryParseParserBarrierReady(
                msg.AsSpan(),
                out var barrierStreamId))
        {
            if (barrierStreamId == _streamId)
            {
                Volatile.Read(ref _retirementInputCompletion)?.TrySetResult();
            }
            return;
        }
        if (TerminalBridgeMessages.TryParseFocusReady(msg.AsSpan(), out var focusedStreamId))
        {
            if (focusedStreamId == _streamId)
            {
                Volatile.Read(ref _focusCompletion)?.TrySetResult();
            }
            return;
        }
        if (TerminalBridgeMessages.TryParseInputFrame(
                msg.AsSpan(),
                out var inputStreamId,
                out var inputOrigin,
                out var encodedPayloadOffset))
        {
            // Re-check after FIFO queueing: retirement can begin after OnWebMessageReceived
            // accepted a human frame but before this serialized processor reaches it.
            if (!ShouldAcceptInputFrame(
                    _streamId,
                    Volatile.Read(ref _retiring) != 0,
                    inputStreamId,
                    inputOrigin))
            {
                return;
            }

            // xterm input is base64-encoded raw bytes and scoped by both output stream and
            // origin. A retiring bridge drains only parser DA/DSR/CPR replies; human input is
            // owned exclusively by the bridge whose ordered focus barrier enabled it.
            var encodedInput = msg.AsSpan(encodedPayloadOffset);
            if (encodedInput.Length > MaximumInputFrameBase64Characters)
            {
                FailOutputTransport("validating oversized terminal input");
                return;
            }
            var payload = TerminalBridgeMessages.DecodeBase64Bytes(encodedInput);
            if (payload.Length > MaximumInputFrameUtf8Bytes)
            {
                FailOutputTransport("validating oversized terminal input");
                return;
            }
            _inputWriter.Enqueue(payload);
        }
        else if (msg.StartsWith("r:", StringComparison.Ordinal))
        {
            if (TerminalBridgeMessages.TryParseScopedGeometry(
                    msg.AsSpan(),
                    MinimumUsableColumns,
                    MinimumUsableRows,
                    out var resizeStreamId,
                    out var cols,
                    out var rows) &&
                ShouldAcceptResizeFrame(_streamId, resizeStreamId))
            {
                if (cols == _lastColumns && rows == _lastRows) return;

                _lastColumns = cols;
                _lastRows = rows;
                var size = new TerminalSize(cols, rows);
                _logger.LogInformation("Terminal resize requested: {Columns}x{Rows}.", cols, rows);

                // A resize posted just before x: still owns this stream and must drain before k:.
                // If the remote endpoint is already closing, window-change cannot be sent; record
                // the renderer geometry anyway so the owner rejects replay of ambiguous TUI bytes.
                var resizeSucceeded = false;
                if (!_session.IsClosing)
                {
                    resizeSucceeded = await ResizeSessionAsync(cols, rows).ConfigureAwait(true);
                }
                try { _onTerminalSizeChanged?.Invoke(size, !resizeSucceeded); }
                catch (Exception ex) { _logger.LogWarning(ex, "Terminal size callback failed."); }
                if (!resizeSucceeded && !_disposed && !_session.IsClosing)
                {
                    FailOutputTransport("resizing the terminal session");
                }
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
                var encodedSelection = msg.AsSpan(2);
                if (encodedSelection.Length > MaximumSelectionBase64Characters)
                {
                    _logger.LogWarning("Ignored oversized terminal selection clipboard frame.");
                    return;
                }
                var selectionBytes = TerminalBridgeMessages.DecodeBase64Bytes(encodedSelection);
                if (selectionBytes.Length > MaximumSelectionUtf8Bytes) return;
                var text = Encoding.UTF8.GetString(selectionBytes);
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
        else if (TerminalBridgeMessages.TryParsePasteRequest(
            msg.AsSpan(),
            out var pasteRequestId,
            out var forcePaste))
        {
            // The page already holds genuine user input behind this request. Run clipboard work
            // independently so terminal-generated DA/DSR/CPR replies and resize messages continue
            // through the native FIFO while the output barrier or clipboard API is pending.
            StartClipboardPasteRequest(pasteRequestId, forcePaste);
        }
    }

    private void StartClipboardPasteRequest(long pasteRequestId, bool forcePaste)
    {
        // ProcessClipboardPasteRequestAsync catches every expected transport/clipboard failure.
        // Keep one final observer around the detached operation so an unforeseen exception is never
        // left unobserved and cannot silently strand the page-side paste gate.
        StartObservedOperation(
            () => ProcessClipboardPasteRequestAsync(pasteRequestId, forcePaste),
            ex =>
            {
                Volatile.Write(ref _clipboardPasteInProgress, 0);
                _logger.LogError(ex, "TerminalBridge: unexpected clipboard paste transaction failure.");
                if (_disposed || IsOutputTransportFailed) return;

                PostClipboardPasteCancellation(
                    pasteRequestId,
                    "cancelling failed terminal paste transaction");
            });
    }

    internal static void StartObservedOperation(
        Func<Task> operation,
        Action<Exception> onFailure)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(onFailure);
        _ = ObserveOperationAsync(operation, onFailure);
    }

    private static async Task ObserveOperationAsync(
        Func<Task> operation,
        Action<Exception> onFailure)
    {
        try
        {
            await operation().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            try { onFailure(ex); }
            catch { }
        }
    }

    private async Task ProcessClipboardPasteRequestAsync(long pasteRequestId, bool forcePaste)
    {
        // Clipboard APIs are async and WebView can issue several context-menu events. One
        // bounded transaction at a time prevents overlapping 1 MiB assemblies in the page.
        if (Interlocked.CompareExchange(ref _clipboardPasteInProgress, 1, 0) != 0)
        {
            PostClipboardPasteCancellation(
                pasteRequestId,
                "rejecting overlapping terminal paste transaction");
            return;
        }

        using var transactionCts =
            CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token);
        transactionCts.CancelAfter(ClipboardPasteTransactionTimeout);
        var outputBarrier = _outputPump.EnqueuedSequence;
        var requestText = pasteRequestId.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        var pasteResponsePosted = false;
        try
        {
            // Let JS release its paste marker so native bytes accepted before this request can
            // be posted and parsed. The correlated ACK barrier below closes the C# coalescer gap.
            if (!PostStringToWebView(
                    "paste-drain:" + requestText,
                    "releasing the terminal paste output gate"))
            {
                FailOutputTransport("releasing the terminal paste output gate");
                return;
            }
            DrainOutput();
            if (!await WaitForOutputParsedBarrierAsync(
                    outputBarrier,
                    transactionCts.Token).ConfigureAwait(true))
            {
                return;
            }

            var view = Clipboard.GetContent();
            if (view is null || !view.Contains(StandardDataFormats.Text)) return;
            using var clipboardReadCts =
                CancellationTokenSource.CreateLinkedTokenSource(transactionCts.Token);
            clipboardReadCts.CancelAfter(ClipboardReadTimeout);
            var text = await view.GetTextAsync()
                .AsTask(clipboardReadCts.Token)
                .ConfigureAwait(true);
            if (string.IsNullOrEmpty(text)) return;
            var byteCount = Encoding.UTF8.GetByteCount(text);
            if (byteCount > MaximumClipboardPasteUtf8Bytes)
            {
                _logger.LogWarning(
                    "Rejected terminal paste of {ByteCount} UTF-8 bytes; limit is {LimitBytes} bytes.",
                    byteCount,
                    MaximumClipboardPasteUtf8Bytes);
                return;
            }

            transactionCts.Token.ThrowIfCancellationRequested();
            pasteResponsePosted = PostClipboardPasteInChunks(
                pasteRequestId,
                forcePaste,
                text,
                byteCount,
                transactionCts.Token);
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
            // Bridge retirement owns the cancellation; no stale clipboard result may reach
            // the replacement session.
        }
        catch (OperationCanceledException ex) when (transactionCts.IsCancellationRequested)
        {
            _logger.LogWarning(
                ex,
                "Terminal clipboard paste exceeded its {TimeoutSeconds}-second end-to-end deadline.",
                ClipboardPasteTransactionTimeout.TotalSeconds);
        }
        catch (OperationCanceledException ex)
        {
            _logger.LogWarning(ex, "TerminalBridge: timed out reading clipboard for paste.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TerminalBridge: failed to read clipboard for paste.");
        }
        finally
        {
            if (!pasteResponsePosted && !_disposed && !IsOutputTransportFailed)
            {
                PostClipboardPasteCancellation(
                    pasteRequestId,
                    "cancelling terminal paste transaction");
            }
            Volatile.Write(ref _clipboardPasteInProgress, 0);
        }
    }

    private void PostClipboardPasteCancellation(long pasteRequestId, string operation)
    {
        if (!PostStringToWebView(
                "paste-cancel:" + pasteRequestId.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
                operation))
        {
            FailOutputTransport(operation);
        }
    }

    private Task<bool> WaitForOutputBarrierAsync(ulong outputBarrier) =>
        WaitForOutputBarrierAsync(
            outputBarrier,
            CancellationToken.None,
            OutputAcknowledgementTimeout);

    private async Task<bool> WaitForOutputBarrierAsync(
        ulong outputBarrier,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        var started = Environment.TickCount64;
        while (_outputPump.PostedSequence < outputBarrier)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_disposed || IsOutputTransportFailed) return false;

            // ACKs may have opened credit since the prior iteration. Drain on the WebView thread
            // until the complete native byte prefix has entered the ordered page channel.
            DrainOutput();
            if (_outputPump.PostedSequence >= outputBarrier) return true;

            if (timeout is { } limit &&
                Environment.TickCount64 - started >= limit.TotalMilliseconds)
            {
                FailOutputTransport("ordering a terminal interaction behind pending output");
                return false;
            }
            await Task.Delay(10, cancellationToken).ConfigureAwait(true);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return true;
    }

    private async Task<bool> WaitForOutputParsedBarrierAsync(
        ulong outputBarrier,
        CancellationToken cancellationToken)
    {
        if (!await WaitForOutputBarrierAsync(
                outputBarrier,
                cancellationToken).ConfigureAwait(true))
        {
            return false;
        }
        if (outputBarrier == 0) return true;

        // Posted frames are FIFO and bridge.js submits only one xterm.write at a time. Once the
        // newest frame posted for this prefix is ACKed, every earlier byte was necessarily parsed.
        var barrierFrameId = _outputPump.LastPostedFrameId;
        if (barrierFrameId <= 0)
        {
            FailOutputTransport("resolving the terminal output parse barrier");
            return false;
        }

        while (_outputPump.IsFrameInFlight(barrierFrameId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_disposed || IsOutputTransportFailed) return false;
            await Task.Delay(10, cancellationToken).ConfigureAwait(true);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return true;
    }

    private bool PostClipboardPasteInChunks(
        long requestId,
        bool forcePaste,
        string text,
        int totalUtf8Bytes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var requestText = requestId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (!PostStringToWebView(
                $"paste-begin:{requestText}:{(forcePaste ? 1 : 0)}:{totalUtf8Bytes}",
                "starting terminal paste transaction"))
        {
            FailOutputTransport("starting terminal paste transaction");
            return false;
        }

        for (var offset = 0; offset < text.Length;)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var characterCount = Math.Min(ClipboardPasteChunkCharacters, text.Length - offset);
            // Each chunk is encoded independently, so never split a surrogate pair. Keep CRLF
            // together as well to preserve the exact host text before the final UTF-8 assembly.
            if (offset + characterCount < text.Length &&
                ((char.IsHighSurrogate(text[offset + characterCount - 1]) &&
                  char.IsLowSurrogate(text[offset + characterCount])) ||
                 (text[offset + characterCount - 1] == '\r' &&
                  text[offset + characterCount] == '\n')))
            {
                characterCount--;
            }

            var characters = text.AsSpan(offset, characterCount);
            var bytes = new byte[Encoding.UTF8.GetByteCount(characters)];
            Encoding.UTF8.GetBytes(characters, bytes);
            var encoded = Convert.ToBase64String(bytes);
            if (!PostStringToWebView(
                    $"paste-chunk:{requestText}:{encoded}",
                    "posting terminal paste chunk"))
            {
                FailOutputTransport("posting terminal paste chunk");
                return false;
            }
            offset += characterCount;
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!PostStringToWebView(
                "paste-end:" + requestText,
                "completing terminal paste transaction"))
        {
            FailOutputTransport("completing terminal paste transaction");
            return false;
        }
        return true;
    }

    private async Task<bool> ResizeSessionAsync(uint columns, uint rows)
    {
        try
        {
            await _session.ResizeAsync(columns, rows)
                .WaitAsync(TerminalResizeTimeout)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            LogSessionOperationAfterClose(ex, "resizing terminal");
            return false;
        }
    }
    private void LogSessionOperationAfterClose(Exception ex, string operation)
    {
        if (_disposed) return;
        _logger.LogDebug(ex, "Terminal session ended while {Operation}; owner will handle the close event.", operation);
    }

    public Task<TerminalOutputRetirement> RetireAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_retirementLock)
        {
            return _retirementTask ??= RetireCoreAsync(timeout, cancellationToken);
        }
    }

    private async Task<TerminalOutputRetirement> RetireCoreAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref _retiring, 1);
        // Focus and retirement are UI-thread-affine once marshaled, so after this publication no
        // new f: can pass RequestFocusCoreAsync's final check. Wake an already-installed proof too.
        Volatile.Read(ref _focusCompletion)?.TrySetException(
            new IOException("Terminal retired before the focus barrier completed."));

        var deadline = Environment.TickCount64 + (long)Math.Ceiling(timeout.TotalMilliseconds);
        var exactRetirement = false;
        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            if (Interlocked.CompareExchange(
                    ref _retirementInputCompletion,
                    completion,
                    null) is not null)
            {
                throw new InvalidOperationException(
                    "A terminal input retirement barrier is already pending.");
            }

            // Failure can publish after RetireAsync's entry check but before this proof is installed.
            // Re-check after publication; x: is still posted below to revoke page-side input/paste.
            if (IsOutputTransportFailed)
            {
                completion.TrySetException(
                    new IOException("Terminal output transport failed before the retirement barrier."));
            }

            // Seal the native prefix and immediately retire page-side human input/paste state.
            // x: only releases page-side gates; the ordered k: proof is deliberately posted
            // after every sealed byte reached xterm and acknowledged, so queued native output
            // can never be overtaken by an early parser barrier.
            ScheduleDrain(_outputPump.Seal());
            var retirementPosted = PostStringToWebView(
                "x:" + _streamId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "posting terminal retirement boundary");

            var remaining = RemainingUntil(deadline);
            if (retirementPosted &&
                remaining > TimeSpan.Zero &&
                await FlushOutputAsync(remaining, cancellationToken).ConfigureAwait(true))
            {
                remaining = RemainingUntil(deadline);
                if (remaining > TimeSpan.Zero &&
                    PostStringToWebView(
                        "k:" + _streamId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        "posting terminal retirement input barrier"))
                {
                    remaining = RemainingUntil(deadline);
                    exactRetirement =
                        remaining > TimeSpan.Zero &&
                        await WaitForRetirementInputBarrierAsync(
                            completion.Task,
                            remaining,
                            cancellationToken).ConfigureAwait(true);
                }
            }

            if (!exactRetirement)
            {
                _logger.LogWarning(
                    "Terminal bridge retirement could not confirm its complete output and input prefix.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.LogDebug("Terminal bridge retirement was cancelled; preserving its uncertain prefix.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Terminal bridge retirement failed; preserving its unposted and uncertain output.");
        }
        finally
        {
            Interlocked.CompareExchange(
                ref _retirementInputCompletion,
                null,
                completion);
        }

        var retirement = DisposeAndTakePendingOutput(
            hadUncertainGeometry: !exactRetirement);
        return retirement with
        {
            HadUnacknowledgedOutput =
                retirement.HadUnacknowledgedOutput || !exactRetirement,
        };
    }

    private static async Task<bool> WaitForRetirementInputBarrierAsync(
        Task completion,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            await completion.WaitAsync(timeout, cancellationToken).ConfigureAwait(true);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
    }

    private static TimeSpan RemainingUntil(long deadline)
    {
        var remainingMilliseconds = deadline - Environment.TickCount64;
        return remainingMilliseconds > 0
            ? TimeSpan.FromMilliseconds(remainingMilliseconds)
            : TimeSpan.Zero;
    }

    /// <summary>
    /// Detaches the bridge and returns bytes that never reached the WebView plus whether posted
    /// frames still lacked an xterm acknowledgement. The owner uses both facts to decide whether
    /// the surviving protocol session has an exact replay checkpoint.
    /// </summary>
    public TerminalOutputRetirement DisposeAndTakePendingOutput() =>
        DisposeAndTakePendingOutput(hadUncertainGeometry: true);

    private TerminalOutputRetirement DisposeAndTakePendingOutput(
        bool hadUncertainGeometry)
    {
        if (_disposed)
        {
            return TerminalOutputRetirement.Empty with
            {
                HadUncertainGeometry = hadUncertainGeometry,
            };
        }
        // Publish disposal before touching thread-affine objects so concurrent producers stop.
        // Cleanup is deliberately best-effort: even a dead WebView/timer must not prevent the
        // output pump from returning its queue and releasing a paused protocol producer.
        _disposed = true;
        var retirement = TerminalOutputRetirement.Empty;
        try
        {
            try { _lifetimeCts.Cancel(); }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Terminal bridge lifetime cancellation reported a cleanup failure.");
            }
            Volatile.Read(ref _focusCompletion)?.TrySetCanceled();
            Volatile.Read(ref _retirementInputCompletion)?.TrySetCanceled();

            try
            {
                _webView.WebMessageReceived -= OnWebMessageReceived;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Terminal WebView was unavailable while detaching its message handler.");
            }

            StopAndDetachTimer(
                ref _coalesceTimer,
                OnCoalesceTimerTick,
                "coalesce");
            StopAndDetachTimer(
                ref _outputAcknowledgementTimer,
                OnOutputAcknowledgementTimeout,
                "output acknowledgement");
        }
        catch (Exception ex)
        {
            // Logging/timer/WebView implementations are outside the pump's ownership boundary.
            // None may bypass retirement or strand a producer paused by output backpressure.
            try { _logger.LogDebug(ex, "Terminal bridge ancillary cleanup failed."); }
            catch { /* retirement below remains mandatory */ }
        }
        finally
        {
            retirement = _outputPump.DisposeAndTakeRetirementState();
        }
        return retirement with
        {
            HadUncertainGeometry = hadUncertainGeometry,
        };
    }

    private void StopAndDetachTimer(
        ref DispatcherQueueTimer? timer,
        TypedEventHandler<DispatcherQueueTimer, object> handler,
        string purpose)
    {
        var retiredTimer = timer;
        timer = null;
        if (retiredTimer is null) return;

        try
        {
            retiredTimer.Stop();
            retiredTimer.Tick -= handler;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Terminal {Purpose} timer was unavailable during bridge disposal.", purpose);
        }
    }

    public void Dispose() => _ = DisposeAndTakePendingOutput();

    private bool IsOutputTransportFailed => Volatile.Read(ref _outputTransportFailed) != 0;
}
