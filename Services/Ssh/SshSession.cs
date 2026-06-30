using System.Buffers;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Wormhole.Services.Ssh;

internal sealed class SshSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ISshSessionStream _stream;
    private readonly CancellationTokenSource _cts = new();
    private readonly CancellationToken _disposeToken;
    // ShellStream's write buffer is not safe for concurrent access — SSH.NET's internal
    // _sync lock guards reads and disposal only. Serialize all writes through this gate so
    // overlapping callers can't corrupt the shared buffer (see WriteAsync).
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ILogger<SshSession> _logger;
    private readonly object _closedHandlersLock = new();
    private EventHandler? _closedHandlers;
    private Task? _readPump;
    private int _disposed;
    private int _remoteClosed;
    private int _closedRaised;
    private int _started;

    // Terminal flow-control gate. The read pump awaits this before each read; a *completed* gate
    // (the default) means "reading allowed". PauseReading swaps in an uncompleted TCS to park the
    // pump so the SSH channel window fills and back-pressures the remote producer; ResumeReading
    // completes the TCS to release it. Guarded by _readGateLock. See ISshSession.PauseReading.
    private readonly object _readGateLock = new();
    private TaskCompletionSource _readGate = CreateOpenGate();
    private bool _readingPaused;

    public SshSession(SshClient client, ShellStream stream, string hostFingerprint, ILogger<SshSession> logger)
        : this(client, new ShellStreamAdapter(stream), hostFingerprint, logger)
    {
    }

    internal SshSession(SshClient client, ISshSessionStream stream, string hostFingerprint, ILogger<SshSession> logger)
    {
        _client = client;
        _stream = stream;
        _logger = logger;
        HostFingerprint = hostFingerprint;
        _disposeToken = _cts.Token;
        _client.ErrorOccurred += OnClientErrorOccurred;
        _stream.Closed += OnStreamClosed;
        _stream.ErrorOccurred += OnStreamErrorOccurred;
    }

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        if (IsUnavailable) return;
        _readPump = Task.Run(ReadPumpAsync);
    }

    public string HostFingerprint { get; }

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    public event EventHandler? Closed
    {
        add
        {
            if (value is null) return;

            var invokeImmediately = false;
            lock (_closedHandlersLock)
            {
                if (IsClosedRaised && !IsDisposed)
                {
                    invokeImmediately = true;
                }
                else
                {
                    _closedHandlers += value;
                }
            }

            if (invokeImmediately)
            {
                InvokeClosedHandler(value);
            }
        }
        remove
        {
            if (value is null) return;
            lock (_closedHandlersLock) _closedHandlers -= value;
        }
    }

    private bool IsDisposed => Volatile.Read(ref _disposed) != 0;
    private bool IsRemoteClosed => Volatile.Read(ref _remoteClosed) != 0;
    private bool IsClosedRaised => Volatile.Read(ref _closedRaised) != 0;
    private bool IsUnavailable => IsDisposed || IsRemoteClosed;

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (IsUnavailable) return;

        // Writes reach this method from two unsynchronized sources: the WebView2 message
        // handler (TerminalBridge.OnWebMessageReceived is async void, so it yields to the UI
        // message pump at each await and a second keystroke handler can start before the first
        // write finishes) and SshAutoSudoDriver's fire-and-forget line sends from the read-pump
        // thread. ShellStream.WriteAsync/FlushAsync mutate a shared write buffer with no locking,
        // so two overlapping writes scramble its offset/length bookkeeping and a byte gets dropped
        // or never flushed — most visibly the lone "\r" from Enter, which strands the user at a
        // prompt. Hold the gate across both the write and the flush so each write+flush is atomic.
        using var linkedCts = cancellationToken.CanBeCanceled
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeToken)
            : null;
        var writeToken = linkedCts?.Token ?? _disposeToken;

        try
        {
            await _writeLock.WaitAsync(writeToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return; }

        try
        {
            if (IsUnavailable) return;
            await _stream.WriteAsync(data, writeToken).ConfigureAwait(false);
            await _stream.FlushAsync(writeToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested || IsUnavailable)
        {
            // DisposeAsync cancels the session token so active writes and queued waiters can unwind
            // even when callers used the default, non-cancelable token.
        }
        catch (ObjectDisposedException) when (IsDisposed)
        {
            // Raced with DisposeAsync.
        }
        catch (Exception ex)
        {
            SignalRemoteClosed("write to SSH shell failed", ex);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public Task ResizeAsync(uint columns, uint rows)
    {
        if (IsUnavailable) return Task.CompletedTask;
        try
        {
            _stream.ChangeWindowSize(columns, rows, 0, 0);
        }
        catch (ObjectDisposedException) when (IsDisposed)
        {
            // Raced with DisposeAsync.
        }
        catch (Exception ex)
        {
            SignalRemoteClosed($"resize of SSH shell to {columns}x{rows} failed", ex);
        }
        return Task.CompletedTask;
    }

    private static TaskCompletionSource CreateOpenGate()
    {
        // RunContinuationsAsynchronously: the pump's awaiter must not run inline on whichever
        // thread completes the gate (ResumeReading runs on the UI thread) — that would hijack the
        // UI thread to run the SSH read loop.
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
    }

    public void PauseReading()
    {
        if (IsUnavailable) return;
        lock (_readGateLock)
        {
            if (_readingPaused) return;
            _readingPaused = true;
            // Install a fresh uncompleted gate only when the current one is open (completed); if a
            // prior pause already swapped in an uncompleted gate we keep parking on it.
            if (_readGate.Task.IsCompleted)
            {
                _readGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
    }

    public void ResumeReading()
    {
        lock (_readGateLock)
        {
            if (!_readingPaused) return;
            _readingPaused = false;
            _readGate.TrySetResult();
        }
    }

    private async Task ReadPumpAsync()
    {
        var ct = _cts.Token;
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // Flow control: a consumer (TerminalBridge) parks the pump here when xterm.js falls
                // behind, so the SSH channel window — and thus the remote producer — is throttled
                // instead of xterm buffering unboundedly to its discard limit. Released by
                // ResumeReading, or by cancellation on teardown (WaitAsync observes ct).
                Task gate;
                lock (_readGateLock) gate = _readGate.Task;
                if (!gate.IsCompleted)
                {
                    try { await gate.WaitAsync(ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }
                }

                int n;
                try
                {
                    n = await _stream.ReadAsync(buffer.AsMemory(0, 8192), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (Exception ex)
                {
                    // Treat unexpected I/O failures as a remote-side disconnect so the VM
                    // doesn't lie to the user about an active session.
                    SignalRemoteClosed("SSH read pump terminated", ex);
                    return;
                }
                if (n <= 0)
                {
                    SignalRemoteClosed("SSH shell returned EOF");
                    return;
                }

                // Subscriber exceptions (e.g. WebView2 disposed mid-send) must not kill the pump.
                // The event is synchronous and its memory is valid only until Invoke returns.
                // Current subscribers copy immediately into their replay/coalescing buffers,
                // avoiding a per-read allocation here while keeping retained data safe.
                try
                {
                    DataReceived?.Invoke(this, buffer.AsMemory(0, n));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "DataReceived subscriber threw; continuing.");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        _client.ErrorOccurred -= OnClientErrorOccurred;
        _stream.Closed -= OnStreamClosed;
        _stream.ErrorOccurred -= OnStreamErrorOccurred;

        // PuTTY-style teardown: yank the channel first so the read pump's blocked
        // ShellStream.ReadAsync surfaces ObjectDisposedException immediately
        // (caught at the pump's catch block) and exits in microseconds. The CTS
        // alone takes 100-500 ms to propagate through SSH.NET's internal polling,
        // which the user perceives as lag on tab-context-menu Reconnect.
        try { _cts.Cancel(); } catch { /* already disposed */ }
        // Release a pump parked on the flow-control gate so it observes cancellation immediately.
        // WaitAsync(ct) would also throw on cancel, but completing the gate avoids depending solely
        // on that and is harmless (TrySetResult no-ops) when the pump isn't parked.
        ReleaseReadGate();
        try { _stream.Close(); } catch { /* socket may already be torn down */ }
        try { _stream.Dispose(); } catch { /* idempotent */ }

        if (_readPump is not null)
        {
            try
            {
                await _readPump.WaitAsync(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false);
            }
            catch { /* pump might throw on shutdown; ignore */ }
        }

        // SshClient.Disconnect does a synchronous SSH_MSG_DISCONNECT round-trip and
        // Dispose can block on socket teardown. Both are pointless to wait for on
        // the reconnect path — the channel is already dead. Fire-and-forget.
        var client = _client;
        var cts = _cts;
        _ = Task.Run(() =>
        {
            try { if (client.IsConnected) client.Disconnect(); } catch { /* network already gone */ }
            try { client.Dispose(); } catch { /* idempotent */ }
            try { cts.Dispose(); } catch { /* idempotent */ }
        });

        // _writeLock is intentionally NOT disposed: an in-flight WriteAsync still needs to
        // Release() it in its finally, and Release/WaitAsync on a disposed SemaphoreSlim throws
        // ObjectDisposedException — worse, Dispose doesn't wake a queued waiter, which would
        // strand it. It holds no OS handle unless AvailableWaitHandle is touched (we never do),
        // so GC reclaims it harmlessly. Mirrors FileTransferOrchestrator's gate convention.
    }

    private void OnClientErrorOccurred(object? sender, ExceptionEventArgs e) =>
        SignalRemoteClosed("SSH client reported an error", e.Exception);

    private void OnStreamClosed(object? sender, EventArgs e) =>
        SignalRemoteClosed("SSH shell stream closed", drainBufferedOutput: true);

    private void OnStreamErrorOccurred(object? sender, Exception e) =>
        SignalRemoteClosed("SSH shell stream reported an error", e, drainBufferedOutput: true);

    private void SignalRemoteClosed(string reason, Exception? exception = null, bool drainBufferedOutput = false)
    {
        if (IsDisposed) return;
        if (Interlocked.Exchange(ref _remoteClosed, 1) != 0)
        {
            if (!drainBufferedOutput || _readPump is not { IsCompleted: false })
            {
                CompleteRemoteClosed();
            }
            return;
        }

        if (exception is null)
        {
            _logger.LogInformation("SSH session closed: {Reason}.", reason);
        }
        else
        {
            _logger.LogInformation(exception, "SSH session closed: {Reason}.", reason);
        }

        ReleaseReadGate();
        if (drainBufferedOutput && _readPump is { IsCompleted: false })
        {
            return;
        }

        CompleteRemoteClosed();
    }

    private void CompleteRemoteClosed()
    {
        if (IsDisposed) return;
        if (Interlocked.Exchange(ref _closedRaised, 1) != 0) return;

        try { _cts.Cancel(); } catch { /* already disposed */ }
        ReleaseReadGate();
        try { _stream.Close(); } catch { /* best effort: stream is already unhealthy */ }

        EventHandler? handlers;
        lock (_closedHandlersLock) handlers = _closedHandlers;
        if (handlers is null) return;

        try { handlers.Invoke(this, EventArgs.Empty); }
        catch (Exception ex) { _logger.LogWarning(ex, "Closed subscriber threw."); }
    }

    private void ReleaseReadGate()
    {
        lock (_readGateLock)
        {
            _readingPaused = false;
            _readGate.TrySetResult();
        }
    }

    private void InvokeClosedHandler(EventHandler handler)
    {
        if (IsDisposed) return;
        try { handler(this, EventArgs.Empty); }
        catch (Exception ex) { _logger.LogWarning(ex, "Closed subscriber threw."); }
    }
}

internal interface ISshSessionStream : IDisposable
{
    event EventHandler? Closed;
    event EventHandler<Exception>? ErrorOccurred;
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
    Task FlushAsync(CancellationToken cancellationToken);
    void ChangeWindowSize(uint columns, uint rows, uint width, uint height);
    void Close();
}

internal sealed class ShellStreamAdapter : ISshSessionStream
{
    private readonly ShellStream _stream;

    public ShellStreamAdapter(ShellStream stream)
    {
        _stream = stream;
        _stream.Closed += OnClosed;
        _stream.ErrorOccurred += OnErrorOccurred;
    }

    public event EventHandler? Closed;
    public event EventHandler<Exception>? ErrorOccurred;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        _stream.WriteAsync(data, cancellationToken);

    public Task FlushAsync(CancellationToken cancellationToken) =>
        _stream.FlushAsync(cancellationToken);

    public void ChangeWindowSize(uint columns, uint rows, uint width, uint height) =>
        _stream.ChangeWindowSize(columns, rows, width, height);

    public void Close() => _stream.Close();

    public void Dispose()
    {
        _stream.Closed -= OnClosed;
        _stream.ErrorOccurred -= OnErrorOccurred;
        _stream.Dispose();
    }

    private void OnClosed(object? sender, EventArgs e) =>
        Closed?.Invoke(this, EventArgs.Empty);

    private void OnErrorOccurred(object? sender, ExceptionEventArgs e) =>
        ErrorOccurred?.Invoke(this, e.Exception);
}
