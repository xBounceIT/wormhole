using System.Buffers;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace Wormhole.Services.Ssh;

internal sealed class SshSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ShellStream _stream;
    private readonly CancellationTokenSource _cts = new();
    // ShellStream's write buffer is not safe for concurrent access — SSH.NET's internal
    // _sync lock guards reads and disposal only. Serialize all writes through this gate so
    // overlapping callers can't corrupt the shared buffer (see WriteAsync).
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ILogger<SshSession> _logger;
    private Task? _readPump;
    private int _disposed;
    private int _started;

    // Terminal flow-control gate. The read pump awaits this before each read; a *completed* gate
    // (the default) means "reading allowed". PauseReading swaps in an uncompleted TCS to park the
    // pump so the SSH channel window fills and back-pressures the remote producer; ResumeReading
    // completes the TCS to release it. Guarded by _readGateLock. See ISshSession.PauseReading.
    private readonly object _readGateLock = new();
    private TaskCompletionSource _readGate = CreateOpenGate();
    private bool _readingPaused;

    public SshSession(SshClient client, ShellStream stream, string hostFingerprint, ILogger<SshSession> logger)
    {
        _client = client;
        _stream = stream;
        _logger = logger;
        HostFingerprint = hostFingerprint;
    }

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        if (IsDisposed) return;
        _readPump = Task.Run(ReadPumpAsync);
    }

    public string HostFingerprint { get; }

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    public event EventHandler? Closed;

    private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (IsDisposed) return;

        // Writes reach this method from two unsynchronized sources: the WebView2 message
        // handler (TerminalBridge.OnWebMessageReceived is async void, so it yields to the UI
        // message pump at each await and a second keystroke handler can start before the first
        // write finishes) and SshAutoSudoDriver's fire-and-forget line sends from the read-pump
        // thread. ShellStream.WriteAsync/FlushAsync mutate a shared write buffer with no locking,
        // so two overlapping writes scramble its offset/length bookkeeping and a byte gets dropped
        // or never flushed — most visibly the lone "\r" from Enter, which strands the user at a
        // prompt. Hold the gate across both the write and the flush so each write+flush is atomic.
        try
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return; }

        try
        {
            if (IsDisposed) return;
            await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) { /* raced with Dispose */ }
        finally
        {
            _writeLock.Release();
        }
    }

    public Task ResizeAsync(uint columns, uint rows)
    {
        if (IsDisposed) return Task.CompletedTask;
        try
        {
            _stream.ChangeWindowSize(columns, rows, 0, 0);
        }
        catch (ObjectDisposedException) { /* raced with Dispose */ }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ChangeWindowSize failed for {Cols}x{Rows}.", columns, rows);
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
        if (IsDisposed) return;
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
        var remoteClosed = false;
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
                    _logger.LogInformation(ex, "SSH read pump terminated.");
                    remoteClosed = true;
                    return;
                }
                if (n <= 0)
                {
                    remoteClosed = true;
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
            // Only surface Closed if the *remote* end ended the session. Our own
            // DisposeAsync cancels the CTS first; we don't want to fire Closed on a
            // user-initiated tear-down (the VM is already managing that state).
            if (remoteClosed && !IsDisposed)
            {
                try { Closed?.Invoke(this, EventArgs.Empty); }
                catch (Exception ex) { _logger.LogWarning(ex, "Closed subscriber threw."); }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        // PuTTY-style teardown: yank the channel first so the read pump's blocked
        // ShellStream.ReadAsync surfaces ObjectDisposedException immediately
        // (caught at the pump's catch block) and exits in microseconds. The CTS
        // alone takes 100-500 ms to propagate through SSH.NET's internal polling,
        // which the user perceives as lag on tab-context-menu Reconnect.
        try { _cts.Cancel(); } catch { /* already disposed */ }
        // Release a pump parked on the flow-control gate so it observes cancellation immediately.
        // WaitAsync(ct) would also throw on cancel, but completing the gate avoids depending solely
        // on that and is harmless (TrySetResult no-ops) when the pump isn't parked.
        lock (_readGateLock) { _readingPaused = false; _readGate.TrySetResult(); }
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
}
