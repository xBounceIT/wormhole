using System.Buffers;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace Wormhole.Services.Ssh;

internal sealed class SshSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ShellStream _stream;
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger<SshSession> _logger;
    private Task? _readPump;
    private int _disposed;
    private int _started;

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
        try
        {
            await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) { /* raced with Dispose */ }
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

    private async Task ReadPumpAsync()
    {
        var ct = _cts.Token;
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        var remoteClosed = false;
        try
        {
            while (!ct.IsCancellationRequested)
            {
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
    }
}
