using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace Wormhole.Services.Ssh;

internal sealed class SshSession : ISshSession
{
    private readonly SshClient _client;
    private readonly ShellStream _stream;
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger<SshSession> _logger;
    private readonly Task _readPump;
    private int _disposed;

    public SshSession(SshClient client, ShellStream stream, string hostFingerprint, ILogger<SshSession> logger)
    {
        _client = client;
        _stream = stream;
        _logger = logger;
        HostFingerprint = hostFingerprint;
        _readPump = Task.Run(ReadPumpAsync);
    }

    public string HostFingerprint { get; }

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;

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
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested)
        {
            int n;
            try
            {
                n = await _stream.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (Exception ex)
            {
                _logger.LogInformation(ex, "SSH read pump terminated.");
                return;
            }
            if (n <= 0) return;

            var snapshot = new byte[n];
            Array.Copy(buffer, snapshot, n);

            // Subscriber exceptions (e.g. WebView2 disposed mid-send) must not kill the pump.
            try
            {
                DataReceived?.Invoke(this, snapshot);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DataReceived subscriber threw; continuing.");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        try { _cts.Cancel(); } catch { /* already disposed */ }

        try
        {
            await _readPump.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch { /* pump might throw on shutdown; ignore */ }

        try { _stream.Close(); } catch { /* socket may already be torn down */ }
        try { _stream.Dispose(); } catch { /* idempotent */ }

        try
        {
            if (_client.IsConnected) _client.Disconnect();
        }
        catch { /* network already gone */ }
        try { _client.Dispose(); } catch { /* idempotent */ }

        _cts.Dispose();
    }
}
