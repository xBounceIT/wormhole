using System.Buffers;
using System.IO.Ports;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services.Serial;

internal sealed class SerialSession : ITerminalSession
{
    private readonly SerialPort _port;
    private readonly SerialFlowControlMode _flowControl;
    private readonly CancellationTokenSource _cts = new();
    private readonly CancellationToken _disposeToken;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ILogger<SerialSession> _logger;
    private Task? _readPump;
    private int _disposed;
    private int _started;

    private readonly object _readGateLock = new();
    private TaskCompletionSource _readGate = CreateOpenGate();
    private bool _readingPaused;

    private readonly object _lineStateLock = new();

    public SerialSession(SerialPort port, SerialFlowControlMode flowControl, ILogger<SerialSession> logger)
    {
        _port = port;
        _flowControl = flowControl;
        _logger = logger;
        _disposeToken = _cts.Token;
    }

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    public event EventHandler? Closed;

    private bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        if (IsDisposed) return;
        _readPump = Task.Run(ReadPumpAsync);
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (IsDisposed || data.Length == 0) return;

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
            if (IsDisposed) return;
            if (_flowControl == SerialFlowControlMode.DsrDtr)
            {
                await WaitForDsrAsync(writeToken).ConfigureAwait(false);
            }

            await _port.BaseStream.WriteAsync(data, writeToken).ConfigureAwait(false);
            await _port.BaseStream.FlushAsync(writeToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested || IsDisposed)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException ex) when (IsDisposed)
        {
            _logger.LogDebug(ex, "Serial write raced with disposal.");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public Task ResizeAsync(uint columns, uint rows) => Task.CompletedTask;

    public void PauseReading()
    {
        if (IsDisposed) return;
        lock (_readGateLock)
        {
            if (_readingPaused) return;
            _readingPaused = true;
            if (_readGate.Task.IsCompleted)
            {
                _readGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        if (_flowControl == SerialFlowControlMode.DsrDtr)
        {
            SetDtr(false);
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

        if (_flowControl == SerialFlowControlMode.DsrDtr)
        {
            SetDtr(true);
        }
    }

    private async Task WaitForDsrAsync(CancellationToken cancellationToken)
    {
        while (!IsDisposed)
        {
            try
            {
                if (_port.DsrHolding) return;
            }
            catch (InvalidOperationException) when (IsDisposed)
            {
                return;
            }

            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
    }

    private static TaskCompletionSource CreateOpenGate()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
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
                    n = await _port.BaseStream.ReadAsync(buffer.AsMemory(0, 8192), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (InvalidOperationException) { return; }
                catch (Exception ex)
                {
                    _logger.LogInformation(ex, "Serial read pump terminated for {PortName}.", _port.PortName);
                    remoteClosed = true;
                    return;
                }

                if (n <= 0)
                {
                    remoteClosed = true;
                    return;
                }

                try
                {
                    DataReceived?.Invoke(this, buffer.AsMemory(0, n));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Serial DataReceived subscriber threw; continuing.");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            if (remoteClosed && !IsDisposed)
            {
                try { Closed?.Invoke(this, EventArgs.Empty); }
                catch (Exception ex) { _logger.LogWarning(ex, "Serial Closed subscriber threw."); }
            }
        }
    }

    private void SetDtr(bool enabled)
    {
        lock (_lineStateLock)
        {
            if (IsDisposed) return;
            try { _port.DtrEnable = enabled; }
            catch (Exception ex) { _logger.LogDebug(ex, "Failed to set DTR={Enabled}.", enabled); }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        try { _cts.Cancel(); } catch { /* already disposed */ }
        lock (_readGateLock) { _readingPaused = false; _readGate.TrySetResult(); }

        try { _port.Close(); } catch { /* best effort */ }
        try { _port.Dispose(); } catch { /* best effort */ }

        if (_readPump is not null)
        {
            try { await _readPump.WaitAsync(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false); }
            catch { /* pump might throw on shutdown; ignore */ }
        }

        try { _cts.Dispose(); } catch { /* best effort */ }
    }
}
