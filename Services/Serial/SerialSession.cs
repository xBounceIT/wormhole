using System.Buffers;
using System.IO.Ports;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Serial;

internal sealed class SerialSession : ITerminalSession
{
    private readonly ISerialSessionPort _port;
    private readonly SerialFlowControlMode _flowControl;
    private readonly CancellationTokenSource _cts = new();
    private readonly CancellationToken _disposeToken;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ILogger<SerialSession> _logger;
    private static readonly TimeSpan UnexpectedCloseReadDrainTimeout =
        TimeSpan.FromMilliseconds(250);
    private readonly TaskCompletionSource _readPumpCompleted =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _closeOrderingLock = new();
    private int _closedBoundaryReached;
    private const int StateOpen = 0;
    private const int StateUnexpectedlyClosed = 1;
    private const int StateDisposed = 2;
    private int _lifecycleState;
    private int _started;

    private readonly object _readGateLock = new();
    private TaskCompletionSource _readGate = CreateOpenGate();
    private bool _readingPaused;
    private bool _receiveFlowControlFailed;

    public SerialSession(SerialPort port, SerialFlowControlMode flowControl, ILogger<SerialSession> logger)
        : this(
            new SerialSessionPortAdapter(port ?? throw new ArgumentNullException(nameof(port))),
            flowControl,
            logger)
    {
    }

    internal SerialSession(
        ISerialSessionPort port,
        SerialFlowControlMode flowControl,
        ILogger<SerialSession> logger)
    {
        _port = port ?? throw new ArgumentNullException(nameof(port));
        _flowControl = flowControl;
        _logger = new NonThrowingLogger<SerialSession>(logger);
        _disposeToken = _cts.Token;
    }

    public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
    public event EventHandler? Closed;

    public bool IsClosing => IsUnavailable;

    private bool IsUnavailable => Volatile.Read(ref _lifecycleState) != StateOpen;

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        if (IsUnavailable)
        {
            _readPumpCompleted.TrySetResult();
            return;
        }

        try
        {
            _ = Task.Run(ReadPumpAsync);
        }
        catch
        {
            _readPumpCompleted.TrySetResult();
            throw;
        }
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (IsUnavailable || data.Length == 0) return;

        using var linkedCts = cancellationToken.CanBeCanceled
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeToken)
            : null;
        var writeToken = linkedCts?.Token ?? _disposeToken;

        try
        {
            await _writeLock.WaitAsync(writeToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested || IsUnavailable)
        {
            return;
        }

        try
        {
            if (IsUnavailable) return;
            if (_flowControl == SerialFlowControlMode.DsrDtr)
            {
                await WaitForDsrAsync(writeToken).ConfigureAwait(false);
            }
            if (IsUnavailable) return;

            await _port.WriteAsync(data, writeToken).ConfigureAwait(false);
            await _port.FlushAsync(writeToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested || IsUnavailable)
        {
        }
        catch (ObjectDisposedException) when (IsUnavailable)
        {
        }
        catch (InvalidOperationException ex) when (IsUnavailable)
        {
            _logger.LogDebug(ex, "Serial write raced with session close or disposal.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            SignalUnexpectedClose("Serial terminal write failed.", ex);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public Task ResizeAsync(uint columns, uint rows) => Task.CompletedTask;

    public void PauseReading()
    {
        // With no serial flow-control signal there is no way to slow the peer. Parking the read
        // pump would merely let the finite driver buffer overflow and silently discard bytes.
        // Keep draining into the terminal's bounded managed queue; its hard cap fails the session
        // explicitly if the renderer remains stalled.
        if (IsUnavailable || !SupportsReceiveBackpressure(_flowControl)) return;

        Exception? dtrFailure = null;
        lock (_readGateLock)
        {
            if (IsUnavailable || _readingPaused || _receiveFlowControlFailed) return;
            _readingPaused = true;
            if (_readGate.Task.IsCompleted)
            {
                _readGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }

            // Keep the logical gate and the physical DTR transition under one lock. Otherwise a
            // concurrent Resume can set DTR high and a stale Pause can land low afterward.
            if (_flowControl == SerialFlowControlMode.DsrDtr &&
                !TrySetDtr(false, out dtrFailure))
            {
                // The physical line state is unknown. Never leave the read pump parked: release
                // it and fail the session so its owner can close/reopen the port cleanly.
                _readingPaused = false;
                _receiveFlowControlFailed = true;
                _readGate.TrySetResult();
            }
        }

        if (dtrFailure is not null)
        {
            SignalUnexpectedClose("Serial DTR flow-control pause failed.", dtrFailure);
        }
    }

    internal static bool SupportsReceiveBackpressure(SerialFlowControlMode mode) =>
        mode is SerialFlowControlMode.XonXoff or
            SerialFlowControlMode.RtsCts or
            SerialFlowControlMode.DsrDtr;

    internal bool IsReadingPausedForTesting
    {
        get { lock (_readGateLock) return _readingPaused; }
    }

    public void ResumeReading()
    {
        Exception? dtrFailure = null;
        lock (_readGateLock)
        {
            if (IsUnavailable)
            {
                _readingPaused = false;
                _readGate.TrySetResult();
                return;
            }
            if (!_readingPaused) return;

            // Reassert DTR before waking the managed read pump. Even if the hardware transition
            // fails, open the gate so no task remains wedged and fail the session below.
            if (_flowControl == SerialFlowControlMode.DsrDtr &&
                !TrySetDtr(true, out dtrFailure))
            {
                _receiveFlowControlFailed = true;
            }

            _readingPaused = false;
            _readGate.TrySetResult();
        }

        if (dtrFailure is not null)
        {
            SignalUnexpectedClose("Serial DTR flow-control resume failed.", dtrFailure);
        }
    }

    private async Task WaitForDsrAsync(CancellationToken cancellationToken)
    {
        while (!IsUnavailable)
        {
            try
            {
                if (_port.DsrHolding) return;
            }
            catch (InvalidOperationException) when (IsUnavailable)
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
        var ct = _disposeToken;
        byte[]? rentedBuffer = null;
        try
        {
            var buffer = ArrayPool<byte>.Shared.Rent(8192);
            rentedBuffer = buffer;
            while (!ct.IsCancellationRequested && !IsUnavailable)
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
                    n = await _port.ReadAsync(buffer.AsMemory(0, 8192), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested || IsUnavailable) { return; }
                catch (ObjectDisposedException) when (IsUnavailable) { return; }
                catch (InvalidOperationException) when (IsUnavailable) { return; }
                catch (Exception ex)
                {
                    SignalUnexpectedClose("Serial terminal read pump failed.", ex);
                    return;
                }

                if (n <= 0)
                {
                    SignalUnexpectedClose("Serial terminal stream returned EOF.");
                    return;
                }

                RaiseReadPumpDataReceived(buffer.AsMemory(0, n));
            }
        }
        catch (Exception ex)
        {
            SignalUnexpectedClose("Serial terminal read pump failed.", ex);
        }
        finally
        {
            if (rentedBuffer is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedBuffer);
            }
            _readPumpCompleted.TrySetResult();
        }
    }

    private void SignalUnexpectedClose(string reason, Exception? exception = null)
    {
        // One atomic lifecycle transition distinguishes a real transport failure from local
        // disposal. Publish unavailability and cancel new I/O immediately. Closed is deferred
        // until the read pump drains its already-completed read (or a bounded timeout), so its
        // final bytes cannot appear in the shell after the close notification.
        if (Interlocked.CompareExchange(
                ref _lifecycleState,
                StateUnexpectedlyClosed,
                StateOpen) != StateOpen)
        {
            return;
        }

        try { _cts.Cancel(); } catch { /* disposal won the race after the state transition */ }
        lock (_readGateLock)
        {
            _readingPaused = false;
            _readGate.TrySetResult();
        }

        if (exception is null)
        {
            _logger.LogInformation("{Reason} Port={PortName}.", reason, _port.PortName);
        }
        else
        {
            _logger.LogInformation(exception, "{Reason} Port={PortName}.", reason, _port.PortName);
        }

        _ = CompleteUnexpectedCloseAsync();
    }

    private async Task CompleteUnexpectedCloseAsync()
    {
        if (Volatile.Read(ref _started) != 0)
        {
            try
            {
                await _readPumpCompleted.Task
                    .WaitAsync(UnexpectedCloseReadDrainTimeout)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _logger.LogDebug(
                    "Timed out waiting for the serial read pump before publishing Closed. Port={PortName}.",
                    _port.PortName);
            }
        }

        RaiseClosedOnce();
    }

    private void RaiseClosedOnce()
    {
        EventHandler? handlers;
        lock (_closeOrderingLock)
        {
            if (_closedBoundaryReached != 0 ||
                Volatile.Read(ref _lifecycleState) == StateDisposed)
            {
                return;
            }

            _closedBoundaryReached = 1;
            handlers = Closed;
        }

        if (handlers is null) return;
        foreach (EventHandler handler in handlers.GetInvocationList())
        {
            try { handler(this, EventArgs.Empty); }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Serial Closed subscriber threw; continuing with remaining subscribers.");
            }
        }
    }

    internal void RaiseDataReceived(ReadOnlyMemory<byte> data) =>
        PublishDataReceived(data, allowUnexpectedlyClosed: false);

    private void RaiseReadPumpDataReceived(ReadOnlyMemory<byte> data) =>
        PublishDataReceived(data, allowUnexpectedlyClosed: true);

    private void PublishDataReceived(
        ReadOnlyMemory<byte> data,
        bool allowUnexpectedlyClosed)
    {
        if (data.IsEmpty) return;

        // Serialize the final read with the Closed boundary. The read pump may publish one read
        // that completed before cancellation became observable; synthetic/post-close publishers
        // remain rejected. Handler-by-handler isolation prevents one consumer starving the rest.
        lock (_closeOrderingLock)
        {
            var state = Volatile.Read(ref _lifecycleState);
            if (_closedBoundaryReached != 0 ||
                (state != StateOpen &&
                 !(allowUnexpectedlyClosed && state == StateUnexpectedlyClosed)))
            {
                return;
            }

            var handlers = DataReceived;
            if (handlers is null) return;
            foreach (EventHandler<ReadOnlyMemory<byte>> handler in handlers.GetInvocationList())
            {
                try
                {
                    handler(this, data);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "Serial DataReceived subscriber threw; continuing with remaining subscribers.");
                }
            }
        }
    }

    private bool TrySetDtr(bool enabled, out Exception? failure)
    {
        try
        {
            _port.DtrEnable = enabled;
            failure = null;
            return true;
        }
        catch (Exception ex)
        {
            failure = ex;
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_closeOrderingLock)
        {
            if (Interlocked.Exchange(ref _lifecycleState, StateDisposed) == StateDisposed)
                return;

            // Disposal is a terminal boundary but is intentionally not an unexpected Closed event.
            _closedBoundaryReached = 1;
        }

        if (Volatile.Read(ref _started) == 0)
        {
            _readPumpCompleted.TrySetResult();
        }

        try { _cts.Cancel(); } catch { /* already disposed */ }
        lock (_readGateLock) { _readingPaused = false; _readGate.TrySetResult(); }

        try { _port.Close(); } catch { /* best effort */ }
        try { _port.Dispose(); } catch { /* best effort */ }

        try
        {
            await _readPumpCompleted.Task
                .WaitAsync(UnexpectedCloseReadDrainTimeout)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // A broken driver may ignore cancellation/Close. The closed boundary above still
            // prevents a late completion from publishing bytes into a disposed session.
        }

        try { _cts.Dispose(); } catch { /* best effort */ }
    }
}

internal interface ISerialSessionPort : IDisposable
{
    string PortName { get; }
    bool DsrHolding { get; }
    bool DtrEnable { set; }
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
    Task FlushAsync(CancellationToken cancellationToken);
    void Close();
}

internal sealed class SerialSessionPortAdapter(SerialPort port) : ISerialSessionPort
{
    public string PortName => port.PortName;
    public bool DsrHolding => port.DsrHolding;
    public bool DtrEnable { set => port.DtrEnable = value; }

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        port.BaseStream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        port.BaseStream.WriteAsync(data, cancellationToken);

    public Task FlushAsync(CancellationToken cancellationToken) =>
        port.BaseStream.FlushAsync(cancellationToken);

    public void Close() => port.Close();
    public void Dispose() => port.Dispose();
}
