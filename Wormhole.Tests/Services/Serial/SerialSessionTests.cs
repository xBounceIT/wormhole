using System.IO.Ports;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Services.Serial;

public sealed class SerialSessionTests
{
    [Theory]
    [InlineData(SerialFlowControlMode.None, false)]
    [InlineData(SerialFlowControlMode.XonXoff, true)]
    [InlineData(SerialFlowControlMode.RtsCts, true)]
    [InlineData(SerialFlowControlMode.DsrDtr, true)]
    [InlineData((SerialFlowControlMode)999, false)]
    public void SupportsReceiveBackpressure_OnlyForControlledModes(
        SerialFlowControlMode mode,
        bool expected)
    {
        Assert.Equal(expected, SerialSession.SupportsReceiveBackpressure(mode));
    }

    [Fact]
    public async Task DisposeAsync_CancelsActiveAndQueuedWritesGracefully()
    {
        var port = new TestSerialSessionPort { CancelFirstWrite = true };
        var session = CreateSession(port, SerialFlowControlMode.None);

        var activeWrite = session.WriteAsync(new byte[] { 0x01 });
        await port.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var queuedWrite = session.WriteAsync(new byte[] { 0x02 });
        Assert.False(queuedWrite.IsCompleted);

        await session.DisposeAsync();

        await activeWrite.WaitAsync(TimeSpan.FromSeconds(1));
        await queuedWrite.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(port.FirstWriteToken.IsCancellationRequested);
        Assert.Equal(1, port.WriteCalls);
        Assert.Equal(1, port.CloseCalls);
    }

    [Fact]
    public async Task WriteAsync_CallerCancellationDuringActiveWrite_PropagatesWithoutClosingSession()
    {
        var port = new TestSerialSessionPort { CancelFirstWrite = true };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var closedCount = 0;
        session.Closed += (_, _) => Interlocked.Increment(ref closedCount);
        using var callerCts = new CancellationTokenSource();

        var write = session.WriteAsync(new byte[] { 0x01 }, callerCts.Token);
        await port.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        callerCts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => write);
        Assert.Equal(0, Volatile.Read(ref closedCount));
        Assert.Equal(0, port.CloseCalls);

        await session.WriteAsync(new byte[] { 0x02 });
        Assert.Equal(2, port.WriteCalls);
    }

    [Fact]
    public async Task WriteAsync_CallerCancellationWhileQueued_PropagatesWithoutClosingSession()
    {
        var port = new TestSerialSessionPort { GateFirstWrite = true };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var closedCount = 0;
        session.Closed += (_, _) => Interlocked.Increment(ref closedCount);

        var activeWrite = session.WriteAsync(new byte[] { 0x01 });
        await port.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        using var callerCts = new CancellationTokenSource();
        var queuedWrite = session.WriteAsync(new byte[] { 0x02 }, callerCts.Token);
        Assert.False(queuedWrite.IsCompleted);

        callerCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queuedWrite);
        Assert.Equal(0, Volatile.Read(ref closedCount));
        Assert.Equal(0, port.CloseCalls);

        port.ReleaseFirstWrite.TrySetResult();
        await activeWrite.WaitAsync(TimeSpan.FromSeconds(1));
        await session.WriteAsync(new byte[] { 0x03 });
        Assert.Equal(2, port.WriteCalls);
    }

    [Fact]
    public async Task WriteFailure_CancelsQueuedWritesAndRejectsLaterInput()
    {
        var failure = new IOException("serial write failed");
        var port = new TestSerialSessionPort
        {
            GateFirstWrite = true,
            FirstWriteException = failure,
        };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closedCount = 0;
        session.Closed += (_, _) =>
        {
            Interlocked.Increment(ref closedCount);
            closed.TrySetResult();
        };

        var activeWrite = session.WriteAsync(new byte[] { 0x01 });
        await port.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var queuedWrite = session.WriteAsync(new byte[] { 0x02 });
        Assert.False(queuedWrite.IsCompleted);

        port.ReleaseFirstWrite.TrySetResult();
        var thrown = await Assert.ThrowsAsync<IOException>(() => activeWrite);
        await queuedWrite.WaitAsync(TimeSpan.FromSeconds(1));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await session.WriteAsync(new byte[] { 0x03 });

        Assert.Same(failure, thrown);
        Assert.Equal(1, port.WriteCalls);
        Assert.Equal(1, Volatile.Read(ref closedCount));
    }

    [Fact]
    public async Task DtrFailure_CancelsReadPumpAndRejectsFurtherIo()
    {
        var failure = new IOException("DTR low failed");
        var port = new TestSerialSessionPort
        {
            BlockReads = true,
            DtrSetter = enabled => { if (!enabled) throw failure; },
        };
        await using var session = CreateSession(port, SerialFlowControlMode.DsrDtr);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();
        await port.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        session.PauseReading();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await port.ReadCanceled.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await session.WriteAsync(new byte[] { 0x01 });
        session.ResumeReading();
        session.PauseReading();

        Assert.True(port.LastReadToken.IsCancellationRequested);
        Assert.Equal(1, port.ReadCalls);
        Assert.Equal(0, port.WriteCalls);
        Assert.Collection(port.DtrTransitions, transition => Assert.False(transition));
    }

    [Fact]
    public async Task ReadFailure_MarksUnavailableBeforeClosedAndRejectsLaterWrite()
    {
        var port = new TestSerialSessionPort
        {
            ReadException = new IOException("serial device removed"),
        };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closedCount = 0;
        session.Closed += (_, _) =>
        {
            Interlocked.Increment(ref closedCount);
            closed.TrySetResult();
        };

        session.Start();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await session.WriteAsync(new byte[] { 0x01 });
        session.RaiseDataReceived(new byte[] { 0x02 });

        Assert.True(port.LastReadToken.IsCancellationRequested);
        Assert.Equal(1, port.ReadCalls);
        Assert.Equal(0, port.WriteCalls);
        Assert.Equal(1, Volatile.Read(ref closedCount));
    }

    [Fact]
    public async Task ReadFailure_ThrowingLoggerStillNotifiesLaterSubscriber()
    {
        var port = new TestSerialSessionPort
        {
            ReadException = new IOException("serial device removed"),
        };
        await using var session = CreateSession(
            port,
            SerialFlowControlMode.None,
            new ThrowingLogger<SerialSession>());
        var laterSubscriber = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        session.Closed += (_, _) => throw new InvalidOperationException("broken subscriber");
        session.Closed += (_, _) => laterSubscriber.TrySetResult();

        session.Start();

        await laterSubscriber.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(port.LastReadToken.IsCancellationRequested);
        Assert.Equal(1, port.ReadCalls);
    }

    [Fact]
    public async Task DsrDtr_PauseAndConcurrentResume_ApplyPhysicalTransitionsInOrder()
    {
        using var pauseEntered = new ManualResetEventSlim();
        using var allowPauseToFinish = new ManualResetEventSlim();
        var port = new TestSerialSessionPort
        {
            DtrSetter = enabled =>
            {
                if (enabled) return;
                pauseEntered.Set();
                Assert.True(allowPauseToFinish.Wait(TimeSpan.FromSeconds(5)));
            },
        };
        await using var session = CreateSession(port, SerialFlowControlMode.DsrDtr);

        var pauseTask = Task.Factory.StartNew(
            session.PauseReading,
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        Assert.True(pauseEntered.Wait(TimeSpan.FromSeconds(1)));
        var resumeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumeTask = Task.Factory.StartNew(
            () =>
            {
                resumeStarted.TrySetResult();
                session.ResumeReading();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        await resumeStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(resumeTask.IsCompleted);

        allowPauseToFinish.Set();
        await Task.WhenAll(pauseTask, resumeTask).WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Collection(
            port.DtrTransitions,
            transition => Assert.False(transition),
            transition => Assert.True(transition));
        Assert.False(session.IsReadingPausedForTesting);
    }

    [Fact]
    public async Task DsrDtr_PauseTransitionFailure_ReleasesGateAndRaisesClosed()
    {
        var failure = new IOException("DTR low failed");
        var port = new TestSerialSessionPort
        {
            DtrSetter = enabled => { if (!enabled) throw failure; },
        };
        await using var session = CreateSession(port, SerialFlowControlMode.DsrDtr);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(session.IsReadingPausedForTesting);
        session.PauseReading();
        Assert.Collection(
            port.DtrTransitions,
            transition => Assert.False(transition));
    }

    [Fact]
    public async Task DsrDtr_ResumeTransitionFailure_ReleasesGateAndRaisesClosed()
    {
        var failure = new IOException("DTR high failed");
        var port = new TestSerialSessionPort
        {
            DtrSetter = enabled => { if (enabled) throw failure; },
        };
        await using var session = CreateSession(port, SerialFlowControlMode.DsrDtr);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();
        Assert.True(session.IsReadingPausedForTesting);
        session.ResumeReading();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(session.IsReadingPausedForTesting);
        session.PauseReading();
        Assert.Collection(
            port.DtrTransitions,
            transition => Assert.False(transition),
            transition => Assert.True(transition));
    }

    [Fact]
    public async Task WriteFailure_ReadAlreadyCompletedPublishesTailBeforeClosed()
    {
        var tail = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J', (byte)'x' };
        var port = new TestSerialSessionPort
        {
            GateReadCompletion = true,
            ReadPayload = tail,
            FirstWriteException = new IOException("serial write failed"),
        };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var events = new List<string>();
        var received = new List<byte>();
        var closed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += (_, data) =>
        {
            events.Add("data");
            received.AddRange(data.ToArray());
        };
        session.Closed += (_, _) =>
        {
            events.Add("closed");
            closed.TrySetResult();
        };

        session.Start();
        await port.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<IOException>(
            () => session.WriteAsync(new byte[] { 0x01 }));
        port.ReleaseRead.TrySetResult();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(tail, received);
        Assert.Collection(
            events,
            item => Assert.Equal("data", item),
            item => Assert.Equal("closed", item));
    }

    [Fact]
    public async Task UnexpectedCloseTimeout_DropsReadCompletedAfterClosedAndDispose()
    {
        var port = new TestSerialSessionPort
        {
            GateReadCompletion = true,
            ReadPayload = new byte[] { (byte)'l', (byte)'a', (byte)'t', (byte)'e' },
            FirstWriteException = new IOException("serial write failed"),
        };
        await using var session = CreateSession(port, SerialFlowControlMode.None);
        var received = new List<byte>();
        var closedCount = 0;
        var closed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += (_, data) => received.AddRange(data.ToArray());
        session.Closed += (_, _) =>
        {
            Interlocked.Increment(ref closedCount);
            closed.TrySetResult();
        };

        session.Start();
        await port.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<IOException>(
            () => session.WriteAsync(new byte[] { 0x01 }));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(2));

        session.RaiseDataReceived(new byte[] { (byte)'x' });
        port.ReleaseRead.TrySetResult();
        await session.DisposeAsync();

        Assert.Empty(received);
        Assert.Equal(1, Volatile.Read(ref closedCount));
    }

    [Fact]
    public async Task DataReceived_ThrowingSubscriber_DoesNotStarveLaterSubscribers()
    {
        using var port = new SerialPort();
        await using var session = new SerialSession(
            port,
            SerialFlowControlMode.None,
            NullLogger<SerialSession>.Instance);
        var payload = new byte[] { 0x00, 0x7f, 0xff };
        var throwingSubscriberCalls = 0;
        byte[]? received = null;

        session.DataReceived += (_, _) =>
        {
            Interlocked.Increment(ref throwingSubscriberCalls);
            throw new InvalidOperationException("broken subscriber");
        };
        session.DataReceived += (_, data) => received = data.ToArray();

        session.RaiseDataReceived(payload);

        Assert.Equal(payload, received);
        Assert.Equal(1, Volatile.Read(ref throwingSubscriberCalls));
    }

    private static SerialSession CreateSession(
        ISerialSessionPort port,
        SerialFlowControlMode flowControl,
        ILogger<SerialSession>? logger = null) =>
        new(port, flowControl, logger ?? NullLogger<SerialSession>.Instance);

    private sealed class TestSerialSessionPort : ISerialSessionPort
    {
        private readonly object _dtrLock = new();
        private readonly List<bool> _dtrTransitions = [];
        private int _closeCalls;
        private int _writeCalls;
        private int _readCalls;

        public string PortName => "TEST";
        public bool DsrHolding => true;
        public bool CancelFirstWrite { get; init; }
        public bool GateFirstWrite { get; init; }
        public bool BlockReads { get; init; }
        public bool GateReadCompletion { get; init; }
        public byte[]? ReadPayload { get; init; }
        public Exception? FirstWriteException { get; init; }
        public Exception? ReadException { get; init; }
        public Action<bool>? DtrSetter { get; init; }

        public TaskCompletionSource FirstWriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseFirstWrite { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseRead { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadCanceled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CloseCalls => Volatile.Read(ref _closeCalls);
        public int WriteCalls => Volatile.Read(ref _writeCalls);
        public int ReadCalls => Volatile.Read(ref _readCalls);
        public CancellationToken FirstWriteToken { get; private set; }
        public CancellationToken LastReadToken { get; private set; }

        public bool DtrEnable
        {
            set
            {
                lock (_dtrLock) _dtrTransitions.Add(value);
                DtrSetter?.Invoke(value);
            }
        }

        public IReadOnlyList<bool> DtrTransitions
        {
            get { lock (_dtrLock) return _dtrTransitions.ToArray(); }
        }

        public async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _readCalls);
            LastReadToken = cancellationToken;
            ReadStarted.TrySetResult();
            if (ReadException is not null) throw ReadException;
            if (GateReadCompletion)
            {
                // Model a driver that completed a read in native code just as cancellation won.
                await ReleaseRead.Task.ConfigureAwait(false);
            }
            if (ReadPayload is { } payload)
            {
                payload.AsMemory().CopyTo(buffer);
                return payload.Length;
            }
            if (!BlockReads) return 0;

            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
                return 0;
            }
            catch (OperationCanceledException)
            {
                ReadCanceled.TrySetResult();
                throw;
            }
        }

        public async ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _writeCalls) != 1) return;
            FirstWriteToken = cancellationToken;
            FirstWriteStarted.TrySetResult();
            if (CancelFirstWrite)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            }
            else if (GateFirstWrite)
            {
                await ReleaseFirstWrite.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            if (FirstWriteException is not null) throw FirstWriteException;
        }

        public Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public void Close() => Interlocked.Increment(ref _closeCalls);
        public void Dispose() { }
    }
}
