using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Services.Ssh;

public sealed class SshSessionTests
{
    [Fact]
    public async Task DisposeAsync_CancelsActiveAndQueuedWritesWithoutCallerToken()
    {
        var stream = new BlockingSshSessionStream();
        await using var session = CreateSession(stream);

        var activeWrite = session.WriteAsync(new byte[] { 0x01 });
        await stream.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(stream.FirstWriteToken.CanBeCanceled);

        var queuedWrite = session.WriteAsync(new byte[] { 0x02 });
        Assert.False(queuedWrite.IsCompleted);

        await session.DisposeAsync();

        await activeWrite.WaitAsync(TimeSpan.FromSeconds(1));
        await queuedWrite.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(stream.FirstWriteToken.IsCancellationRequested);
        Assert.Equal(1, stream.WriteCalls);
    }

    [Fact]
    public async Task WriteAsync_CallerCancellationDuringActiveWrite_PropagatesWithoutClosingSession()
    {
        var stream = new CallerCancelableSshSessionStream();
        await using var session = CreateSession(stream);
        var closedCount = 0;
        session.Closed += (_, _) => Interlocked.Increment(ref closedCount);
        using var callerCts = new CancellationTokenSource();

        var write = session.WriteAsync(new byte[] { 0x01 }, callerCts.Token);
        await stream.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        callerCts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => write);
        Assert.Equal(0, Volatile.Read(ref closedCount));
        Assert.Equal(0, stream.CloseCalls);

        await session.WriteAsync(new byte[] { 0x02 });
        Assert.Equal(2, stream.WriteCalls);
    }

    [Fact]
    public async Task WriteAsync_CallerCancellationWhileQueued_PropagatesWithoutClosingSession()
    {
        var stream = new QueuedCallerCancellationSshSessionStream();
        await using var session = CreateSession(stream);
        var closedCount = 0;
        session.Closed += (_, _) => Interlocked.Increment(ref closedCount);

        var activeWrite = session.WriteAsync(new byte[] { 0x01 });
        await stream.FirstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        using var callerCts = new CancellationTokenSource();
        var queuedWrite = session.WriteAsync(new byte[] { 0x02 }, callerCts.Token);
        Assert.False(queuedWrite.IsCompleted);

        callerCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queuedWrite);
        Assert.Equal(0, Volatile.Read(ref closedCount));
        Assert.Equal(0, stream.CloseCalls);

        stream.ReleaseFirstWrite.TrySetResult();
        await activeWrite.WaitAsync(TimeSpan.FromSeconds(1));
        await session.WriteAsync(new byte[] { 0x03 });
        Assert.Equal(2, stream.WriteCalls);
    }

    [Fact]
    public async Task StreamClosed_RaisesClosedOnce()
    {
        var stream = new TestSshSessionStream { BlockReads = true };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closedCount = 0;
        session.Closed += (_, _) =>
        {
            if (Interlocked.Increment(ref closedCount) == 1) closed.TrySetResult();
        };

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        stream.RaiseClosed();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();
        stream.RaiseError(new IOException("second close signal"));

        Assert.Equal(1, Volatile.Read(ref closedCount));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task StreamClosed_ThrowingLoggerStillNotifiesLaterSubscribers()
    {
        var stream = new TestSshSessionStream { BlockReads = true };
        await using var session = CreateSession(stream, new ThrowingLogger<SshSession>());
        var laterSubscriber = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        session.Closed += (_, _) => throw new InvalidOperationException("broken subscriber");
        session.Closed += (_, _) => laterSubscriber.TrySetResult();

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();

        await laterSubscriber.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClientError_DrainsBufferedTailRegardlessOfEventOrder(
        bool streamErrorFirst)
    {
        var tail = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J', (byte)'$' };
        var stream = new TestSshSessionStream { BlockReads = true };
        stream.EnqueueRead(tail);
        await using var session = CreateSession(stream);
        var received = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += (_, data) => received.TrySetResult(data.ToArray());
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();
        session.Start();
        if (streamErrorFirst)
        {
            stream.RaiseError(new IOException("shell stream failed"));
            session.SignalClientErrorForTesting(new IOException("client failed"));
        }
        else
        {
            session.SignalClientErrorForTesting(new IOException("client failed"));
            stream.RaiseError(new IOException("shell stream failed"));
        }

        Assert.Equal(tail, await received.Task.WaitAsync(TimeSpan.FromSeconds(1)));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task ClientError_ClosesStreamToWakeReaderAndDrainTailWithoutStreamEvent()
    {
        var tail = new byte[] { (byte)'f', (byte)'i', (byte)'n', (byte)'a', (byte)'l' };
        var stream = new TestSshSessionStream { BlockReads = true };
        stream.EnqueueRead(tail);
        await using var session = CreateSession(stream);
        var received = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += (_, data) => received.TrySetResult(data.ToArray());
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();
        session.Start();
        session.SignalClientErrorForTesting(new IOException("client failed"));

        Assert.Equal(tail, await received.Task.WaitAsync(TimeSpan.FromSeconds(1)));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task ConcurrentWriteFailure_CannotInterruptEstablishedTailDrain()
    {
        var tail = new byte[] { (byte)'t', (byte)'a', (byte)'i', (byte)'l' };
        var stream = new DelayedFailingWriteSshSessionStream { BlockReads = true };
        stream.EnqueueRead(tail);
        await using var session = CreateSession(stream);
        var received = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        session.DataReceived += (_, data) => received.TrySetResult(data.ToArray());
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();
        session.Start();
        var write = session.WriteAsync(new byte[] { 0x01 });
        await stream.WriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        session.SignalClientErrorForTesting(new IOException("client failed"));
        stream.ReleaseWriteFailure.TrySetResult();
        await Assert.ThrowsAsync<IOException>(() => write);
        stream.AllowRemoteEof.TrySetResult();
        Assert.Equal(tail, await received.Task.WaitAsync(TimeSpan.FromSeconds(1)));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task StreamError_RaisesClosedAndUnblocksReadPump()
    {
        var stream = new TestSshSessionStream { BlockReads = true };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        stream.RaiseError(new IOException("socket lost"));

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await stream.ReadCompletedAfterRemoteClose.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(stream.ReadCanceled.Task.IsCompleted);
        Assert.Equal(1, stream.CloseCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StreamClosed_FinalReadThrows_CompletesClosedExactlyOnce(
        bool operationCanceled)
    {
        var stream = new TestSshSessionStream
        {
            BlockReads = true,
            ReadExceptionAfterRemoteClose = operationCanceled
                ? new OperationCanceledException("remote channel canceled its pending read")
                : new ObjectDisposedException("remote shell stream"),
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closedCount = 0;
        session.Closed += (_, _) =>
        {
            Interlocked.Increment(ref closedCount);
            closed.TrySetResult();
        };

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();
        stream.RaiseError(new IOException("duplicate teardown notification"));
        await Task.Delay(25);

        Assert.Equal(1, Volatile.Read(ref closedCount));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task StreamClosedWhileReadingPaused_ReleasesBackpressureAndDrainsBeforeClosed()
    {
        var stream = new TestSshSessionStream();
        stream.EnqueueRead(new byte[] { 0x41, 0x42, 0x43 });
        stream.EnqueueRead(new byte[] { 0x44, 0x45, 0x46 });
        await using var session = CreateSession(stream);
        var firstData = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = new List<byte>();
        var events = new List<string>();
        var pauseCount = 0;
        var closedCount = 0;
        session.DataReceived += (_, data) =>
        {
            received.AddRange(data.ToArray());
            events.Add("data");
            if (Interlocked.Increment(ref pauseCount) == 1)
            {
                session.PauseReading();
                firstData.TrySetResult();
            }
        };
        session.Closed += (_, _) =>
        {
            Interlocked.Increment(ref closedCount);
            events.Add("closed");
            closed.TrySetResult();
        };

        session.PauseReading();
        session.Start();

        stream.RaiseClosed();
        await firstData.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();
        stream.RaiseError(new IOException("duplicate teardown notification"));
        await Task.Delay(25);
        Assert.Collection(
            received,
            b => Assert.Equal(0x41, b),
            b => Assert.Equal(0x42, b),
            b => Assert.Equal(0x43, b),
            b => Assert.Equal(0x44, b),
            b => Assert.Equal(0x45, b),
            b => Assert.Equal(0x46, b));
        Assert.Collection(
            events,
            e => Assert.Equal("data", e),
            e => Assert.Equal("data", e),
            e => Assert.Equal("closed", e));
        Assert.Equal(1, stream.CloseCalls);
        Assert.Equal(1, Volatile.Read(ref closedCount));
    }

    [Fact]
    public async Task PausedRead_ExcessiveShellStreamBacklog_ClosesSessionBeforeMemoryCanGrowUnbounded()
    {
        var stream = new TestSshSessionStream
        {
            BlockReads = true,
            BufferedLength = SshSession.MaxBufferedOutputBacklogBytes + 1,
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.PauseReading();
        session.Start();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(stream.ReadStarted.Task.IsCompleted);
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task WriteFailure_RaisesClosedAndPropagatesToCaller()
    {
        var stream = new TestSshSessionStream
        {
            BlockReads = true,
            WriteException = new IOException("socket lost during write"),
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var ex = await Assert.ThrowsAsync<IOException>(() => session.WriteAsync(new byte[] { 0x01 }));

        Assert.Same(stream.WriteException, ex);
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task ResizeFailure_RaisesClosedWithoutThrowingToCaller()
    {
        var stream = new TestSshSessionStream
        {
            BlockReads = true,
            ResizeException = new IOException("socket lost during resize"),
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await session.ResizeAsync(120, 40);

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task DisposeAsync_StreamClosedDuringDispose_DoesNotRaiseClosed()
    {
        var stream = new TestSshSessionStream { CloseRaisesClosed = true };
        var session = CreateSession(stream);
        var closedCount = 0;
        session.Closed += (_, _) => Interlocked.Increment(ref closedCount);

        await session.DisposeAsync();

        Assert.Equal(0, Volatile.Read(ref closedCount));
        Assert.Equal(1, stream.CloseCalls);
    }

    [Fact]
    public async Task StreamClosedBeforeConsumerSubscribes_DefersTailDrainUntilStart()
    {
        var stream = new TestSshSessionStream { BlockReads = true };
        stream.EnqueueRead(new byte[] { 0x2A });
        await using var session = CreateSession(stream);

        stream.RaiseClosed();
        await stream.RemoteEofSignaled.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.False(session.HasStarted);
        Assert.False(stream.ReadStarted.Task.IsCompleted);
        Assert.Equal(1, stream.CloseCalls);

        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = new List<byte>();
        session.DataReceived += (_, data) => received.AddRange(data.ToArray());
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Collection(received, b => Assert.Equal(0x2A, b));
    }

    [Fact]
    public async Task Closed_ThrowingSubscriber_DoesNotStarveLaterSubscribers()
    {
        var stream = new TestSshSessionStream { BlockReads = true };
        await using var session = CreateSession(stream);
        var laterSubscriber = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        session.Closed += (_, _) => throw new InvalidOperationException("broken subscriber");
        session.Closed += (_, _) => laterSubscriber.TrySetResult();

        session.Start();
        await stream.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        stream.RaiseClosed();

        await laterSubscriber.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }
    [Fact]
    public async Task DataReceived_ThrowingSubscriber_DoesNotStarveLaterSubscribers()
    {
        var stream = new TestSshSessionStream();
        var payload = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J' };
        stream.EnqueueRead(payload);
        await using var session = CreateSession(stream);
        var laterSubscriber = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var throwingSubscriberCalls = 0;

        session.DataReceived += (_, _) =>
        {
            Interlocked.Increment(ref throwingSubscriberCalls);
            throw new InvalidOperationException("broken subscriber");
        };
        session.DataReceived += (_, data) => laterSubscriber.TrySetResult(data.ToArray());

        session.Start();

        var received = await laterSubscriber.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(payload, received);
        Assert.Equal(1, Volatile.Read(ref throwingSubscriberCalls));
    }

    private static SshSession CreateSession(
        ISshSessionStream stream,
        ILogger<SshSession>? logger = null) =>
        new(
            new SshClient("localhost", "user", "password"),
            stream,
            "fingerprint",
            logger ?? NullLogger<SshSession>.Instance);

    private class TestSshSessionStream : ISshSessionStream
    {
        private readonly object _readResultsLock = new();
        private readonly Queue<byte[]> _readResults = new();
        private readonly TaskCompletionSource _remoteReadReleased =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _closeCalls;

        public event EventHandler? Closed;
        public event EventHandler<Exception>? ErrorOccurred;

        public bool BlockReads { get; init; }
        public long BufferedLength { get; set; }
        public bool CloseRaisesClosed { get; init; }
        public Exception? WriteException { get; init; }
        public Exception? ResizeException { get; init; }
        public Exception? ReadExceptionAfterRemoteClose { get; init; }

        public TaskCompletionSource ReadStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadCanceled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadCompletedAfterRemoteClose { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource RemoteEofSignaled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CloseCalls => Volatile.Read(ref _closeCalls);

        public void EnqueueRead(byte[] data)
        {
            lock (_readResultsLock)
            {
                _readResults.Enqueue(data);
            }
        }

        public virtual ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            ReadStarted.TrySetResult();
            if (TryReadQueued(buffer, out var read)) return new(read);
            if (!BlockReads) return new(0);
            return new(ReadUntilRemoteClosedOrCanceledAsync(cancellationToken));
        }

        public virtual ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            if (WriteException is not null) throw WriteException;
            return ValueTask.CompletedTask;
        }

        public virtual Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public virtual void ChangeWindowSize(uint columns, uint rows, uint width, uint height)
        {
            if (ResizeException is not null) throw ResizeException;
        }

        public void Close()
        {
            Interlocked.Increment(ref _closeCalls);
            // Real ShellStream disposal wakes readers while preserving its buffered bytes.
            _remoteReadReleased.TrySetResult();
            if (CloseRaisesClosed) Closed?.Invoke(this, EventArgs.Empty);
        }

        public virtual void Dispose()
        {
        }

        public void RaiseClosed()
        {
            _remoteReadReleased.TrySetResult();
            Closed?.Invoke(this, EventArgs.Empty);
            RemoteEofSignaled.TrySetResult();
        }

        public void RaiseError(Exception exception)
        {
            // SSH.NET relays Session.ErrorOccurred without disposing the channel or waking Read.
            ErrorOccurred?.Invoke(this, exception);
        }

        private bool TryReadQueued(Memory<byte> buffer, out int read)
        {
            lock (_readResultsLock)
            {
                if (_readResults.Count == 0)
                {
                    read = 0;
                    return false;
                }

                var data = _readResults.Dequeue();
                read = Math.Min(data.Length, buffer.Length);
                data.AsSpan(0, read).CopyTo(buffer.Span);
                return true;
            }
        }

        private async Task<int> ReadUntilRemoteClosedOrCanceledAsync(CancellationToken cancellationToken)
        {
            var canceled = Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            var completed = await Task.WhenAny(_remoteReadReleased.Task, canceled).ConfigureAwait(false);
            if (completed == _remoteReadReleased.Task)
            {
                ReadCompletedAfterRemoteClose.TrySetResult();
                if (ReadExceptionAfterRemoteClose is { } exception) throw exception;
                return 0;
            }

            try
            {
                await canceled.ConfigureAwait(false);
                return 0;
            }
            catch (OperationCanceledException)
            {
                ReadCanceled.TrySetResult();
                throw;
            }
        }
    }

    private sealed class DelayedFailingWriteSshSessionStream : TestSshSessionStream
    {
        private int _readCalls;

        public TaskCompletionSource WriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseWriteFailure { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource AllowRemoteEof { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _readCalls) == 1)
            {
                return base.ReadAsync(buffer, cancellationToken);
            }

            return new(ReadRemoteEofAfterWriteFailureAsync(buffer, cancellationToken));
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken)
        {
            WriteStarted.TrySetResult();
            await ReleaseWriteFailure.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            throw new IOException("delayed write failure");
        }

        private async Task<int> ReadRemoteEofAfterWriteFailureAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            await AllowRemoteEof.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return await base.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class CallerCancelableSshSessionStream : TestSshSessionStream
    {
        private int _writeCalls;

        public TaskCompletionSource FirstWriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int WriteCalls => Volatile.Read(ref _writeCalls);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _writeCalls) != 1) return;
            FirstWriteStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class QueuedCallerCancellationSshSessionStream : TestSshSessionStream
    {
        private int _writeCalls;

        public TaskCompletionSource FirstWriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseFirstWrite { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int WriteCalls => Volatile.Read(ref _writeCalls);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _writeCalls) != 1) return;
            FirstWriteStarted.TrySetResult();
            await ReleaseFirstWrite.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class BlockingSshSessionStream : TestSshSessionStream
    {
        private int _writeCalls;

        public TaskCompletionSource FirstWriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CancellationToken FirstWriteToken { get; private set; }

        public int WriteCalls => Volatile.Read(ref _writeCalls);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
            new(0);

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _writeCalls);
            if (call != 1)
            {
                throw new InvalidOperationException("Queued write reached the stream after disposal.");
            }

            FirstWriteToken = cancellationToken;
            FirstWriteStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
    }
}
