using Microsoft.Extensions.Logging.Abstractions;
using Renci.SshNet;
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

    [Fact]
    public async Task StreamClosedWhileReadingPaused_WaitsForResumeThenDrainsBeforeClosed()
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
            events.Add("closed");
            closed.TrySetResult();
        };

        session.PauseReading();
        session.Start();

        stream.RaiseClosed();
        await Task.Delay(50);
        Assert.False(stream.ReadStarted.Task.IsCompleted);
        Assert.False(closed.Task.IsCompleted);

        session.ResumeReading();
        await firstData.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await Task.Delay(50);
        Assert.Collection(
            received,
            b => Assert.Equal(0x41, b),
            b => Assert.Equal(0x42, b),
            b => Assert.Equal(0x43, b));
        Assert.False(closed.Task.IsCompleted);

        session.ResumeReading();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
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
    }

    [Fact]
    public async Task WriteFailure_RaisesClosedAndPropagatesToCaller()
    {
        var stream = new TestSshSessionStream
        {
            WriteException = new IOException("socket lost during write"),
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

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
            ResizeException = new IOException("socket lost during resize"),
        };
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

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
    public async Task StreamClosedBeforeConsumerSubscribes_IsReplayed()
    {
        var stream = new TestSshSessionStream();
        stream.EnqueueRead(new byte[] { 0x2A });
        await using var session = CreateSession(stream);

        stream.RaiseClosed();

        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = new List<byte>();
        session.DataReceived += (_, data) => received.AddRange(data.ToArray());
        session.Closed += (_, _) => closed.TrySetResult();

        session.Start();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Collection(received, b => Assert.Equal(0x2A, b));
    }

    private static SshSession CreateSession(ISshSessionStream stream) =>
        new(
            new SshClient("localhost", "user", "password"),
            stream,
            "fingerprint",
            NullLogger<SshSession>.Instance);

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
        public bool CloseRaisesClosed { get; init; }
        public Exception? WriteException { get; init; }
        public Exception? ResizeException { get; init; }

        public TaskCompletionSource ReadStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadCanceled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReadCompletedAfterRemoteClose { get; } =
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
            if (CloseRaisesClosed) RaiseClosed();
        }

        public virtual void Dispose()
        {
        }

        public void RaiseClosed()
        {
            _remoteReadReleased.TrySetResult();
            Closed?.Invoke(this, EventArgs.Empty);
        }

        public void RaiseError(Exception exception)
        {
            _remoteReadReleased.TrySetResult();
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
