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
        var stream = new TestSshSessionStream();
        await using var session = CreateSession(stream);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var closedCount = 0;
        session.Closed += (_, _) =>
        {
            if (Interlocked.Increment(ref closedCount) == 1) closed.TrySetResult();
        };

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
        await stream.ReadCanceled.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(stream.LastReadToken.IsCancellationRequested);
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
        await using var session = CreateSession(stream);

        stream.RaiseClosed();

        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += (_, _) => closed.TrySetResult();

        await closed.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }

    private static SshSession CreateSession(ISshSessionStream stream) =>
        new(
            new SshClient("localhost", "user", "password"),
            stream,
            "fingerprint",
            NullLogger<SshSession>.Instance);

    private class TestSshSessionStream : ISshSessionStream
    {
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

        public CancellationToken LastReadToken { get; private set; }
        public int CloseCalls => Volatile.Read(ref _closeCalls);

        public virtual ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            LastReadToken = cancellationToken;
            if (!BlockReads) return new(0);
            return new(ReadUntilCanceledAsync(cancellationToken));
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

        public void RaiseClosed() => Closed?.Invoke(this, EventArgs.Empty);

        public void RaiseError(Exception exception) => ErrorOccurred?.Invoke(this, exception);

        private async Task<int> ReadUntilCanceledAsync(CancellationToken cancellationToken)
        {
            ReadStarted.TrySetResult();
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
