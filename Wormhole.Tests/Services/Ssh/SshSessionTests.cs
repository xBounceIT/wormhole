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
        await using var session = new SshSession(
            new SshClient("localhost", "user", "password"),
            stream,
            "fingerprint",
            NullLogger<SshSession>.Instance);

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

    private sealed class BlockingSshSessionStream : ISshSessionStream
    {
        private int _writeCalls;

        public TaskCompletionSource FirstWriteStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CancellationToken FirstWriteToken { get; private set; }

        public int WriteCalls => Volatile.Read(ref _writeCalls);

        public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
            new(0);

        public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
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

        public Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public void ChangeWindowSize(uint columns, uint rows, uint width, uint height)
        {
        }

        public void Close()
        {
        }

        public void Dispose()
        {
        }
    }
}
