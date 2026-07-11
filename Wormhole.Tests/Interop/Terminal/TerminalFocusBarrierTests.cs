using Wormhole.Interop.Terminal;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalFocusBarrierTests
{
    [Fact]
    public async Task WaitAsync_KeepsStatusConnectingUntilFocusCompletes()
    {
        var sink = new BlockingFocusSink();
        var status = SessionStatus.Connecting;

        async Task PublishConnectedAsync()
        {
            if (await TerminalFocusBarrier.WaitAsync(sink, () => true))
            {
                status = SessionStatus.Connected;
            }
        }

        var publish = PublishConnectedAsync();
        await sink.FocusRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(SessionStatus.Connecting, status);

        sink.FocusRelease.TrySetResult();
        await publish;

        Assert.Equal(SessionStatus.Connected, status);
    }

    [Fact]
    public async Task WaitAsync_DoesNotPublishAfterLifecycleBecomesStale()
    {
        var sink = new BlockingFocusSink();
        var current = true;
        var status = SessionStatus.Connecting;

        async Task PublishConnectedAsync()
        {
            if (await TerminalFocusBarrier.WaitAsync(sink, () => current))
            {
                status = SessionStatus.Connected;
            }
        }

        var publish = PublishConnectedAsync();
        await sink.FocusRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));
        current = false;
        sink.FocusRelease.TrySetResult();
        await publish;

        Assert.Equal(SessionStatus.Connecting, status);
    }

    [Fact]
    public async Task RequestGate_SecondCallerNeedsItsOwnBarrierAndAcknowledgement()
    {
        var gate = new TerminalFocusRequestGate();
        var firstPosted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var firstAcknowledgement = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondPosted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondAcknowledgement = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var first = gate.RunAsync(async () =>
        {
            firstPosted.TrySetResult();
            await firstAcknowledgement.Task;
        }, CancellationToken.None);
        await firstPosted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var second = gate.RunAsync(async () =>
        {
            secondPosted.TrySetResult();
            await secondAcknowledgement.Task;
        }, CancellationToken.None);

        Assert.False(secondPosted.Task.IsCompleted);
        firstAcknowledgement.TrySetResult();
        await secondPosted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(second.IsCompleted);

        secondAcknowledgement.TrySetResult();
        await Task.WhenAll(first, second);
    }

    private sealed class BlockingFocusSink : ITerminalOutputSink
    {
        public TaskCompletionSource FocusRequested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FocusRelease { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool TryAppendOutput(ReadOnlyMemory<byte> data) => true;
        public void Replay(ReadOnlyMemory<byte> data, bool suppressTerminalResponses) { }
        public Task<bool> FlushOutputAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task RequestFocusAsync()
        {
            FocusRequested.TrySetResult();
            return FocusRelease.Task;
        }

        public TerminalOutputRetirement DisposeAndTakePendingOutput() =>
            TerminalOutputRetirement.Empty;
        public void Dispose() { }
    }
}
