using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalBridgeConcurrencyTests
{
    [Theory]
    [InlineData(42, 42, true)]
    [InlineData(42, 41, false)]
    [InlineData(42, 43, false)]
    public void ResizeAdmission_IsScopedToExactBridgeStream(
        long bridgeStreamId,
        long resizeStreamId,
        bool expected)
    {
        Assert.Equal(
            expected,
            TerminalBridge.ShouldAcceptResizeFrame(bridgeStreamId, resizeStreamId));
    }

    [Fact]
    public async Task StartObservedOperation_ReturnsWhileOperationIsStillPending()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Exception? observedFailure = null;

        var startCall = Task.Run(() => TerminalBridge.StartObservedOperation(
            () => release.Task,
            ex => observedFailure = ex));

        await startCall.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.False(release.Task.IsCompleted);
        Assert.Null(observedFailure);

        release.SetResult();
    }

    [Fact]
    public async Task StartObservedOperation_ReportsAsynchronousFailure()
    {
        var expected = new IOException("paste failed");
        var observed = new TaskCompletionSource<Exception>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        TerminalBridge.StartObservedOperation(
            () => Task.FromException(expected),
            ex => observed.TrySetResult(ex));

        Assert.Same(expected, await observed.Task.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void ClipboardPasteTransactionDeadline_PrecedesRendererExpiry()
    {
        Assert.Equal(
            TimeSpan.FromSeconds(40),
            TerminalBridge.ClipboardPasteTransactionTimeout);
        Assert.True(
            TerminalBridge.ClipboardPasteTransactionTimeout < TimeSpan.FromSeconds(50),
            "The native transaction must cancel before bridge.js retires the paste request.");
    }
}
