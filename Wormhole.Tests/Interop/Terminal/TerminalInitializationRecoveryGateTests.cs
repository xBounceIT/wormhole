using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalInitializationRecoveryGateTests
{
    [Fact]
    public void FirstUnownedBrowserExit_QueuesExactlyOneAutomaticReplacement()
    {
        var gate = new TerminalInitializationRecoveryGate();

        Assert.Equal(
            TerminalBrowserExitAction.QueueAutomaticRetry,
            gate.OnUnownedBrowserProcessExited());
        Assert.Equal(
            TerminalInitializationRecoveryState.AutomaticRetryQueued,
            gate.State);
        Assert.True(gate.HasQueuedReplacement);
        Assert.True(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: true));

        gate.OnReplacementSucceeded();

        Assert.Equal(
            TerminalInitializationRecoveryState.AutomaticRetryRunning,
            gate.State);
        Assert.False(gate.HasQueuedReplacement);
    }

    [Fact]
    public void DuplicateExitFromSameFailedCore_DoesNotQueueAnotherReplacement()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();

        Assert.Equal(
            TerminalBrowserExitAction.Ignore,
            gate.OnUnownedBrowserProcessExited());
        Assert.Equal(
            TerminalInitializationRecoveryState.AutomaticRetryQueued,
            gate.State);
    }

    [Fact]
    public void ReplacementExitBeforeAttach_RequiresManualRetryAndStopsAutomaticLoop()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();
        gate.OnReplacementSucceeded();

        Assert.Equal(
            TerminalBrowserExitAction.RequireManualRetry,
            gate.OnUnownedBrowserProcessExited());
        Assert.True(gate.RequiresManualRetry);
        Assert.False(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: true));
    }

    [Fact]
    public void ManualRetry_GetsOneFreshReplacementAttempt()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();
        gate.OnReplacementSucceeded();
        gate.OnUnownedBrowserProcessExited();

        Assert.True(gate.TryQueueManualRetry());
        Assert.True(gate.HasQueuedReplacement);
        Assert.True(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: true));

        gate.OnReplacementSucceeded();

        Assert.Equal(TerminalInitializationRecoveryState.ManualRetryRunning, gate.State);

        gate.OnRendererAttached();

        Assert.Equal(TerminalInitializationRecoveryState.Available, gate.State);
    }

    [Fact]
    public void BrowserExit_DuringManualRetry_RequiresAnotherManualRetry()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();
        gate.OnReplacementSucceeded();
        gate.OnUnownedBrowserProcessExited();
        Assert.True(gate.TryQueueManualRetry());
        gate.OnReplacementSucceeded();

        var action = gate.OnUnownedBrowserProcessExited();

        Assert.Equal(TerminalBrowserExitAction.RequireManualRetry, action);
        Assert.Equal(TerminalInitializationRecoveryState.ManualRetryRequired, gate.State);
    }

    [Fact]
    public void ManualReplacementFailure_LeavesRetryButtonActionable()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();
        gate.OnReplacementSucceeded();
        gate.OnUnownedBrowserProcessExited();
        gate.TryQueueManualRetry();
        gate.OnReplacementSucceeded();

        gate.OnReplacementFailed();

        Assert.True(gate.RequiresManualRetry);
        Assert.True(gate.TryQueueManualRetry());
    }

    [Fact]
    public void StaleOrUnloadedInitialization_CannotConsumeQueuedReplacement()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();

        Assert.False(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: false));
        Assert.True(gate.HasQueuedReplacement);
    }

    [Fact]
    public void FailedReplacementTransaction_LeavesQueuedRecoveryUncommitted()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();

        // Candidate construction/insertion failed, so the view never commits success to the gate.
        Assert.Equal(TerminalInitializationRecoveryState.AutomaticRetryQueued, gate.State);
        Assert.True(gate.HasQueuedReplacement);
        Assert.True(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: true));
    }

    [Fact]
    public void RebindWhileInitializationIsRunning_HandsLatchToCurrentTarget()
    {
        var gate = new TerminalInitializationRecoveryGate();

        Assert.True(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: false,
            currentTargetIsAvailable: true));
    }

    [Fact]
    public void RebindHandoff_RequiresALiveCurrentTarget()
    {
        var gate = new TerminalInitializationRecoveryGate();

        Assert.False(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: false,
            currentTargetIsAvailable: false));
    }

    [Fact]
    public void RebindHandoff_CannotBypassManualRetryBoundary()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnReplacementFailed();

        Assert.False(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: false,
            currentTargetIsAvailable: true));

        Assert.True(gate.TryQueueManualRetry());
        Assert.True(gate.ShouldConsumeInitializationRetry(
            retryRequested: true,
            recreationRequired: true,
            currentTargetIsAvailable: true));
    }

    [Fact]
    public void SuccessfulAttachOrNewBinding_ResetsRecoveryEpisode()
    {
        var gate = new TerminalInitializationRecoveryGate();
        gate.OnUnownedBrowserProcessExited();
        gate.OnReplacementSucceeded();
        gate.OnUnownedBrowserProcessExited();

        gate.OnRendererAttached();
        Assert.Equal(TerminalInitializationRecoveryState.Available, gate.State);
        Assert.Equal(
            TerminalBrowserExitAction.QueueAutomaticRetry,
            gate.OnUnownedBrowserProcessExited());

        gate.OnBindingChanged();
        Assert.Equal(TerminalInitializationRecoveryState.Available, gate.State);
    }
}
