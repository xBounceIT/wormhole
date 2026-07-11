namespace Wormhole.Interop.Terminal;

internal enum TerminalInitializationRecoveryState
{
    Available,
    AutomaticRetryQueued,
    AutomaticRetryRunning,
    ManualRetryRequired,
    ManualRetryQueued,
    ManualRetryRunning,
}

internal enum TerminalBrowserExitAction
{
    Ignore,
    QueueAutomaticRetry,
    RequireManualRetry,
}

/// <summary>
/// Bounds view-local WebView2 replacement before a renderer is attached to a session. One browser
/// exit is recovered automatically; a replacement that exits before a successful attach requires
/// an explicit local retry so a broken runtime cannot create an unbounded process-restart loop.
/// </summary>
internal sealed class TerminalInitializationRecoveryGate
{
    public TerminalInitializationRecoveryState State { get; private set; }

    public bool HasQueuedReplacement =>
        State is TerminalInitializationRecoveryState.AutomaticRetryQueued or
            TerminalInitializationRecoveryState.ManualRetryQueued;

    public bool RequiresManualRetry =>
        State == TerminalInitializationRecoveryState.ManualRetryRequired;

    public TerminalBrowserExitAction OnUnownedBrowserProcessExited()
    {
        switch (State)
        {
            case TerminalInitializationRecoveryState.Available:
                State = TerminalInitializationRecoveryState.AutomaticRetryQueued;
                return TerminalBrowserExitAction.QueueAutomaticRetry;

            case TerminalInitializationRecoveryState.AutomaticRetryRunning:
            case TerminalInitializationRecoveryState.ManualRetryRunning:
                State = TerminalInitializationRecoveryState.ManualRetryRequired;
                return TerminalBrowserExitAction.RequireManualRetry;

            default:
                return TerminalBrowserExitAction.Ignore;
        }
    }

    public bool ShouldConsumeInitializationRetry(
        bool retryRequested,
        bool recreationRequired,
        bool currentTargetIsAvailable) =>
        retryRequested &&
        currentTargetIsAvailable &&
        !RequiresManualRetry &&
        (!recreationRequired || HasQueuedReplacement);

    public void OnReplacementSucceeded()
    {
        State = State switch
        {
            TerminalInitializationRecoveryState.AutomaticRetryQueued =>
                TerminalInitializationRecoveryState.AutomaticRetryRunning,
            TerminalInitializationRecoveryState.ManualRetryQueued =>
                TerminalInitializationRecoveryState.ManualRetryRunning,
            _ => State,
        };
    }

    public void OnReplacementFailed() =>
        State = TerminalInitializationRecoveryState.ManualRetryRequired;

    public bool TryQueueManualRetry()
    {
        if (State != TerminalInitializationRecoveryState.ManualRetryRequired) return false;
        State = TerminalInitializationRecoveryState.ManualRetryQueued;
        return true;
    }

    public void OnRendererAttached() => State = TerminalInitializationRecoveryState.Available;

    public void OnBindingChanged() => State = TerminalInitializationRecoveryState.Available;
}
