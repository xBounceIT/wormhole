namespace Wormhole.Interop.Terminal;

/// <summary>
/// Keeps a session non-interactive until the ordered xterm focus barrier completes and the caller
/// confirms that the same session, renderer, and lifecycle are still current.
/// </summary>
internal static class TerminalFocusBarrier
{
    public static async Task<bool> WaitAsync(
        ITerminalOutputSink? outputSink,
        Func<bool> isCurrent)
    {
        ArgumentNullException.ThrowIfNull(isCurrent);
        if (outputSink is not null)
        {
            await outputSink.RequestFocusAsync().ConfigureAwait(true);
        }
        return isCurrent();
    }
}
/// <summary>
/// Serializes complete output-barrier/focus/acknowledgement requests. A later caller must run its
/// own barrier after the prior focus completes; sharing the prior acknowledgement would let output
/// accepted between the two requests escape the later caller's focus boundary.
/// </summary>
internal sealed class TerminalFocusRequestGate
{
    private readonly object _sync = new();
    private Task _tail = Task.CompletedTask;

    public Task RunAsync(Func<Task> request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var turn = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task predecessor;
        lock (_sync)
        {
            predecessor = _tail;
            _tail = turn.Task;
        }

        return RunAfterAsync(predecessor, turn, request, cancellationToken);
    }

    private static async Task RunAfterAsync(
        Task predecessor,
        TaskCompletionSource turn,
        Func<Task> request,
        CancellationToken cancellationToken)
    {
        try
        {
            // A cancelled turn still waits for its predecessor before releasing the next one;
            // otherwise a later focus could overtake the active output/focus boundary.
            await predecessor.ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            await request().ConfigureAwait(true);
        }
        finally
        {
            turn.TrySetResult();
        }
    }
}
