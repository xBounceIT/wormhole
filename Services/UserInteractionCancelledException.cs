namespace Wormhole.Services;

/// <summary>
/// Marks an operation that stopped because the user deliberately dismissed or declined an
/// interaction. This is a cancellation outcome, not an application failure: command and session
/// boundaries should handle it through their <see cref="OperationCanceledException"/> paths and
/// must not emit error-level logs or stack traces for it.
/// </summary>
public class UserInteractionCancelledException : OperationCanceledException
{
    public UserInteractionCancelledException(string message)
        : base(message)
    {
    }

    public UserInteractionCancelledException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
