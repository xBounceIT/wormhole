using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions.Transfer;

public enum TransferState
{
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

/// <summary>
/// One row in the bottom transfer-queue strip. Owns its own <see cref="CancellationTokenSource"/>
/// so the cancel button on the row affects only this transfer, not the whole queue.
/// </summary>
public sealed partial class TransferItemViewModel : ObservableObject
{
    private readonly CancellationTokenSource _cts;
    private readonly Action<TransferItemViewModel>? _removeCallback;

    public TransferItemViewModel(string displayName, TransferDirection direction, long expectedBytes, CancellationToken parentToken, Action<TransferItemViewModel>? removeCallback = null)
    {
        DisplayName = displayName;
        Direction = direction;
        ExpectedBytes = expectedBytes;
        _removeCallback = removeCallback;
        // Linked so closing the dialog (which cancels the parent CTS) also cancels
        // every in-flight row without manually walking the collection.
        _cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
    }

    public string DisplayName { get; }
    public TransferDirection Direction { get; }
    public CancellationToken Token => _cts.Token;

    [ObservableProperty]
    private long expectedBytes;

    [ObservableProperty]
    private long bytesTransferred;

    [ObservableProperty]
    private TransferState state = TransferState.Queued;

    [ObservableProperty]
    private string? errorMessage;

    public double ProgressFraction =>
        // A Completed row should always render full, even when the source's reported
        // size was 0 or unknown (e.g. a remote stat returned no Size, or a legitimately
        // 0-byte file). Otherwise the snap-to-100% mutation in the orchestrator becomes
        // a no-op (BytesTransferred = ExpectedBytes = 0 → fraction stays 0) and the
        // user sees an empty bar on a finished transfer.
        State is TransferState.Completed ? 1.0 :
        ExpectedBytes <= 0 ? 0 : Math.Clamp((double)BytesTransferred / ExpectedBytes, 0, 1);

    partial void OnBytesTransferredChanged(long value) => OnPropertyChanged(nameof(ProgressFraction));
    partial void OnExpectedBytesChanged(long value) => OnPropertyChanged(nameof(ProgressFraction));
    partial void OnStateChanged(TransferState value) => OnPropertyChanged(nameof(ProgressFraction));

    [RelayCommand]
    public void Cancel()
    {
        // The X glyph on the row is a "clear" affordance: always remove the row, and
        // additionally cancel the underlying transfer if it's still running or queued.
        // Without the unconditional remove, finished rows lingered forever and the
        // button felt dead because Cancel was a no-op for non-running states.
        if (State is TransferState.Queued or TransferState.Running)
        {
            // ObjectDisposedException: row.DisposeToken() may have run in EnqueueAsync's
            // finally between the State read and this Cancel call.
            // AggregateException: CancellationTokenSource.Cancel rethrows callback faults
            // wrapped in AggregateException; one bad SSH.NET registration must not let
            // the X button leave the row stuck in the queue.
            try { _cts.Cancel(); }
            catch (ObjectDisposedException) { /* already cleaned up */ }
            catch (AggregateException) { /* a registered callback threw; row still gets removed */ }
        }
        _removeCallback?.Invoke(this);
    }

    public void DisposeToken()
    {
        try { _cts.Dispose(); } catch { /* idempotent */ }
    }
}
