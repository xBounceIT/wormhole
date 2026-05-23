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

    public TransferItemViewModel(string displayName, TransferDirection direction, long expectedBytes, CancellationToken parentToken)
    {
        DisplayName = displayName;
        Direction = direction;
        ExpectedBytes = expectedBytes;
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
        ExpectedBytes <= 0 ? 0 : Math.Clamp((double)BytesTransferred / ExpectedBytes, 0, 1);

    partial void OnBytesTransferredChanged(long value) => OnPropertyChanged(nameof(ProgressFraction));
    partial void OnExpectedBytesChanged(long value) => OnPropertyChanged(nameof(ProgressFraction));

    [RelayCommand]
    public void Cancel()
    {
        if (State is TransferState.Completed or TransferState.Failed or TransferState.Cancelled) return;
        try { _cts.Cancel(); } catch (ObjectDisposedException) { /* already cleaned up */ }
    }

    public void DisposeToken()
    {
        try { _cts.Dispose(); } catch { /* idempotent */ }
    }
}
