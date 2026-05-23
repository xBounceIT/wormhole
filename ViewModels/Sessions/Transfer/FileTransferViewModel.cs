using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Models;
using Wormhole.Services.Sftp;

namespace Wormhole.ViewModels.Sessions.Transfer;

/// <summary>
/// Backing VM for the file transfer dialog. Composes the local and remote panes plus
/// the orchestrator's transfer queue. Disposing this VM disposes the orchestrator and,
/// transitively, the SFTP session it owns.
/// </summary>
public sealed partial class FileTransferViewModel : ObservableObject, IAsyncDisposable
{
    private readonly IFileTransferOrchestrator _orchestrator;
    private int _disposed;

    public FileTransferViewModel(IFileTransferOrchestrator orchestrator, string connectionTitle, string remoteHost, string initialLocalPath, string initialRemotePath)
    {
        _orchestrator = orchestrator;
        ConnectionTitle = connectionTitle;
        RemoteHost = remoteHost;

        LocalPane = new LocalFilePaneViewModel();
        RemotePane = new RemoteFilePaneViewModel(orchestrator.Session, orchestrator.RunSerializedAsync);
        Transfers = orchestrator.Transfers;
        InitialLocalPath = initialLocalPath;
        InitialRemotePath = initialRemotePath;
    }

    public string ConnectionTitle { get; }
    public string RemoteHost { get; }

    public LocalFilePaneViewModel LocalPane { get; }
    public RemoteFilePaneViewModel RemotePane { get; }
    public ObservableCollection<TransferItemViewModel> Transfers { get; }
    public string InitialLocalPath { get; }
    public string InitialRemotePath { get; }

    public async Task LoadInitialAsync()
    {
        // Both panes can list independently — the local one doesn't go through the
        // SFTP semaphore. Fire both in parallel and await the pair.
        var local = LocalPane.LoadAsync(InitialLocalPath);
        var remote = RemotePane.LoadAsync(InitialRemotePath);
        await Task.WhenAll(local, remote).ConfigureAwait(true);
    }

    public Task EnqueueAsync(TransferRequest request, ConflictResolver resolver, CancellationToken cancellationToken = default) =>
        _orchestrator.EnqueueAsync(request, resolver, cancellationToken);

    public Task<IReadOnlyList<string>> StageForExportAsync(IReadOnlyList<TransferItem> items, CancellationToken cancellationToken = default) =>
        _orchestrator.StageForExportAsync(items, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        await _orchestrator.DisposeAsync().ConfigureAwait(false);
    }
}
