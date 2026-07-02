namespace Wormhole.Services.Bitwarden;

public interface IBitwardenCredentialSyncService
{
    event EventHandler? SyncCompleted;

    void Start();
    Task SyncIfStaleAsync(CancellationToken cancellationToken = default);
    Task SyncNowAsync(CancellationToken cancellationToken = default);
}
