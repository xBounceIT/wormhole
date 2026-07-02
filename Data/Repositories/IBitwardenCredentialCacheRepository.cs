using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public interface IBitwardenCredentialCacheRepository
{
    Task<IReadOnlyList<BitwardenCredentialCacheEntry>> GetAllAsync(CancellationToken cancellationToken = default);
    Task ReplaceFromFullSyncAsync(
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        DateTimeOffset syncTimeUtc,
        CancellationToken cancellationToken = default);
    Task UpsertImportedAsync(
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        CancellationToken cancellationToken = default);
}
