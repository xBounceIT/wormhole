using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

internal sealed class RepositoryCredentialCatalogAdapter : IBitwardenCredentialCatalogService
{
    private readonly ICredentialRepository _repository;

    public RepositoryCredentialCatalogAdapter(ICredentialRepository repository)
    {
        _repository = repository;
    }

    public Task<IReadOnlyList<CredentialProfile>> GetCredentialPageProfilesAsync(CancellationToken cancellationToken = default) =>
        _repository.GetAllAsync(cancellationToken);

    public Task<IReadOnlyList<CredentialProfile>> GetPickerProfilesAsync(CancellationToken cancellationToken = default) =>
        _repository.GetAllAsync(cancellationToken);

    public async Task<IReadOnlyList<CredentialProfile>> GetProfilesForProtocolAsync(
        ProtocolType protocol,
        CancellationToken cancellationToken = default)
    {
        var all = await _repository.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return all.Where(c => c.Protocol == protocol).ToList();
    }

    public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        _repository.GetByIdAsync(id, cancellationToken);
}

internal sealed class NoOpBitwardenCredentialSyncService : IBitwardenCredentialSyncService
{
    public static NoOpBitwardenCredentialSyncService Instance { get; } = new();

    public event EventHandler? SyncCompleted { add { } remove { } }

    public void Start() { }
    public Task SyncIfStaleAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task SyncNowAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}
