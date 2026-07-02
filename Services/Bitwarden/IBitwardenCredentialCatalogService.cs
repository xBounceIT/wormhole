using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public interface IBitwardenCredentialCatalogService
{
    Task<IReadOnlyList<CredentialProfile>> GetCredentialPageProfilesAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CredentialProfile>> GetPickerProfilesAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CredentialProfile>> GetProfilesForProtocolAsync(ProtocolType protocol, CancellationToken cancellationToken = default);
    Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
}
