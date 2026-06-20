using Wormhole.Models;

namespace Wormhole.Services;

public interface IConnectionCredentialBindingService
{
    Task SaveCredentialBindingAsync(
        Guid nodeId,
        CredentialProfile credential,
        CancellationToken cancellationToken = default);
}
