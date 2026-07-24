using Wormhole.Models;

namespace Wormhole.Services;

public interface IConnectionCredentialBindingService
{
    Task SaveCredentialBindingAsync(
        Guid nodeId,
        CredentialProfile credential,
        CancellationToken cancellationToken = default);

    Task SaveInlinePasswordAsync(
        Guid nodeId,
        string password,
        string? username = null,
        string? rdpDomain = null,
        CancellationToken cancellationToken = default);
}
