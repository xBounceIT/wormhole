using Wormhole.Models;

namespace Wormhole.Services;

public interface ICredentialPasswordResolver
{
    Task<string?> ReadPasswordAsync(
        CredentialProfile credential,
        Func<CancellationToken, Task<string?>>? unlockPrompt = null,
        CancellationToken cancellationToken = default);
}
