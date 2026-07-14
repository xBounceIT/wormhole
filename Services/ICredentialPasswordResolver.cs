using Wormhole.Models;

namespace Wormhole.Services;

/// <summary>
/// Prompts for the Bitwarden master password and runs the supplied unlock operation while the
/// prompt can keep a visible busy state on screen. Returns the resulting session key, or null when
/// the user cancels.
/// </summary>
public delegate Task<string?> BitwardenUnlockPrompt(
    Func<string, CancellationToken, Task<string>> unlockAsync,
    CancellationToken cancellationToken);

public interface ICredentialPasswordResolver
{
    Task<string?> ReadPasswordAsync(
        CredentialProfile credential,
        BitwardenUnlockPrompt? unlockPrompt = null,
        CancellationToken cancellationToken = default);
}
