using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Non-interactive leg of the Entra ID OAuth flow: redeeming a cached refresh token for a fresh
/// access token without showing UI. Split from <see cref="IAzureVpnAuthService"/> so the
/// provider's token-resolution logic is unit-testable with fakes for both halves.
/// </summary>
public interface IAzureVpnOAuthClient
{
    /// <summary>
    /// Exchanges <paramref name="refreshToken"/> at the tenant's token endpoint. Returns the new
    /// tokens on success, or <c>null</c> when Entra rejected the grant (expired/revoked refresh
    /// token, conditional-access change, …) — the caller falls back to interactive sign-in.
    /// Network-level failures throw.
    /// </summary>
    Task<AzureVpnTokenResult?> RefreshAsync(
        AzureVpnSettings settings,
        string refreshToken,
        CancellationToken cancellationToken);
}
