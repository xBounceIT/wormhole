using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Per-tunnel persistence for the Entra ID refresh token, so reconnects acquire a fresh access
/// token silently instead of re-opening the Microsoft sign-in popup (matching the native Azure VPN
/// Client's cached-sign-in behavior). A miss simply means the next connect is interactive.
/// </summary>
public interface IAzureVpnTokenCache
{
    /// <summary>
    /// Returns the cached refresh token, or <c>null</c> on any miss (no cache, identity mismatch
    /// after settings changed, expired entry, undecryptable blob). Never throws for cache-state
    /// reasons.
    /// </summary>
    Task<string?> TryReadAsync(Guid tunnelConfigId, AzureVpnSettings settings, CancellationToken cancellationToken);

    Task WriteAsync(Guid tunnelConfigId, AzureVpnSettings settings, string refreshToken, CancellationToken cancellationToken);

    /// <summary>Best-effort delete; never throws.</summary>
    Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken);
}
