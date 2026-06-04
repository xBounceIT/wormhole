using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Per-tunnel cache of downloaded Stormshield Automatic-mode OpenVPN profiles. Lets a reconnect reuse a
/// still-current profile instead of re-downloading it, so that — when an OTP is in play — the single-use
/// code can be routed to the OpenVPN data-plane password rather than always being spent on the HTTPS
/// download. See <see cref="StormshieldCacheRecord"/> and the native-client gate it mirrors.
/// </summary>
public interface IStormshieldConfigCache
{
    /// <summary>
    /// Returns the cached profile for this tunnel, or <c>null</c> when there is no usable cache — the
    /// file is missing, corrupt, an unknown schema version, past its max age, or was written for a
    /// different site identity than <paramref name="settings"/> describes. A null result is always safe:
    /// the caller falls back to downloading.
    /// </summary>
    Task<StormshieldCacheRecord?> TryReadAsync(
        Guid tunnelConfigId, StormshieldSettings settings, CancellationToken cancellationToken);

    /// <summary>
    /// Persists the downloaded profile and the firewall config hash it corresponds to, encrypted and
    /// keyed to this tunnel. Atomic: a torn write leaves the prior cache (or no cache) intact rather
    /// than a half-written, undecryptable blob.
    /// </summary>
    Task WriteAsync(
        Guid tunnelConfigId, StormshieldSettings settings, string configHash, string profileOvpn,
        CancellationToken cancellationToken);

    /// <summary>Best-effort removal of any cached profile for this tunnel (called when it is deleted).</summary>
    Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken);
}
