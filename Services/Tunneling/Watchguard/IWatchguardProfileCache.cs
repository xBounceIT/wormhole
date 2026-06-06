using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Per-tunnel cache of the WatchGuard OpenVPN profile (CA + client cert + key, inlined into a
/// self-contained <c>.ovpn</c>) downloaded from the Firebox portal.
///
/// <para>It exists to make WatchGuard 2FA a SINGLE factor. A WatchGuard connect has two auth
/// layers: the web <c>sslvpn_logon</c> (used only to download the profile) and the OpenVPN
/// data-channel auth (a CRV1 dynamic challenge). Each demands AuthPoint 2FA independently — and the
/// web logon also tends to fire a spurious push even when an OTP is entered. Re-downloading on every
/// connect therefore burns one factor on the portal and leaves the OpenVPN layer demanding a second
/// (the double-2FA users hate). With a cached profile the portal logon is skipped entirely, so the
/// user's one factor flows straight to the OpenVPN CRV1 layer — matching the native client, which
/// downloads the profile once at setup and reuses it. Mirrors
/// <see cref="Stormshield.IStormshieldConfigCache"/>, whose Automatic mode solves the identical
/// "single-use code can only be spent in one place" problem.</para>
/// </summary>
public interface IWatchguardProfileCache
{
    /// <summary>
    /// Returns the cached self-contained <c>.ovpn</c> for this tunnel, or <c>null</c> on any miss
    /// (absent, decrypt/parse failure, unknown schema, site-identity changed, or older than the max
    /// age). A miss simply means the caller falls back to the web-portal download.
    /// </summary>
    Task<string?> TryReadProfileAsync(Guid tunnelConfigId, WatchguardSettings settings, CancellationToken cancellationToken);

    /// <summary>
    /// Persists the downloaded self-contained <c>.ovpn</c> for this tunnel, DPAPI-encrypted
    /// (<see cref="System.Security.Cryptography.DataProtectionScope.CurrentUser"/>) with the tunnel
    /// Id as entropy and an atomic temp-file + move so an interrupted write never leaves a
    /// half-decryptable key blob.
    /// </summary>
    Task WriteProfileAsync(Guid tunnelConfigId, WatchguardSettings settings, string profileOvpn, CancellationToken cancellationToken);

    /// <summary>
    /// Drops any cached profile for this tunnel — e.g. after a cached profile fails the OpenVPN auth,
    /// so the next connect re-downloads instead of looping on a stale cert/key.
    /// </summary>
    Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken);
}
