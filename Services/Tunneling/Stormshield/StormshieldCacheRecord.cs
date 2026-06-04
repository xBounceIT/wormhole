using System;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// One cached Stormshield <see cref="StormshieldConnectionMode.Automatic"/> OpenVPN profile, persisted
/// DPAPI-encrypted per tunnel (see <see cref="StormshieldConfigCache"/>). The cache exists so a
/// reconnect can reuse the profile <em>without</em> re-downloading it: when "Use an OTP" is enabled the
/// single-use code can only be spent in one place — either the HTTPS config download or the OpenVPN
/// data-plane password — so re-downloading on every connect would always burn the code on the download
/// and leave the data-plane auth password-only (the bug). With a current cached profile the download is
/// skipped and the code flows to the data plane instead, mirroring the native v5 client's hash-cache gate.
///
/// <para>This record holds a plaintext private key (inside <see cref="ProfileOvpn"/>), so it is the same
/// sensitivity class as the Import-mode profile already stored in <c>tunnels\*.dpapi</c> and must only
/// ever live inside the DPAPI-encrypted blob, never plaintext on disk.</para>
/// </summary>
public sealed class StormshieldCacheRecord
{
    /// <summary>Bumped if the persisted shape changes; a record with a different version reads as a miss.</summary>
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    /// <summary>
    /// SHA-256 (hex) of the tunnel's identity-defining settings (Server|Port|Username|AppToken). The
    /// cache file is keyed only by tunnel Id, so this guards against reusing a profile after the user
    /// edits the server / username — a changed identity reads as a miss.
    /// </summary>
    public string SiteIdentityHash { get; set; } = string.Empty;

    /// <summary>
    /// The firewall's SSL VPN config hash (opaque token from <c>auth/v1/sslvpn/hash</c>) observed when
    /// this profile was downloaded. Compared case-insensitively to the firewall's <em>current</em> hash
    /// to decide whether the cached profile is still up to date.
    /// </summary>
    public string ConfigHash { get; set; } = string.Empty;

    /// <summary>The normalized, self-contained <c>.ovpn</c> (inline ca/cert/key). Holds a plaintext key.</summary>
    public string ProfileOvpn { get; set; } = string.Empty;

    /// <summary>When the profile was cached; used to bound how long a cached private key may be reused.</summary>
    public DateTimeOffset CachedAtUtc { get; set; }
}
