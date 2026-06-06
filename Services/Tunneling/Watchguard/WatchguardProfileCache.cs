using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Default <see cref="IWatchguardProfileCache"/>: stores each tunnel's downloaded OpenVPN profile as
/// a single DPAPI-encrypted (<see cref="DataProtectionScope.CurrentUser"/>) JSON blob under
/// <c>%LOCALAPPDATA%\Wormhole\watchguard-cache\&lt;id:N&gt;.ovpncache</c>. Directly mirrors
/// <see cref="Stormshield.StormshieldConfigCache"/> (same protection class as the per-tunnel secret),
/// with the same two hardenings: the tunnel Id is fed in as DPAPI <c>optionalEntropy</c> so a blob
/// copied to a different tunnel's filename cannot be decrypted, and writes are atomic (temp file +
/// <see cref="File.Move(string,string,bool)"/>) so an interrupted write never leaves a
/// half-decryptable key blob — a torn write reads as a miss.
///
/// <para>Reads are defensive: any failure (missing file, decrypt error, malformed JSON, unknown
/// schema, expired entry, or site-identity mismatch) is reported as a miss, never an exception — a
/// miss merely means the caller re-downloads via the web portal. WatchGuard has no config-hash
/// endpoint (unlike Stormshield), so freshness is bounded purely by the site-identity hash plus a
/// max age; the OpenVPN handshake itself rejects an expired client cert, so the max age only guards
/// against a server-side cert rotation while the identity is unchanged.</para>
/// </summary>
internal sealed class WatchguardProfileCache : IWatchguardProfileCache
{
    private readonly ILogger<WatchguardProfileCache> _logger;
    private readonly string _cacheDirectory;
    private readonly TimeSpan _maxAge;

    // WatchGuard client certs are long-lived (years), and re-downloading costs a portal 2FA, so the
    // cache is kept for 30 days — long enough to avoid frequent re-provisioning, short enough to
    // bound reuse of a profile the firewall may have rotated under an unchanged server/username.
    public WatchguardProfileCache(ILogger<WatchguardProfileCache> logger)
        : this(logger, AppPaths.GetWatchguardCacheDirectory(), TimeSpan.FromDays(30))
    {
    }

    // Test/explicit ctor: a caller-supplied directory + max age. Internal for unit tests exercising
    // the on-disk behavior against a temp directory.
    internal WatchguardProfileCache(ILogger<WatchguardProfileCache> logger, string cacheDirectory, TimeSpan maxAge)
    {
        _logger = logger;
        _cacheDirectory = cacheDirectory;
        _maxAge = maxAge;
    }

    public async Task<string?> TryReadProfileAsync(
        Guid tunnelConfigId, WatchguardSettings settings, CancellationToken cancellationToken)
    {
        var path = CachePath(tunnelConfigId);
        byte[] blob;
        try
        {
            blob = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Watchguard profile cache read failed for {TunnelId}; treating as a miss.", tunnelConfigId);
            return null;
        }

        try
        {
            var json = await Task.Run(() =>
            {
                var plaintext = ProtectedData.Unprotect(blob, Entropy(tunnelConfigId), DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plaintext);
            }, cancellationToken).ConfigureAwait(false);

            var record = JsonSerializer.Deserialize<CacheRecord>(json);
            if (record is null
                || record.SchemaVersion != CacheRecord.CurrentSchemaVersion
                || !string.Equals(record.SiteIdentityHash, ComputeSiteIdentity(settings), StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(record.ProfileOvpn))
            {
                return null;
            }

            if (DateTimeOffset.UtcNow - record.CachedAtUtc > _maxAge)
            {
                _logger.LogDebug("Watchguard profile cache for {TunnelId} is older than {MaxAge}; treating as a miss.", tunnelConfigId, _maxAge);
                return null;
            }

            return record.ProfileOvpn;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // CryptographicException (DPAPI failure / tampered blob / wrong user), JsonException, etc.
            _logger.LogDebug(ex, "Watchguard profile cache for {TunnelId} could not be decoded; treating as a miss.", tunnelConfigId);
            return null;
        }
    }

    public async Task WriteProfileAsync(
        Guid tunnelConfigId, WatchguardSettings settings, string profileOvpn, CancellationToken cancellationToken)
    {
        var record = new CacheRecord
        {
            SchemaVersion = CacheRecord.CurrentSchemaVersion,
            SiteIdentityHash = ComputeSiteIdentity(settings),
            ProfileOvpn = profileOvpn,
            CachedAtUtc = DateTimeOffset.UtcNow,
        };

        Directory.CreateDirectory(_cacheDirectory);
        var path = CachePath(tunnelConfigId);
        // Unique temp name per write so concurrent writers can't clobber one another's temp file.
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            var blob = await Task.Run(() =>
            {
                var json = JsonSerializer.SerializeToUtf8Bytes(record);
                return ProtectedData.Protect(json, Entropy(tunnelConfigId), DataProtectionScope.CurrentUser);
            }, cancellationToken).ConfigureAwait(false);

            await File.WriteAllBytesAsync(tempPath, blob, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
            throw;
        }
    }

    public Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken) =>
        Task.Run(() =>
        {
            try
            {
                File.Delete(CachePath(tunnelConfigId));
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete Watchguard profile cache for {TunnelId}.", tunnelConfigId);
            }
        }, cancellationToken);

    private string CachePath(Guid tunnelConfigId) =>
        Path.Combine(_cacheDirectory, tunnelConfigId.ToString("N") + ".ovpncache");

    private static byte[] Entropy(Guid tunnelConfigId) => tunnelConfigId.ToByteArray();

    // SHA-256 of the identity-defining settings. Newline-delimited (rather than concatenated) so e.g.
    // Server="a" Port=11 and Server="a1" Port=1 can't collide. Hex, uppercase, for a stable compare.
    // Password is deliberately EXCLUDED (it isn't part of the site's identity and changes
    // independently); the TLS-trust settings ARE included so tightening trust (TrustServerCertificate
    // true -> a pinned CaPem) invalidates a profile fetched under looser trust.
    internal static string ComputeSiteIdentity(WatchguardSettings settings)
    {
        var material = string.Join('\n', new[]
        {
            settings.Server ?? string.Empty,
            settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            settings.Username ?? string.Empty,
            settings.TrustServerCertificate ? "1" : "0",
            settings.CaPem ?? string.Empty,
        });
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash);
    }

    // Internal on-disk shape. Holds a plaintext private key inside ProfileOvpn, so it only ever
    // lives inside the DPAPI-encrypted blob — never plaintext on disk.
    private sealed class CacheRecord
    {
        public const int CurrentSchemaVersion = 1;

        [JsonPropertyName("schemaVersion")] public int SchemaVersion { get; set; } = CurrentSchemaVersion;
        [JsonPropertyName("siteIdentityHash")] public string SiteIdentityHash { get; set; } = string.Empty;
        [JsonPropertyName("profileOvpn")] public string ProfileOvpn { get; set; } = string.Empty;
        [JsonPropertyName("cachedAtUtc")] public DateTimeOffset CachedAtUtc { get; set; }
    }
}
