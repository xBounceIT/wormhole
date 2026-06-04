using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Default <see cref="IStormshieldConfigCache"/>: stores each tunnel's downloaded Automatic-mode profile
/// as a single DPAPI-encrypted (<see cref="DataProtectionScope.CurrentUser"/>) JSON blob under
/// <c>%LOCALAPPDATA%\Wormhole\stormshield-cache\&lt;id:N&gt;.ovpncache</c>. This mirrors the protection
/// <see cref="CredentialService"/> already gives the per-tunnel secret blob (which likewise holds a
/// plaintext key), with two hardenings layered on:
///
/// <list type="bullet">
///   <item>the tunnel Id is fed in as DPAPI <c>optionalEntropy</c>, so a blob copied to a different
///   tunnel's filename cannot be decrypted;</item>
///   <item>writes are atomic (temp file + <see cref="File.Move(string,string,bool)"/>), so an
///   interrupted write never leaves a half-decryptable key blob — a torn write reads as a miss.</item>
/// </list>
///
/// <para>Reads are defensive: any failure (missing file, decrypt error, malformed JSON, unknown schema,
/// expired entry, site-identity mismatch, or a body that no longer looks like an OpenVPN profile) is
/// reported as a miss, never an exception — a miss merely means the caller re-downloads. A configurable
/// max age bounds how long a cached private key may be reused even while the firewall keeps reporting
/// "unchanged".</para>
/// </summary>
internal sealed class StormshieldConfigCache : IStormshieldConfigCache
{
    private readonly ILogger<StormshieldConfigCache> _logger;
    private readonly string _cacheDirectory;
    private readonly TimeSpan _maxAge;

    public StormshieldConfigCache(ILogger<StormshieldConfigCache> logger)
        : this(logger, AppPaths.GetStormshieldCacheDirectory(), TimeSpan.FromDays(7))
    {
    }

    // Test/explicit ctor: a caller-supplied directory + max age. Kept internal for unit tests that
    // exercise the on-disk behavior against a temp directory.
    internal StormshieldConfigCache(ILogger<StormshieldConfigCache> logger, string cacheDirectory, TimeSpan maxAge)
    {
        _logger = logger;
        _cacheDirectory = cacheDirectory;
        _maxAge = maxAge;
    }

    public async Task<StormshieldCacheRecord?> TryReadAsync(
        Guid tunnelConfigId, StormshieldSettings settings, CancellationToken cancellationToken)
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
            _logger.LogDebug(ex, "Stormshield config cache read failed for {TunnelId}; treating as a miss.", tunnelConfigId);
            return null;
        }

        try
        {
            var json = await Task.Run(() =>
            {
                var plaintext = ProtectedData.Unprotect(blob, Entropy(tunnelConfigId), DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plaintext);
            }, cancellationToken).ConfigureAwait(false);

            var record = JsonSerializer.Deserialize<StormshieldCacheRecord>(json);
            if (record is null
                || record.SchemaVersion != StormshieldCacheRecord.CurrentSchemaVersion
                || !string.Equals(record.SiteIdentityHash, ComputeSiteIdentity(settings), StringComparison.Ordinal)
                || string.IsNullOrEmpty(record.ProfileOvpn)
                || !StormshieldPortalClient.LooksLikeOpenVpnProfile(record.ProfileOvpn))
            {
                return null;
            }

            if (DateTimeOffset.UtcNow - record.CachedAtUtc > _maxAge)
            {
                _logger.LogDebug("Stormshield config cache for {TunnelId} is older than {MaxAge}; treating as a miss.", tunnelConfigId, _maxAge);
                return null;
            }

            return record;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // CryptographicException (DPAPI failure / tampered blob / wrong user), JsonException, etc.
            _logger.LogDebug(ex, "Stormshield config cache for {TunnelId} could not be decoded; treating as a miss.", tunnelConfigId);
            return null;
        }
    }

    public async Task WriteAsync(
        Guid tunnelConfigId, StormshieldSettings settings, string configHash, string profileOvpn,
        CancellationToken cancellationToken)
    {
        var record = new StormshieldCacheRecord
        {
            SchemaVersion = StormshieldCacheRecord.CurrentSchemaVersion,
            SiteIdentityHash = ComputeSiteIdentity(settings),
            ConfigHash = configHash ?? string.Empty,
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
                _logger.LogWarning(ex, "Failed to delete Stormshield config cache for {TunnelId}.", tunnelConfigId);
            }
        }, cancellationToken);

    private string CachePath(Guid tunnelConfigId) =>
        Path.Combine(_cacheDirectory, tunnelConfigId.ToString("N") + ".ovpncache");

    private static byte[] Entropy(Guid tunnelConfigId) => tunnelConfigId.ToByteArray();

    // SHA-256 of the identity-defining settings. Newline-delimited (rather than concatenated) so e.g.
    // Server="a" Port=11 and Server="a1" Port=1 can't collide. Hex, uppercase for a stable comparison.
    // Password is deliberately EXCLUDED (it isn't part of the site's identity and changes independently);
    // the TLS-trust settings ARE included so tightening trust (e.g. TrustServerCertificate true -> a pinned
    // CaPem) invalidates a profile that was fetched under looser trust.
    internal static string ComputeSiteIdentity(StormshieldSettings settings)
    {
        var material = string.Join('\n', new[]
        {
            settings.Server ?? string.Empty,
            settings.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            settings.Username ?? string.Empty,
            string.IsNullOrWhiteSpace(settings.AppToken) ? StormshieldSettings.DefaultAppToken : settings.AppToken,
            settings.TrustServerCertificate ? "1" : "0",
            settings.CaPem ?? string.Empty,
        });
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash);
    }
}
