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

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Default <see cref="IAzureVpnTokenCache"/>: stores each tunnel's Entra ID refresh token as a
/// single DPAPI-encrypted (<see cref="DataProtectionScope.CurrentUser"/>) JSON blob under
/// <c>%LOCALAPPDATA%\Wormhole\azurevpn-cache\&lt;id:N&gt;.tokencache</c>. Directly mirrors
/// <see cref="Watchguard.WatchguardProfileCache"/>, with the same two hardenings: the tunnel Id is
/// fed in as DPAPI <c>optionalEntropy</c> so a blob copied to a different tunnel's filename cannot
/// be decrypted, and writes are atomic (temp file + <see cref="File.Move(string,string,bool)"/>)
/// so an interrupted write never leaves a half-decryptable blob — a torn write reads as a miss.
///
/// <para>Reads are defensive: any failure (missing file, decrypt error, malformed JSON, unknown
/// schema, expired entry, or identity mismatch after the tunnel's tenant/audience/client changed)
/// is reported as a miss, never an exception — a miss merely means the next connect shows the
/// interactive sign-in popup. The max age is a local bound on how long a refresh token sits on
/// disk; Entra enforces the real lifetime server-side and a rejected grant also degrades to the
/// popup.</para>
/// </summary>
internal sealed class AzureVpnTokenCache : IAzureVpnTokenCache
{
    private readonly ILogger<AzureVpnTokenCache> _logger;
    private readonly string _cacheDirectory;
    private readonly TimeSpan _maxAge;

    // Entra refresh tokens for public clients live up to 90 days with sliding renewal; the cache
    // rotates the stored token on every successful silent refresh, so 90 days of inactivity is
    // the point where Entra would reject it anyway.
    public AzureVpnTokenCache(ILogger<AzureVpnTokenCache> logger)
        : this(logger, AppPaths.GetAzureVpnCacheDirectory(), TimeSpan.FromDays(90))
    {
    }

    internal AzureVpnTokenCache(ILogger<AzureVpnTokenCache> logger, string cacheDirectory, TimeSpan maxAge)
    {
        _logger = logger;
        _cacheDirectory = cacheDirectory;
        _maxAge = maxAge;
    }

    public async Task<string?> TryReadAsync(
        Guid tunnelConfigId, AzureVpnSettings settings, CancellationToken cancellationToken)
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
            _logger.LogDebug(ex, "Azure VPN token cache read failed for {TunnelId}; treating as a miss.", tunnelConfigId);
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
                || !string.Equals(record.IdentityHash, ComputeIdentity(settings), StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(record.RefreshToken))
            {
                return null;
            }

            if (DateTimeOffset.UtcNow - record.CachedAtUtc > _maxAge)
            {
                _logger.LogDebug("Azure VPN token cache for {TunnelId} is older than {MaxAge}; treating as a miss.", tunnelConfigId, _maxAge);
                return null;
            }

            return record.RefreshToken;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Azure VPN token cache for {TunnelId} could not be decoded; treating as a miss.", tunnelConfigId);
            return null;
        }
    }

    public async Task WriteAsync(
        Guid tunnelConfigId, AzureVpnSettings settings, string refreshToken, CancellationToken cancellationToken)
    {
        var record = new CacheRecord
        {
            SchemaVersion = CacheRecord.CurrentSchemaVersion,
            IdentityHash = ComputeIdentity(settings),
            RefreshToken = refreshToken,
            CachedAtUtc = DateTimeOffset.UtcNow,
        };

        Directory.CreateDirectory(_cacheDirectory);
        var path = CachePath(tunnelConfigId);
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
                _logger.LogWarning(ex, "Failed to delete Azure VPN token cache for {TunnelId}.", tunnelConfigId);
            }
        }, cancellationToken);

    private string CachePath(Guid tunnelConfigId) =>
        Path.Combine(_cacheDirectory, tunnelConfigId.ToString("N") + ".tokencache");

    private static byte[] Entropy(Guid tunnelConfigId) => tunnelConfigId.ToByteArray();

    // SHA-256 of the identity-defining settings, newline-delimited so adjacent fields can't
    // collide. A refresh token is bound to (tenant, client) — changing either must invalidate the
    // cache so the silent path doesn't present a token minted for a different identity.
    internal static string ComputeIdentity(AzureVpnSettings settings)
    {
        var material = string.Join('\n', new[]
        {
            settings.TenantId ?? string.Empty,
            settings.Audience ?? string.Empty,
            settings.ClientId ?? string.Empty,
        });
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(hash);
    }

    // Internal on-disk shape. Holds a live refresh token, so it only ever lives inside the
    // DPAPI-encrypted blob — never plaintext on disk.
    private sealed class CacheRecord
    {
        public const int CurrentSchemaVersion = 1;

        [JsonPropertyName("schemaVersion")] public int SchemaVersion { get; set; } = CurrentSchemaVersion;
        [JsonPropertyName("identityHash")] public string IdentityHash { get; set; } = string.Empty;
        [JsonPropertyName("refreshToken")] public string RefreshToken { get; set; } = string.Empty;
        [JsonPropertyName("cachedAtUtc")] public DateTimeOffset CachedAtUtc { get; set; }
    }
}
