using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

/// <summary>
/// Exercises the on-disk behavior of <see cref="WatchguardProfileCache"/> against a temp directory:
/// the DPAPI round-trip, site-identity invalidation, and max-age expiry. The cache is the mechanism
/// that makes WatchGuard 2FA a single factor — a reconnect reuses the cached profile so the one
/// factor flows to the OpenVPN CRV1 layer instead of being burned on the portal download.
/// </summary>
public class WatchguardProfileCacheTests : IDisposable
{
    private readonly string _dir;

    public WatchguardProfileCacheTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wh-wg-cache-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    private WatchguardProfileCache NewCache(TimeSpan? maxAge = null) =>
        new(NullLogger<WatchguardProfileCache>.Instance, _dir, maxAge ?? TimeSpan.FromDays(30));

    private static WatchguardSettings Settings() => new()
    {
        Server = "vpn.example.com",
        Port = 443,
        Username = "alice",
        Password = "secret",
        TrustServerCertificate = false,
        CaPem = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
    };

    [Fact]
    public async Task TryRead_BeforeAnyWrite_IsMiss()
    {
        var cache = NewCache();
        Assert.Null(await cache.TryReadProfileAsync(Guid.NewGuid(), Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task WriteThenRead_RoundTripsTheProfile()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        const string profile = "client\nremote vpn.example.com 443 tcp\n<ca>\nCA\n</ca>\n";

        await cache.WriteProfileAsync(id, Settings(), profile, CancellationToken.None);

        Assert.Equal(profile, await cache.TryReadProfileAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task TryRead_AfterServerChanged_IsMiss()
    {
        // A changed site identity (server/username/CA/trust) must invalidate a cached profile so the
        // next connect re-downloads against the new identity rather than reusing the wrong cert/key.
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteProfileAsync(id, Settings(), "profile", CancellationToken.None);

        var moved = Settings();
        moved.Server = "vpn2.example.com";

        Assert.Null(await cache.TryReadProfileAsync(id, moved, CancellationToken.None));
    }

    [Fact]
    public async Task TryRead_PastMaxAge_IsMiss()
    {
        var id = Guid.NewGuid();
        // Write with a normal cache, then read through one whose max age is already elapsed.
        await NewCache().WriteProfileAsync(id, Settings(), "profile", CancellationToken.None);

        var expired = NewCache(TimeSpan.Zero);
        Assert.Null(await expired.TryReadProfileAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Delete_RemovesTheCachedProfile()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteProfileAsync(id, Settings(), "profile", CancellationToken.None);

        await cache.DeleteAsync(id, CancellationToken.None);

        Assert.Null(await cache.TryReadProfileAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Entropy_IsScopedToTunnelId()
    {
        // The tunnel Id is DPAPI optionalEntropy, so a blob written for one tunnel must not decrypt
        // when read under a different tunnel Id (defends against a copied cache file).
        var cache = NewCache();
        var idA = Guid.NewGuid();
        await cache.WriteProfileAsync(idA, Settings(), "profile", CancellationToken.None);

        // Copy A's cache file onto B's path, then attempt to read as B → entropy mismatch → miss.
        var idB = Guid.NewGuid();
        File.Copy(
            Path.Combine(_dir, idA.ToString("N") + ".ovpncache"),
            Path.Combine(_dir, idB.ToString("N") + ".ovpncache"));

        Assert.Null(await cache.TryReadProfileAsync(idB, Settings(), CancellationToken.None));
    }
}
