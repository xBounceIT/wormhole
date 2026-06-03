using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

/// <summary>
/// On-disk tests for the real DPAPI-backed <see cref="StormshieldConfigCache"/> (the provider tests use a
/// fake, so these cover the security-critical machinery the fake bypasses: DPAPI round-trip + tunnel-Id
/// entropy, the site-identity guard, max-age expiry, the OpenVPN-shape re-validation, atomic overwrite, and
/// miss-on-corruption). DPAPI CurrentUser works in a normal Windows test process.
/// </summary>
public sealed class StormshieldConfigCacheTests : IDisposable
{
    private const string SampleProfile = "client\ndev tun\nremote fw 443\n<ca>cert</ca>\n";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "wormhole-sccache-" + Guid.NewGuid().ToString("N"));

    public StormshieldConfigCacheTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private StormshieldConfigCache NewCache(TimeSpan? maxAge = null) =>
        new(NullLogger<StormshieldConfigCache>.Instance, _dir, maxAge ?? TimeSpan.FromDays(7));

    private static StormshieldSettings Settings(string server = "rpv.example.com", string user = "alice") => new()
    {
        Server = server,
        Port = 443,
        Username = user,
        Password = "stored-password",
        AppToken = "sslclient",
        Mode = StormshieldConnectionMode.Automatic,
        UseOtp = true,
    };

    private static string CachePath(string dir, Guid id) => Path.Combine(dir, id.ToString("N") + ".ovpncache");

    [Fact]
    public async Task WriteThenRead_RoundTripsHashAndProfile()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();

        await cache.WriteAsync(id, Settings(), "HASH123", SampleProfile, CancellationToken.None);
        var record = await cache.TryReadAsync(id, Settings(), CancellationToken.None);

        Assert.NotNull(record);
        Assert.Equal("HASH123", record!.ConfigHash);
        Assert.Contains("remote fw 443", record.ProfileOvpn);
    }

    [Fact]
    public async Task Read_NoFile_ReturnsNull()
    {
        var cache = NewCache();
        Assert.Null(await cache.TryReadAsync(Guid.NewGuid(), Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Read_DifferentTunnelId_ReturnsNull()
    {
        var cache = NewCache();
        await cache.WriteAsync(Guid.NewGuid(), Settings(), "H", SampleProfile, CancellationToken.None);

        Assert.Null(await cache.TryReadAsync(Guid.NewGuid(), Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Read_AfterServerChange_ReturnsNull()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteAsync(id, Settings(server: "a.example.com"), "H", SampleProfile, CancellationToken.None);

        // Same tunnel Id, different server → site identity no longer matches → miss (no wrong-server reuse).
        Assert.Null(await cache.TryReadAsync(id, Settings(server: "b.example.com"), CancellationToken.None));
    }

    [Fact]
    public async Task Read_AfterTrustTightened_ReturnsNull()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        var loose = Settings();
        loose.TrustServerCertificate = true;
        await cache.WriteAsync(id, loose, "H", SampleProfile, CancellationToken.None);

        var strict = Settings();
        strict.TrustServerCertificate = false;
        strict.CaPem = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----";
        Assert.Null(await cache.TryReadAsync(id, strict, CancellationToken.None));
    }

    [Fact]
    public async Task Read_Expired_ReturnsNull()
    {
        var id = Guid.NewGuid();
        await NewCache().WriteAsync(id, Settings(), "H", SampleProfile, CancellationToken.None);

        // A cache whose max-age has already elapsed treats the just-written record as too old.
        var expiring = NewCache(maxAge: TimeSpan.Zero);
        Assert.Null(await expiring.TryReadAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Read_NonOpenVpnProfile_ReturnsNull()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteAsync(id, Settings(), "H", "this is not an openvpn profile", CancellationToken.None);

        Assert.Null(await cache.TryReadAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Read_TamperedOrNonDpapiFile_ReturnsNull()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteAsync(id, Settings(), "H", SampleProfile, CancellationToken.None);

        // Corrupt the encrypted blob → DPAPI unprotect fails → miss, never throws to the caller.
        await File.WriteAllBytesAsync(CachePath(_dir, id), new byte[] { 1, 2, 3, 4, 5 });
        Assert.Null(await cache.TryReadAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Delete_RemovesCachedProfile()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteAsync(id, Settings(), "H", SampleProfile, CancellationToken.None);

        await cache.DeleteAsync(id, CancellationToken.None);

        Assert.False(File.Exists(CachePath(_dir, id)));
        Assert.Null(await cache.TryReadAsync(id, Settings(), CancellationToken.None));
    }

    [Fact]
    public async Task Delete_NonExistent_IsNoOp()
    {
        var cache = NewCache();
        await cache.DeleteAsync(Guid.NewGuid(), CancellationToken.None); // must not throw
    }

    [Fact]
    public async Task Write_OverwritesPreviousRecord()
    {
        var cache = NewCache();
        var id = Guid.NewGuid();
        await cache.WriteAsync(id, Settings(), "OLD", "client\ndev tun\nremote old 443\n", CancellationToken.None);
        await cache.WriteAsync(id, Settings(), "NEW", "client\ndev tun\nremote new 443\n", CancellationToken.None);

        var record = await cache.TryReadAsync(id, Settings(), CancellationToken.None);
        Assert.NotNull(record);
        Assert.Equal("NEW", record!.ConfigHash);
        Assert.Contains("remote new 443", record.ProfileOvpn);
    }
}
