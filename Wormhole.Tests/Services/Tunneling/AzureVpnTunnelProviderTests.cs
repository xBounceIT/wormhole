using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling.AzureVpn;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class AzureVpnTunnelProviderTests
{
    private static AzureVpnSettings Settings() => new()
    {
        Servers = new List<string> { "gw.vpn.azure.com" },
        TenantId = "tenant-guid",
        Audience = "audience-guid",
    };

    private static AzureVpnTunnelProvider NewProvider(
        IAzureVpnAuthService? auth = null,
        IAzureVpnOAuthClient? oauth = null,
        IAzureVpnTokenCache? cache = null) =>
        new(auth ?? new FakeAuthService(),
            oauth ?? new FakeOAuthClient(),
            cache ?? new FakeAzureVpnTokenCache(),
            NullLogger<AzureVpnTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

    [Fact]
    public void Kind_IsAzureVpn()
    {
        Assert.Equal(TunnelKind.AzureVpn, NewProvider().Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.AzureVpn };
        await Assert.ThrowsAnyAsync<Exception>(() =>
            NewProvider().EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_RejectsKindMismatchedBlob_NoServers()
    {
        // A blob from another kind deserializes into AzureVpnSettings with empty fields; the
        // provider must fail with an actionable message before any OAuth or popup work.
        var blob = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { Host = "fortigate" });
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.AzureVpn };

        var auth = new FakeAuthService();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider(auth: auth).EstablishAsync(cfg, blob, CancellationToken.None));
        Assert.Contains("gateway server", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, auth.Calls);
    }

    [Fact]
    public async Task EstablishAsync_MissingTenant_FailsBeforeInteractiveSignIn()
    {
        var settings = Settings();
        settings.TenantId = string.Empty;
        var blob = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(settings);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.AzureVpn };

        var auth = new FakeAuthService();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider(auth: auth).EstablishAsync(cfg, blob, CancellationToken.None));
        Assert.Contains("tenant", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, auth.Calls);
    }

    [Fact]
    public async Task ResolveAccessToken_CachedRefreshTokenRedeems_NoPopup_RotatesCache()
    {
        var id = Guid.NewGuid();
        var cache = new FakeAzureVpnTokenCache();
        cache.Seed(id, "refresh-old");
        var oauth = new FakeOAuthClient
        {
            RefreshResult = new AzureVpnTokenResult("access-silent", "refresh-rotated"),
        };
        var auth = new FakeAuthService();

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            oauth, cache, auth, NullLogger.Instance, id, "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-silent", token);
        Assert.Equal(0, auth.Calls);
        Assert.Equal("refresh-old", oauth.LastRefreshTokenSent);
        // Entra rotates refresh tokens per redemption — the new one must replace the old.
        Assert.Equal("refresh-rotated", cache.LastWritten);
    }

    [Fact]
    public async Task ResolveAccessToken_RefreshGrantsNoNewRefreshToken_KeepsOldOne()
    {
        var id = Guid.NewGuid();
        var cache = new FakeAzureVpnTokenCache();
        cache.Seed(id, "refresh-old");
        var oauth = new FakeOAuthClient
        {
            RefreshResult = new AzureVpnTokenResult("access-silent", RefreshToken: null),
        };

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            oauth, cache, new FakeAuthService(), NullLogger.Instance, id, "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-silent", token);
        Assert.Equal("refresh-old", cache.LastWritten);
    }

    [Fact]
    public async Task ResolveAccessToken_RefreshRejected_FallsBackToPopup_AndCachesNewToken()
    {
        var id = Guid.NewGuid();
        var cache = new FakeAzureVpnTokenCache();
        cache.Seed(id, "refresh-expired");
        var oauth = new FakeOAuthClient { RefreshResult = null }; // Entra rejected the grant
        var auth = new FakeAuthService
        {
            Result = new AzureVpnTokenResult("access-interactive", "refresh-fresh"),
        };

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            oauth, cache, auth, NullLogger.Instance, id, "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-interactive", token);
        Assert.Equal(1, auth.Calls);
        Assert.Equal("refresh-fresh", cache.LastWritten);
    }

    [Fact]
    public async Task ResolveAccessToken_RefreshTransportFailure_StillFallsBackToPopup()
    {
        // Offline / proxy failures on the silent POST must degrade to the popup (which surfaces a
        // much clearer error), not kill the connect with a bare HttpRequestException.
        var id = Guid.NewGuid();
        var cache = new FakeAzureVpnTokenCache();
        cache.Seed(id, "refresh-old");
        var oauth = new FakeOAuthClient { Throws = new HttpRequestException("offline") };
        var auth = new FakeAuthService
        {
            Result = new AzureVpnTokenResult("access-interactive", null),
        };

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            oauth, cache, auth, NullLogger.Instance, id, "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-interactive", token);
        Assert.Equal(1, auth.Calls);
    }

    [Fact]
    public async Task ResolveAccessToken_NoCache_GoesStraightToPopup()
    {
        var oauth = new FakeOAuthClient { Throws = new InvalidOperationException("must not be called") };
        var auth = new FakeAuthService
        {
            Result = new AzureVpnTokenResult("access-interactive", "refresh-1"),
        };
        var cache = new FakeAzureVpnTokenCache();

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            oauth, cache, auth, NullLogger.Instance, Guid.NewGuid(), "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-interactive", token);
        Assert.Equal(0, oauth.RefreshCalls);
        Assert.Equal("refresh-1", cache.LastWritten);
    }

    [Fact]
    public async Task ResolveAccessToken_CacheWriteFailure_DoesNotKillConnect()
    {
        // The access token is already in hand; a failed cache write costs the next connect one
        // popup, nothing more.
        var cache = new FakeAzureVpnTokenCache { FailWrites = true };
        var auth = new FakeAuthService
        {
            Result = new AzureVpnTokenResult("access-interactive", "refresh-1"),
        };

        var token = await AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
            new FakeOAuthClient(), cache, auth, NullLogger.Instance, Guid.NewGuid(), "vpn", Settings(), CancellationToken.None);

        Assert.Equal("access-interactive", token);
    }

    [Fact]
    public async Task ResolveAccessToken_UserCancelsPopup_Propagates()
    {
        var auth = new FakeAuthService
        {
            Throws = new UserInteractionCancelledException("Microsoft sign-in was cancelled before authentication completed."),
        };

        var ex = await Assert.ThrowsAsync<UserInteractionCancelledException>(() =>
            AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
                new FakeOAuthClient(), new FakeAzureVpnTokenCache(), auth, NullLogger.Instance,
                Guid.NewGuid(), "vpn", Settings(), CancellationToken.None));
        Assert.Contains("cancelled", ex.Message);
    }

    [Fact]
    public async Task ResolveAccessToken_CancellationDuringRefresh_Propagates()
    {
        var id = Guid.NewGuid();
        var cache = new FakeAzureVpnTokenCache();
        cache.Seed(id, "refresh-old");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var oauth = new FakeOAuthClient { Throws = new OperationCanceledException(cts.Token) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AzureVpnTunnelProvider.ResolveAccessTokenCoreAsync(
                oauth, cache, new FakeAuthService(), NullLogger.Instance, id, "vpn", Settings(), cts.Token));
    }

    private sealed class FakeAuthService : IAzureVpnAuthService
    {
        public int Calls { get; private set; }
        public AzureVpnTokenResult? Result { get; set; }
        public Exception? Throws { get; set; }

        public Task<AzureVpnTokenResult> AuthenticateInteractiveAsync(
            AzureVpnSettings settings, string configName, CancellationToken cancellationToken)
        {
            Calls++;
            if (Throws is not null) throw Throws;
            return Task.FromResult(Result ?? throw new InvalidOperationException("FakeAuthService has no result configured."));
        }
    }

    private sealed class FakeOAuthClient : IAzureVpnOAuthClient
    {
        public int RefreshCalls { get; private set; }
        public string? LastRefreshTokenSent { get; private set; }
        public AzureVpnTokenResult? RefreshResult { get; set; }
        public Exception? Throws { get; set; }

        public Task<AzureVpnTokenResult?> RefreshAsync(
            AzureVpnSettings settings, string refreshToken, CancellationToken cancellationToken)
        {
            RefreshCalls++;
            LastRefreshTokenSent = refreshToken;
            if (Throws is not null) throw Throws;
            return Task.FromResult(RefreshResult);
        }
    }
}
