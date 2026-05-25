using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardTunnelProviderTests
{
    [Fact]
    public void Kind_IsWatchguard()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

        Assert.Equal(TunnelKind.Watchguard, provider.Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_RejectsKindMismatchedBlob()
    {
        // A blob serialized from a different kind's settings shape will deserialize into
        // WatchguardSettings with empty/default fields. The provider's symmetric pre-flight
        // catches this and surfaces a "re-enter settings" error before any network IO.
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };
        var emptyJson = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new WatchguardSettings());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.EstablishAsync(cfg, emptyJson, CancellationToken.None));
        Assert.Contains("Server", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class NullOtpPromptService : IOtpPromptService
    {
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }
}
