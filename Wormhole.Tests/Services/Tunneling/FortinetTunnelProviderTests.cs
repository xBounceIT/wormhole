using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Fortinet;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class FortinetTunnelProviderTests
{
    [Fact]
    public void Kind_IsFortinet()
    {
        var provider = CreateProvider();

        Assert.Equal(TunnelKind.Fortinet, provider.Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var provider = CreateProvider();
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Fortinet };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_SurfacesMissingBinaryClearly()
    {
        // No sidecar binary is built in the test process — we want the surfaced exception
        // to clearly point at the missing wormhole-fortiproxy.exe rather than e.g. a JSON
        // parse error or a generic Process-start fault. Real tunnels require the build's
        // FetchFortiProxy target to have produced the binary; this asserts the failure
        // mode when it didn't.
        var provider = CreateProvider();
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Fortinet };
        var settings = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new FortinetSettings
        {
            Host = "vpn.example.com",
            Port = 443,
            Username = "alice",
            Password = "s3cret",
        });

        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, settings, CancellationToken.None));
        // Either FileNotFoundException (wrapped by FortinetProcessHost) or a Win32Exception
        // depending on platform path quirks — both contain the binary name we want users to see.
        Assert.Contains("fortiproxy", (ex.Message + " " + (ex.InnerException?.Message ?? "")),
            StringComparison.OrdinalIgnoreCase);
    }

    private static FortinetTunnelProvider CreateProvider() =>
        new(
            NullLogger<FortinetTunnelProvider>.Instance,
            NullLoggerFactory.Instance,
            new UnexpectedSamlAuthService());

    private sealed class UnexpectedSamlAuthService : IFortinetSamlAuthService
    {
        public Task<FortinetSamlAuthResult> AuthenticateAsync(
            FortinetSettings settings,
            string configName,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("SSO should not be invoked by this test.");
    }
}
