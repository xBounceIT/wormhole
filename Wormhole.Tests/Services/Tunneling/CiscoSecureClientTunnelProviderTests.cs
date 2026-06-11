using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling.CiscoSecureClient;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class CiscoSecureClientTunnelProviderTests
{
    private static CiscoSecureClientTunnelProvider NewProvider() => new(
        NullLogger<CiscoSecureClientTunnelProvider>.Instance,
        NullLoggerFactory.Instance);

    [Fact]
    public void Kind_IsCiscoSecureClient()
    {
        Assert.Equal(TunnelKind.CiscoSecureClient, NewProvider().Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var provider = NewProvider();
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.CiscoSecureClient };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_RejectsKindMismatchedBlob()
    {
        // A blob whose JSON shape doesn't overlap with CiscoSecureClientSettings (here: a
        // WireGuard payload) deserializes to an all-default settings object with an empty Host.
        // The provider's pre-flight must reject that with an actionable message rather than
        // launching the sidecar and waiting for a timeout.
        var provider = NewProvider();
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "mismatch", Kind = TunnelKind.CiscoSecureClient };
        var wrong = JsonSerializer.SerializeToUtf8Bytes(new WireGuardSettings
        {
            InterfacePrivateKey = "k",
            InterfaceAddress = "10.0.0.2/32",
            PeerPublicKey = "p",
            PeerEndpoint = "vpn:51820",
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.EstablishAsync(cfg, wrong, CancellationToken.None));
        Assert.Contains("Cisco Secure Client", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EstablishAsync_SurfacesMissingBinaryClearly()
    {
        // No sidecar binary is built in the test process — the surfaced exception should clearly
        // point at the missing wormhole-ciscoproxy.exe rather than a JSON parse error or a
        // generic Process-start fault.
        var provider = NewProvider();
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.CiscoSecureClient };
        var settings = JsonSerializer.SerializeToUtf8Bytes(new CiscoSecureClientSettings
        {
            Host = "vpn.example.com",
            Port = 443,
            Username = "alice",
            Password = "s3cret",
        });

        var ex = await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, settings, CancellationToken.None));
        Assert.Contains("ciscoproxy", ex.Message + " " + (ex.InnerException?.Message ?? ""),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SidecarConfig_SerializesSnakeCaseWireContract()
    {
        // The Go sidecar decodes these exact JSON keys; a rename on the C# side would silently
        // break the handshake. Lock the contract here.
        var json = JsonSerializer.Serialize(new CiscoSecureClientSidecarConfig
        {
            Host = "vpn.example.com",
            Port = 8443,
            Username = "alice",
            Password = "s3cret",
            Group = "Contractors",
            SecondaryPassword = "pin",
            TotpSecret = "JBSWY3DPEHPK3PXP",
            TrustServerCertificate = true,
            ServerCertSha256Pin = "ab:cd",
        });

        Assert.Contains("\"host\":", json);
        Assert.Contains("\"secondary_password\":", json);
        Assert.Contains("\"totp_secret\":", json);
        Assert.Contains("\"trust_server_certificate\":", json);
        Assert.Contains("\"server_cert_sha256_pin\":", json);
    }
}
