using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.OpenVpn;
using Wormhole.Tests.Integration.Fixtures;
using Xunit;

namespace Wormhole.Tests.Integration.Services.Tunneling;

public sealed class OpenVpnEndToEndTests
{
    // OpenVPN's TLS handshake + push-reply exchange can run several seconds on a healthy
    // server (the sidecar's own ready budget is 45s). Bump the test timeout above that so
    // we attribute failures to the tunnel layer, not to an externally-clipped read.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(90);

    [SkippableFact]
    public async Task RoutesTrafficThroughTunnel()
    {
        Skip.IfNot(
            IntegrationEnvironment.OpenVpnConfigured,
            "OpenVPN integration test disabled. In CI, this typically means the -tags ovpn3 " +
            "build of wormhole-ovpnproxy failed (check the 'Build wormhole-ovpnproxy' step log). " +
            "Locally, ensure WORMHOLE_OVPNPROXY_PATH points to a built sidecar and " +
            "WORMHOLE_OPENVPN_CLIENT_PROFILE points to a .ovpn produced by tests/vpn-fixtures/bootstrap.sh.");

        var ovpnProfile = await File.ReadAllTextAsync(IntegrationEnvironment.OvpnClientProfilePath!);
        var config = new OpenVpnSidecarConfig { ProfileOvpn = ovpnProfile };

        using var cts = new CancellationTokenSource(TestTimeout);

        await using var host = await OpenVpnProcessHost.StartAsync(
            IntegrationEnvironment.OvpnProxyPath!,
            config,
            NullLogger.Instance,
            cts.Token);

        Assert.NotEqual(0, host.SocksEndpoint.Port);

        await using var stream = await Socks5Client.ConnectAsync(
            host.SocksEndpoint,
            IntegrationEnvironment.OvpnEchoTarget,
            IntegrationEnvironment.OvpnEchoPort,
            cts.Token);

        var ping = Encoding.ASCII.GetBytes("ping");
        await stream.WriteAsync(ping, cts.Token);

        var buf = new byte[4];
        await stream.ReadExactlyAsync(buf, cts.Token);
        Assert.Equal("ping", Encoding.ASCII.GetString(buf));
    }
}
