using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.OpenVpn;
using Wormhole.Tests.Integration.Fixtures;
using Xunit;
using Xunit.Abstractions;

namespace Wormhole.Tests.Integration.Services.Tunneling;

public sealed class OpenVpnEndToEndTests
{
    // OpenVPN's TLS handshake + push-reply exchange can run several seconds on a healthy
    // server, and some profiles need transport fallback attempts before becoming ready.
    // Keep the test timeout above the sidecar host budget so failures are attributed to
    // the tunnel layer, not to an externally-clipped read.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(150);

    private readonly ITestOutputHelper _output;

    public OpenVpnEndToEndTests(ITestOutputHelper output) => _output = output;

    [SkippableFact]
    public Task RoutesTrafficThroughTunnel() =>
        EchoRoundTripAsync(IntegrationEnvironment.OvpnEchoTarget, assertGateway: true);

    // Same round-trip, but the target is a DNS name only the fixture's dnsmasq container
    // (pushed by the server as `dhcp-option DNS`) can resolve. Proves the sidecar surfaces
    // the pushed DNS into its netstack resolver and resolves through the tunnel — the
    // failure mode this guards against is hostname dials dying with "cannot marshal DNS
    // message" because the netstack was created with no DNS servers at all.
    [SkippableFact]
    public Task ResolvesHostnamesViaPushedTunnelDns() =>
        EchoRoundTripAsync(IntegrationEnvironment.OvpnEchoHostname, assertGateway: false);

    private async Task EchoRoundTripAsync(string target, bool assertGateway)
    {
        Skip.IfNot(
            IntegrationEnvironment.OpenVpnConfigured,
            "OpenVPN integration test disabled. In CI, this typically means the -tags ovpn3 " +
            "build of wormhole-ovpnproxy failed (check the 'Build wormhole-ovpnproxy' step log). " +
            "Locally, ensure WORMHOLE_OVPNPROXY_PATH points to a built sidecar and " +
            "WORMHOLE_OPENVPN_CLIENT_PROFILE points to a .ovpn produced by tests/vpn-fixtures/bootstrap.sh.");

        var ovpnProfile = await File.ReadAllTextAsync(IntegrationEnvironment.OvpnClientProfilePath!);
        var config = new OpenVpnSidecarConfig { ProfileOvpn = ovpnProfile };
        var logger = new TestOutputLogger(_output);

        using var cts = new CancellationTokenSource(TestTimeout);

        await using var host = await OpenVpnProcessHost.StartAsync(
            IntegrationEnvironment.OvpnProxyPath!,
            config,
            logger,
            cts.Token);

        Assert.NotEqual(0, host.SocksEndpoint.Port);

        await using var stream = await Socks5Client.ConnectAsync(
            host.SocksEndpoint,
            target,
            IntegrationEnvironment.OvpnEchoPort,
            cts.Token);

        var ping = Encoding.ASCII.GetBytes("ping");
        await stream.WriteAsync(ping, cts.Token);

        var buf = new byte[4];
        await stream.ReadExactlyAsync(buf, cts.Token);
        Assert.Equal("ping", Encoding.ASCII.GetString(buf));

        if (assertGateway)
        {
            await AssertEventuallyLoggedAsync(
                logger,
                line => line.Contains("openvpn: tunnel config", StringComparison.Ordinal)
                    && !line.Contains("gateway4=(none)", StringComparison.Ordinal),
                cts.Token);
        }
    }

    private static async Task AssertEventuallyLoggedAsync(
        TestOutputLogger logger,
        Func<string, bool> predicate,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTimeOffset.UtcNow < deadline)
        {
            foreach (var line in logger.Lines)
            {
                if (predicate(line)) return;
            }
            await Task.Delay(50, cancellationToken);
        }

        Assert.Fail("Expected sidecar log line was not captured. Logs:" + Environment.NewLine
            + string.Join(Environment.NewLine, logger.Lines));
    }
}
