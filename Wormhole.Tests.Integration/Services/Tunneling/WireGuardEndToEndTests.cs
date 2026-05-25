using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.WireGuard;
using Wormhole.Tests.Integration.Fixtures;
using Xunit;
using Xunit.Abstractions;

namespace Wormhole.Tests.Integration.Services.Tunneling;

public sealed class WireGuardEndToEndTests
{
    // 60s covers wgproxy cold start + handshake + SOCKS5 negotiate + echo round-trip on a
    // cold CI runner. The sidecar's own READY budget is 15s, so anything above ~30s here is
    // headroom for runner-scheduling jitter rather than tunnel latency.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(60);

    private readonly ITestOutputHelper _output;

    public WireGuardEndToEndTests(ITestOutputHelper output) => _output = output;

    [SkippableFact]
    public async Task RoutesTrafficThroughTunnel()
    {
        Skip.IfNot(
            IntegrationEnvironment.WireGuardConfigured,
            "Set WORMHOLE_WGPROXY_PATH and WORMHOLE_WG_CLIENT_CONFIG (and run tests/vpn-fixtures/bootstrap.sh + docker compose up) to enable.");

        var configJson = await File.ReadAllTextAsync(IntegrationEnvironment.WgClientConfigPath!);
        var config = JsonSerializer.Deserialize<WireGuardSidecarConfig>(configJson)
            ?? throw new InvalidOperationException("Client config JSON deserialized to null.");

        using var cts = new CancellationTokenSource(TestTimeout);

        await using var host = await WireGuardProcessHost.StartAsync(
            IntegrationEnvironment.WgProxyPath!,
            config,
            new TestOutputLogger(_output),
            cts.Token);

        Assert.NotEqual(0, host.SocksEndpoint.Port);

        // Round-trip through the SOCKS5 endpoint to an echo server that is only reachable
        // through the WireGuard tunnel (its IP lives inside the peer's AllowedIPs / server
        // routing). If the sidecar SOCKS5 surface or the tunnel data plane regressed, this
        // either times out (no route to host) or returns the wrong bytes (SOCKS5 wire bug).
        await using var stream = await Socks5Client.ConnectAsync(
            host.SocksEndpoint,
            IntegrationEnvironment.WgEchoTarget,
            IntegrationEnvironment.WgEchoPort,
            cts.Token);

        var ping = Encoding.ASCII.GetBytes("ping");
        await stream.WriteAsync(ping, cts.Token);

        var buf = new byte[4];
        await stream.ReadExactlyAsync(buf, cts.Token);
        Assert.Equal("ping", Encoding.ASCII.GetString(buf));
    }

    [SkippableFact]
    public async Task LocalForwarderRoutesTrafficThroughTunnel()
    {
        Skip.IfNot(
            IntegrationEnvironment.WireGuardConfigured,
            "Set WORMHOLE_WGPROXY_PATH and WORMHOLE_WG_CLIENT_CONFIG (and run tests/vpn-fixtures/bootstrap.sh + docker compose up) to enable.");

        var configJson = await File.ReadAllTextAsync(IntegrationEnvironment.WgClientConfigPath!);
        var config = JsonSerializer.Deserialize<WireGuardSidecarConfig>(configJson)
            ?? throw new InvalidOperationException("Client config JSON deserialized to null.");

        using var cts = new CancellationTokenSource(TestTimeout);

        await using var host = await WireGuardProcessHost.StartAsync(
            IntegrationEnvironment.WgProxyPath!,
            config,
            new TestOutputLogger(_output),
            cts.Token);

        // This is the path RDP takes: a SocksTunnelInstance wraps the sidecar's SOCKS5
        // endpoint, BindLocalForwarderAsync hands back a 127.0.0.1:<port> loopback listener,
        // and the consumer (ActiveX in prod, TcpClient here) connects to it without ever
        // speaking SOCKS5. No onDispose hook — sidecar lifetime is owned by `await using host`.
        await using var tunnel = new SocksTunnelInstance(host.SocksEndpoint, new TestOutputLogger(_output));

        var localPort = await tunnel.BindLocalForwarderAsync(
            IntegrationEnvironment.WgEchoTarget,
            IntegrationEnvironment.WgEchoPort,
            cts.Token);
        Assert.NotEqual(0, localPort);

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", localPort, cts.Token);
        var stream = client.GetStream();

        var ping = Encoding.ASCII.GetBytes("ping");
        await stream.WriteAsync(ping, cts.Token);

        var buf = new byte[4];
        await stream.ReadExactlyAsync(buf, cts.Token);
        Assert.Equal("ping", Encoding.ASCII.GetString(buf));
    }
}
