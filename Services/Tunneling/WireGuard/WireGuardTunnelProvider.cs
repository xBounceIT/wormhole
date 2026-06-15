using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.WireGuard;

public sealed class WireGuardTunnelProvider : ITunnelProvider
{
    private readonly ILogger<WireGuardTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public WireGuardTunnelProvider(ILogger<WireGuardTunnelProvider> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.WireGuard;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<WireGuardSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid WireGuard payload.");

        var sidecar = new WireGuardSidecarConfig
        {
            InterfacePrivateKey = settings.InterfacePrivateKey,
            InterfaceAddress = settings.InterfaceAddress,
            Mtu = settings.Mtu,
            Dns = settings.Dns ?? new(),
            PeerPublicKey = settings.PeerPublicKey,
            PeerPresharedKey = settings.PeerPresharedKey,
            PeerEndpoint = settings.PeerEndpoint,
            AllowedIps = settings.AllowedIps ?? new(),
            PersistentKeepaliveSeconds = settings.PersistentKeepaliveSeconds,
        };

        var sidecarPath = AppPaths.GetWgProxyExecutablePath();
        _logger.LogDebug("Launching WireGuard sidecar at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        var host = await WireGuardProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<WireGuardProcessHost>(), cancellationToken)
            .ConfigureAwait(false);

        // Wrap-after-start: the sidecar process is alive once StartAsync returns. If the
        // SocksTunnelInstance ctor ever throws (today its args can't trigger one, but a
        // future ArgumentNullException.ThrowIfNull added inside the ctor would), the host
        // would be left running with no managed reference to dispose it. Guard against that
        // by tearing down the host on construction failure.
        try
        {
            return new SocksTunnelInstance(
                host.SocksEndpoint,
                _loggerFactory.CreateLogger<SocksTunnelInstance>(),
                onDispose: host.DisposeAsync,
                failureSignal: host.ProcessExited);
        }
        catch
        {
            await host.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
