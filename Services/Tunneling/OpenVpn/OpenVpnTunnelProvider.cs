using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.OpenVpn;

/// <summary>
/// Provides <see cref="TunnelKind.OpenVpn"/> tunnels by launching the userspace OpenVPN
/// sidecar (<c>wormhole-ovpnproxy.exe</c>), passing it the user's .ovpn profile + optional
/// credentials, and wrapping the sidecar's local SOCKS5 endpoint as an <see
/// cref="ITunnelInstance"/>. Mirrors <c>WireGuardTunnelProvider</c>; differences are scoped
/// to the per-kind config DTO and sidecar binary path.
/// </summary>
public sealed class OpenVpnTunnelProvider : ITunnelProvider
{
    private readonly ILogger<OpenVpnTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public OpenVpnTunnelProvider(ILogger<OpenVpnTunnelProvider> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.OpenVpn;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<OpenVpnSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid OpenVPN payload.");

        if (string.IsNullOrWhiteSpace(settings.ProfileOvpn))
            throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty OpenVPN profile.");

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = settings.ProfileOvpn,
            Username = settings.Username,
            Password = settings.Password,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        _logger.LogDebug("Launching OpenVPN sidecar at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        var host = await OpenVpnProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
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
                onDispose: async () => await host.DisposeAsync().ConfigureAwait(false));
        }
        catch
        {
            await host.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
