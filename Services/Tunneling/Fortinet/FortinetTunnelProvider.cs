using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Fortinet;

public sealed class FortinetTunnelProvider : ITunnelProvider
{
    private readonly ILogger<FortinetTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public FortinetTunnelProvider(ILogger<FortinetTunnelProvider> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.Fortinet;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<FortinetSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Fortinet payload.");

        // Symmetric pre-flight with TunnelConfigsViewModel.ValidateFortinet: catch the
        // kind/blob-mismatch case here too so the user gets a clear actionable error rather
        // than waiting 25 seconds for the sidecar to time out with 'host is required' or
        // posting empty credentials to FortiGate. The deserializer is permissive (forward-
        // compat with future fields), so an empty Host means the blob's actual shape didn't
        // overlap with FortinetSettings — likely corruption or a kind/blob mismatch.
        if (string.IsNullOrWhiteSpace(settings.Host))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has an unreadable Fortinet payload (empty Host). " +
                "Open the tunnel editor to re-enter settings.");
        }

        var sidecar = new FortinetSidecarConfig
        {
            Host = settings.Host,
            Port = settings.Port,
            Username = settings.Username,
            Password = settings.Password,
            Realm = settings.Realm,
            TotpSecret = settings.TotpSecret,
            TrustServerCertificate = settings.TrustServerCertificate,
            ServerCertSha256Pin = settings.ServerCertSha256Pin,
        };

        var sidecarPath = AppPaths.GetFortiProxyExecutablePath();
        _logger.LogDebug("Launching Fortinet sidecar at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        var host = await FortinetProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<FortinetProcessHost>(), cancellationToken)
            .ConfigureAwait(false);

        // Keep lifecycle parity with WireGuard/OpenVPN: once StartAsync returns the sidecar is
        // alive, so a construction-time failure must tear it down immediately.
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
