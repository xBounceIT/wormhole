using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.CiscoSecureClient;

/// <summary>
/// Provides <see cref="TunnelKind.CiscoSecureClient"/> tunnels by launching the userspace
/// <c>wormhole-ciscoproxy.exe</c> sidecar, which speaks the Cisco AnyConnect SSL VPN protocol
/// (aggregate-auth XML login + CSTP tunnel) and exposes a loopback SOCKS5 endpoint. Mirrors
/// <see cref="Fortinet.FortinetTunnelProvider"/>.
/// </summary>
public sealed class CiscoSecureClientTunnelProvider : ITunnelProvider
{
    private readonly ILogger<CiscoSecureClientTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public CiscoSecureClientTunnelProvider(ILogger<CiscoSecureClientTunnelProvider> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.CiscoSecureClient;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<CiscoSecureClientSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Cisco Secure Client payload.");

        // Symmetric pre-flight with TunnelConfigsViewModel.ValidateCiscoSecureClient: catch the
        // kind/blob-mismatch case here too so the user gets a clear actionable error rather than
        // waiting for the sidecar to time out with 'host is required'. The deserializer is
        // permissive (forward-compat with future fields), so an empty Host means the blob's actual
        // shape didn't overlap with CiscoSecureClientSettings — likely corruption or a mismatch.
        if (string.IsNullOrWhiteSpace(settings.Host))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has an unreadable Cisco Secure Client payload (empty Host). " +
                "Open the tunnel editor to re-enter settings.");
        }

        var sidecar = new CiscoSecureClientSidecarConfig
        {
            Host = settings.Host,
            Port = settings.Port,
            Username = settings.Username,
            Password = settings.Password,
            Group = settings.Group,
            SecondaryPassword = settings.SecondaryPassword,
            TotpSecret = settings.TotpSecret,
            TrustServerCertificate = settings.TrustServerCertificate,
            ServerCertSha256Pin = settings.ServerCertSha256Pin,
        };

        var sidecarPath = AppPaths.GetCiscoProxyExecutablePath();
        _logger.LogDebug("Launching Cisco Secure Client sidecar at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        var host = await CiscoSecureClientProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<CiscoSecureClientProcessHost>(), cancellationToken)
            .ConfigureAwait(false);

        // Keep lifecycle parity with the other sidecar-backed providers: once StartAsync returns
        // the sidecar is alive, so a construction-time failure must tear it down immediately.
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
