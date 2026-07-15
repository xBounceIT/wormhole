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
    private readonly IFortinetSamlAuthService _samlAuthService;

    public FortinetTunnelProvider(
        ILogger<FortinetTunnelProvider> logger,
        ILoggerFactory loggerFactory,
        IFortinetSamlAuthService samlAuthService)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _samlAuthService = samlAuthService;
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

        FortinetSamlAuthResult? samlResult = null;
        if (settings.UseSingleSignOn)
        {
            if (settings.UseExternalBrowser && settings.SamlRedirectPort is < 1 or > 65535)
                throw new InvalidOperationException("Fortinet SAML callback port must be between 1 and 65535.");
            if (settings.UseExternalBrowser && !string.IsNullOrWhiteSpace(settings.Realm))
                throw new InvalidOperationException("External-browser Fortinet SSO does not support realms.");
            if (!settings.UseExternalBrowser && !string.IsNullOrWhiteSpace(settings.ServerCertSha256Pin))
            {
                throw new InvalidOperationException(
                    "Embedded-browser Fortinet SSO cannot enforce a server certificate pin; use the external browser or clear the pin.");
            }

            settings = settings.SanitizedForAuthenticationMode();
            progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));
            samlResult = await _samlAuthService.AuthenticateAsync(settings, config.Name, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (string.IsNullOrWhiteSpace(settings.Username) || string.IsNullOrWhiteSpace(settings.Password))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' requires a username and password when SSO is disabled.");
        }

        var sidecar = new FortinetSidecarConfig
        {
            Host = settings.Host,
            Port = settings.Port,
            Username = settings.Username,
            Password = settings.Password,
            Realm = settings.UseSingleSignOn ? null : settings.Realm,
            TotpSecret = settings.TotpSecret,
            SamlAuthId = samlResult?.AuthId,
            SvpnCookie = samlResult?.SvpnCookie,
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
