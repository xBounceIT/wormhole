using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services.Tunneling.OpenVpn;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Provides <see cref="TunnelKind.AzureVpn"/> tunnels for Azure VPN Gateway / Virtual WAN
/// point-to-site with Microsoft Entra ID authentication. Azure's Entra-authenticated P2S data
/// plane is stock OpenVPN over TLS on port 443 — so, like the WatchGuard and Stormshield
/// providers, this does the Azure-specific work in managed code and then delegates the tunnel
/// itself to the shared OpenVPN sidecar (<c>wormhole-ovpnproxy.exe</c>); no new binary is bundled.
///
/// <para>What is Azure-specific is the credential: the gateway authenticates the OpenVPN
/// <c>auth-user-pass</c> exchange with a Microsoft Entra ID access token as the password (fixed
/// username <c>AzureAD</c> — the convention the official clients use). The token is acquired:</para>
/// <list type="number">
///   <item><b>Silently</b> when a DPAPI-cached refresh token redeems successfully — the
///   steady-state reconnect path, no UI;</item>
///   <item>otherwise <b>interactively</b> via the separate Microsoft sign-in popup
///   (<see cref="IAzureVpnAuthService"/>), exactly like the native Azure VPN Client. The granted
///   refresh token is then cached for the next connect.</item>
/// </list>
///
/// <para>Mid-session token expiry is handled by the gateway itself: Azure pushes an OpenVPN
/// <c>auth-token</c> after the initial authentication, which OpenVPN3 in the sidecar replays on
/// TLS renegotiation — the original access token is never re-sent.</para>
/// </summary>
public sealed class AzureVpnTunnelProvider : ITunnelProvider
{
    /// <summary>
    /// Sentinel username Azure P2S gateways expect for Entra-authenticated connections; the
    /// password carries the access token.
    /// </summary>
    internal const string AadAuthUsername = "AzureAD";

    private readonly IAzureVpnAuthService _authService;
    private readonly IAzureVpnOAuthClient _oauthClient;
    private readonly IAzureVpnTokenCache _tokenCache;
    private readonly ILogger<AzureVpnTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public AzureVpnTunnelProvider(
        IAzureVpnAuthService authService,
        IAzureVpnOAuthClient oauthClient,
        IAzureVpnTokenCache tokenCache,
        ILogger<AzureVpnTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _authService = authService;
        _oauthClient = oauthClient;
        _tokenCache = tokenCache;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.AzureVpn;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<AzureVpnSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Azure VPN payload.");

        // Pre-flight mirrors TunnelConfigsViewModel.ValidateAzureVpn so a kind/blob mismatch or
        // missing field fails fast with an actionable message instead of a confusing OAuth error.
        if (settings.Servers.Count == 0 || string.IsNullOrWhiteSpace(settings.Servers[0]))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has no gateway server. Open the tunnel editor and import "
                + "the azurevpnconfig.xml downloaded from the Azure portal.");
        }
        if (string.IsNullOrWhiteSpace(settings.TenantId) || string.IsNullOrWhiteSpace(settings.Audience))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' is missing its Microsoft Entra tenant or audience. Open the "
                + "tunnel editor and re-import the azurevpnconfig.xml.");
        }

        // Build (and validate) the profile BEFORE acquiring a token so a malformed config can't
        // burn an interactive sign-in.
        var profile = AzureVpnProfileBuilder.Build(settings);

        progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));
        var accessToken = await ResolveAccessTokenCoreAsync(
            _oauthClient, _tokenCache, _authService, _logger,
            config.Id, config.Name, settings, cancellationToken).ConfigureAwait(false);

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = profile,
            Username = AadAuthUsername,
            Password = accessToken,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        _logger.LogInformation(
            "Azure VPN '{Name}': starting OpenVPN to {Server} ({Transport}) as tenant {Tenant}.",
            config.Name, settings.Servers[0], settings.Protocol, settings.TenantId);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        OpenVpnProcessHost host;
        try
        {
            host = await OpenVpnProcessHost.StartAsync(
                sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && IsAuthFailure(ex))
        {
            // The gateway rejected a token Entra just minted: almost always an authorization
            // problem (user not assigned to the VPN app, audience mismatch), not a stale-token
            // problem — but drop the cached refresh token anyway so a retry re-runs the full
            // sign-in and picks up any conditional-access / assignment change.
            await _tokenCache.DeleteAsync(config.Id, CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException(
                $"The Azure VPN gateway rejected the Microsoft Entra sign-in for '{config.Name}': {ex.Message} "
                + "Check that your account is assigned to the Azure VPN application and retry — the next attempt "
                + "will sign in from scratch.", ex);
        }

        // Wrap-after-start: once StartAsync returns the sidecar is alive, so a construction-time
        // failure must tear it down. Same pattern as the other providers.
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

    private static bool IsAuthFailure(Exception ex) =>
        ex.Message.Contains("AUTH_FAILED", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Core token resolution: silent refresh first, interactive popup as the fallback. Static and
    /// dependency-injected so it is unit-testable with fake OAuth/cache/auth services (no live
    /// Entra tenant or UI).
    /// <list type="bullet">
    ///   <item><b>Cached refresh token redeems</b>: return the fresh access token and rotate the
    ///   stored refresh token (Entra issues a new one per redemption). No UI.</item>
    ///   <item><b>Refresh rejected</b> (expired/revoked, conditional-access change) or
    ///   <b>no cache</b>: open the Microsoft sign-in popup; cache the granted refresh token.</item>
    ///   <item><b>Refresh transport failure</b> (offline, proxy): still fall through to the popup
    ///   — it surfaces a much clearer error than a bare HTTP exception, and a captive-portal-style
    ///   network may let the browser through where the silent POST failed.</item>
    /// </list>
    /// Cache writes are best-effort: a failed write must not kill a connect that already holds a
    /// valid access token — the cost is one extra popup next time.
    /// </summary>
    internal static async Task<string> ResolveAccessTokenCoreAsync(
        IAzureVpnOAuthClient oauthClient,
        IAzureVpnTokenCache tokenCache,
        IAzureVpnAuthService authService,
        ILogger logger,
        Guid tunnelId,
        string configName,
        AzureVpnSettings settings,
        CancellationToken cancellationToken)
    {
        var cachedRefreshToken = await tokenCache.TryReadAsync(tunnelId, settings, cancellationToken).ConfigureAwait(false);
        if (cachedRefreshToken is not null)
        {
            AzureVpnTokenResult? refreshed = null;
            try
            {
                refreshed = await oauthClient.RefreshAsync(settings, cachedRefreshToken, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Azure VPN '{Name}': silent token refresh failed to reach Microsoft Entra; falling back to interactive sign-in.",
                    configName);
            }

            if (refreshed is not null)
            {
                logger.LogInformation("Azure VPN '{Name}': access token acquired silently via the cached refresh token.", configName);
                await TryCacheRefreshTokenAsync(
                    tokenCache, logger, tunnelId, configName, settings,
                    refreshed.RefreshToken ?? cachedRefreshToken).ConfigureAwait(false);
                return refreshed.AccessToken;
            }
        }

        logger.LogInformation("Azure VPN '{Name}': opening the Microsoft sign-in window.", configName);
        var interactive = await authService.AuthenticateInteractiveAsync(settings, configName, cancellationToken).ConfigureAwait(false);

        if (interactive.RefreshToken is not null)
        {
            await TryCacheRefreshTokenAsync(
                tokenCache, logger, tunnelId, configName, settings, interactive.RefreshToken).ConfigureAwait(false);
        }
        return interactive.AccessToken;
    }

    private static async Task TryCacheRefreshTokenAsync(
        IAzureVpnTokenCache tokenCache, ILogger logger, Guid tunnelId, string configName,
        AzureVpnSettings settings, string refreshToken)
    {
        try
        {
            // CancellationToken.None: the token is already in hand; aborting the write on a
            // user cancel would only cost the next connect an avoidable popup.
            await tokenCache.WriteAsync(tunnelId, settings, refreshToken, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Azure VPN '{Name}': could not persist the refresh token; the next connect may need an interactive sign-in.",
                configName);
        }
    }
}
