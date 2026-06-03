using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services.Tunneling.OpenVpn;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Provides <see cref="TunnelKind.Stormshield"/> tunnels for the Stormshield Network SSL VPN
/// ("SN SSL VPN" / "rpv"). Stormshield's SSL VPN data plane is stock OpenVPN over TLS (it
/// interoperates with unmodified OpenVPN Connect), so — like the WatchGuard provider — this does
/// the Stormshield-specific work in managed code and then delegates the tunnel itself to the shared
/// OpenVPN sidecar (<c>wormhole-ovpnproxy.exe</c>); no new binary is bundled.
///
/// <para>Two modes mirror the official client:</para>
/// <list type="bullet">
///   <item><see cref="StormshieldConnectionMode.Automatic"/> ("Stormshield mode"): authenticate to
///   the firewall captive portal over HTTPS (username/password [+ single-use OTP]), then download
///   the per-user OpenVPN profile (inline CA / client cert / key) and feed it to the sidecar. The
///   OpenVPN <c>auth-user-pass</c> password is the user's real password — NOT the OTP (the OTP is a
///   one-shot factor spent on the HTTPS step; this is a real divergence from WatchGuard, whose OTP
///   becomes the OpenVPN password).</item>
///   <item><see cref="StormshieldConnectionMode.Import"/> ("OpenVPN mode"): use a static <c>.ovpn</c>
///   the user downloaded from the portal. No HTTPS pre-auth; OpenVPN does mutual TLS directly.</item>
/// </list>
///
/// <para>Both modes run the fetched/pasted profile through <see cref="StormshieldProfileNormalizer"/>
/// to fix the modern-OpenVPN cipher-negotiation gotcha and strip VORACLE-risk compression.</para>
///
/// <para>Out of scope (deliberately surfaced as actionable errors rather than faked): the v5 "Connect
/// with single sign-on" browser/OIDC flow cannot be reduced to a silent POST; and a firewall with
/// strict ZTNA "host check" enforcement rejects any third-party client with a proprietary,
/// undocumented attestation.</para>
/// </summary>
public sealed class StormshieldTunnelProvider : ITunnelProvider
{
    /// <summary>
    /// Cap on OTP prompt rounds. A healthy flow needs one code; a couple of retries cover a
    /// mistyped/expired code. Beyond this the gateway is almost certainly misbehaving and we stop
    /// rather than trap the user in an endless prompt loop. (Same rationale as WatchGuard.)
    /// </summary>
    private const int MaxOtpRounds = 3;

    private readonly IOtpPromptService _otpPrompt;
    private readonly ILogger<StormshieldTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public StormshieldTunnelProvider(
        IOtpPromptService otpPrompt,
        ILogger<StormshieldTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _otpPrompt = otpPrompt;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.Stormshield;

    public async Task<ITunnelInstance> EstablishAsync(TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken)
    {
        var settings = JsonSerializer.Deserialize<StormshieldSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Stormshield payload.");

        // The v5 SSO checkbox launches a system browser for an OIDC/SAML exchange — it cannot be
        // performed as a background request, so reject it up front with an actionable message rather
        // than silently ignoring the flag and attempting a password auth that has no password.
        if (settings.UseSingleSignOn)
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' uses single sign-on, which is not yet supported. "
                + "Use username/password (optionally with an OTP), or switch to Import (OpenVPN) mode.");
        }

        var profile = settings.Mode switch
        {
            StormshieldConnectionMode.Import => BuildImportProfile(config, settings),
            StormshieldConnectionMode.Automatic => await FetchAutomaticProfileAsync(config, settings, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Tunnel config '{config.Name}' has an unsupported Stormshield mode '{settings.Mode}'."),
        };

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = profile,
            // The OpenVPN auth-user-pass credentials are the user's real username/password. Empty in
            // pure cert-only Import profiles, which is fine — the sidecar only uses them if the
            // profile declares auth-user-pass.
            Username = string.IsNullOrEmpty(settings.Username) ? null : settings.Username,
            Password = string.IsNullOrEmpty(settings.Password) ? null : settings.Password,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        _logger.LogDebug("Launching OpenVPN sidecar (Stormshield provider) at {Path}.", sidecarPath);

        var host = await OpenVpnProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
            .ConfigureAwait(false);

        // Wrap-after-start: once StartAsync returns the sidecar is alive, so a construction-time
        // failure must tear it down. Same pattern as the other providers.
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

    private static string BuildImportProfile(TunnelConfig config, StormshieldSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.ProfileOvpn))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' is in Import mode but has no OpenVPN profile. "
                + "Paste the .ovpn downloaded from the firewall's /auth \"Personal data\" page, or switch to Automatic mode.");
        }
        return StormshieldProfileNormalizer.Normalize(settings.ProfileOvpn);
    }

    private async Task<string> FetchAutomaticProfileAsync(
        TunnelConfig config, StormshieldSettings settings, CancellationToken cancellationToken)
    {
        // Pre-flight mirrors TunnelConfigsViewModel.ValidateStormshield so a kind/blob mismatch or
        // missing field fails fast with an actionable message instead of a confusing HTTP error.
        if (string.IsNullOrWhiteSpace(settings.Server))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has an unreadable Stormshield payload (empty Server). "
                + "Open the tunnel editor to re-enter settings.");
        }
        if (string.IsNullOrWhiteSpace(settings.Username) || string.IsNullOrWhiteSpace(settings.Password))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' is in Automatic mode but is missing a username or password.");
        }

        var app = string.IsNullOrWhiteSpace(settings.AppToken) ? StormshieldSettings.DefaultAppToken : settings.AppToken;

        using var portal = new StormshieldPortalClient(
            settings.Server, settings.Port, settings.TrustServerCertificate, settings.CaPem);

        _logger.LogDebug(
            "Stormshield pre-auth to {Server}:{Port} for '{Name}' (OTP={UseOtp}).",
            settings.Server, settings.Port, config.Name, settings.UseOtp);

        await RunAuthLoopAsync(portal, _otpPrompt, _logger, config.Name, settings, cancellationToken).ConfigureAwait(false);

        _logger.LogDebug("Stormshield auth succeeded for '{Name}'; downloading OpenVPN profile.", config.Name);

        string rawProfile;
        try
        {
            rawProfile = await portal.DownloadProfileAsync(app, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Stormshield profile download could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                $"Stormshield profile download timed out talking to '{settings.Server}:{settings.Port}'.", ex);
        }

        return StormshieldProfileNormalizer.Normalize(rawProfile);
    }

    /// <summary>
    /// Drives the Stormshield captive-portal authentication to success, prompting for an OTP when the
    /// user opted in or the firewall demands one (<c>NEED_TOTP_AUTH</c>). On return the
    /// <paramref name="portal"/> holds an authenticated session ready for the profile download.
    /// Wraps raw HttpRequestException / timeout into actionable InvalidOperationException so the
    /// session UI shows a Stormshield-specific error.
    ///
    /// Static helper taking everything as parameters so it's directly unit-testable with a fake
    /// <see cref="IStormshieldPortal"/> + <see cref="IOtpPromptService"/>.
    /// </summary>
    internal static async Task RunAuthLoopAsync(
        IStormshieldPortal portal,
        IOtpPromptService otpPrompt,
        ILogger logger,
        string configName,
        StormshieldSettings settings,
        CancellationToken cancellationToken)
    {
        var app = string.IsNullOrWhiteSpace(settings.AppToken) ? StormshieldSettings.DefaultAppToken : settings.AppToken;

        var otpPrompts = 0;
        string? otp = null;
        // If the user checked "Use an OTP", collect the code before the first POST — the official
        // client surfaces the OTP field at connect time and sends it with the initial credentials.
        if (settings.UseOtp)
        {
            otp = await PromptOtpAsync(otpPrompt, configName, cancellationToken).ConfigureAwait(false);
            otpPrompts++;
        }

        var outcome = await AuthenticateWrappedAsync(
            portal, settings.Username, settings.Password, otp, app, settings, cancellationToken).ConfigureAwait(false);

        while (true)
        {
            switch (outcome)
            {
                case StormshieldAuthOutcome.Ok:
                    logger.LogDebug("Stormshield portal accepted credentials for '{Name}'.", configName);
                    return;

                case StormshieldAuthOutcome.NeedOtp:
                    if (otpPrompts >= MaxOtpRounds)
                    {
                        throw new InvalidOperationException(
                            $"Stormshield 2FA exceeded {MaxOtpRounds} attempts — the code may be wrong or the gateway misconfigured.");
                    }
                    logger.LogInformation("Stormshield gateway requested an OTP for '{Name}' (attempt {Round}).", configName, otpPrompts + 1);
                    otp = await PromptOtpAsync(otpPrompt, configName, cancellationToken).ConfigureAwait(false);
                    otpPrompts++;
                    outcome = await AuthenticateWrappedAsync(
                        portal, settings.Username, settings.Password, otp, app, settings, cancellationToken).ConfigureAwait(false);
                    continue;

                case StormshieldAuthOutcome.Bruteforce bruteforce:
                    // The firewall throttled the account after repeated failures. Surface the wait so
                    // the user doesn't keep hammering it.
                    var wait = bruteforce.DelaySeconds > 0 ? $" Try again in {bruteforce.DelaySeconds}s." : string.Empty;
                    throw new InvalidOperationException(
                        $"Stormshield temporarily blocked authentication for '{configName}' after too many failed attempts.{wait}");

                case StormshieldAuthOutcome.Failure failure:
                    throw new InvalidOperationException($"Stormshield authentication failed: {failure.Reason}");

                default:
                    throw new InvalidOperationException(
                        $"Stormshield auth produced an unexpected outcome type: {outcome?.GetType().Name ?? "null"}.");
            }
        }
    }

    private static async Task<StormshieldAuthOutcome> AuthenticateWrappedAsync(
        IStormshieldPortal portal, string username, string password, string? otp, string app,
        StormshieldSettings settings, CancellationToken cancellationToken)
    {
        try
        {
            return await portal.AuthenticateAsync(username, password, otp, app, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Stormshield pre-auth could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                $"Stormshield pre-auth timed out talking to '{settings.Server}:{settings.Port}'.", ex);
        }
    }

    private static async Task<string> PromptOtpAsync(
        IOtpPromptService otpPrompt, string configName, CancellationToken cancellationToken)
    {
        var otp = await otpPrompt.PromptAsync(
            $"Stormshield OTP — {configName}",
            "Enter the one-time code for your VPN connection.",
            cancellationToken).ConfigureAwait(false);
        if (otp is null)
        {
            // Convention from IOtpPromptService: null is a deliberate user dismiss, not a token
            // cancel — surface as a regular InvalidOperation so upstream retry logic doesn't treat
            // it as a transient cancellation.
            throw new InvalidOperationException("Stormshield OTP prompt was cancelled by the user.");
        }
        otp = otp.Trim();
        if (otp.Length == 0)
            throw new InvalidOperationException("Stormshield OTP prompt returned an empty code.");
        return otp;
    }
}
