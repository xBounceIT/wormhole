using System;
using System.Collections.Generic;
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
///   the per-user OpenVPN profile (inline CA / client cert / key) and feed it to the sidecar. With
///   OTP enabled, the official client authenticates twice when the profile is new or changed: once
///   to retrieve the profile, then again to set up the OpenVPN tunnel with a fresh OTP. A cached,
///   current profile skips the first authentication and routes the OTP to OpenVPN.</item>
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
    private static readonly char[] s_remoteDirectiveSeparators = new[] { ' ', '\t' };

    private readonly IOtpPromptService _otpPrompt;
    private readonly IStormshieldConfigCache _configCache;
    private readonly ILogger<StormshieldTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;
    // Singleton-lived (the provider is registered AddSingleton), so its memory of the last code per tunnel
    // survives the abort-and-reconnect a cache-miss download forces — letting it catch the user re-entering
    // the just-spent code before their TOTP window rolls. See StormshieldOtpReuseGuard.
    private readonly StormshieldOtpReuseGuard _otpReuseGuard = new();

    public StormshieldTunnelProvider(
        IOtpPromptService otpPrompt,
        IStormshieldConfigCache configCache,
        ILogger<StormshieldTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _otpPrompt = otpPrompt;
        _configCache = configCache;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.Stormshield;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
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

        // Each mode yields BOTH the profile and the password the OpenVPN data plane should authenticate
        // with. For Automatic + OTP that password may be `password + otp`: when a current cached profile
        // lets us skip the download, the single-use code is routed to the data plane instead of being
        // spent on the HTTPS download (see ResolveAutomaticCoreAsync / the class remarks).
        var (profile, dataPlanePassword, optimisticCacheHit) = settings.Mode switch
        {
            StormshieldConnectionMode.Import => (BuildImportProfile(config, settings), settings.Password, false),
            StormshieldConnectionMode.Automatic => await ResolveAutomaticAsync(config, settings, cancellationToken, progress).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Tunnel config '{config.Name}' has an unsupported Stormshield mode '{settings.Mode}'."),
        };

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = profile,
            // The OpenVPN auth-user-pass credentials are the user's real username/password (with the OTP
            // appended on an Automatic cache-hit). Empty in pure cert-only Import profiles, which is fine —
            // the sidecar only uses them if the profile declares auth-user-pass.
            Username = string.IsNullOrEmpty(settings.Username) ? null : settings.Username,
            Password = string.IsNullOrEmpty(dataPlanePassword) ? null : dataPlanePassword,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        var remoteSummary = SummarizeOpenVpnRemotes(profile);
        if (!string.IsNullOrEmpty(remoteSummary))
        {
            _logger.LogInformation(
                "Stormshield '{Name}': OpenVPN profile remotes from the fetched/cached profile: {Remotes}.",
                config.Name, remoteSummary);
        }
        _logger.LogDebug("Launching OpenVPN sidecar (Stormshield provider) at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        OpenVpnProcessHost host;
        try
        {
            host = await OpenVpnProcessHost.StartAsync(
                sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (
            ex is not OperationCanceledException
            && settings.Mode == StormshieldConnectionMode.Automatic
            && settings.UseOtp)
        {
            // With OTP enabled, reaching the sidecar means we took the cache-hit path and routed the
            // one-time code to the OpenVPN data-plane password (a cache MISS aborts earlier, before the
            // sidecar starts). The code may have reached the firewall or simply expired while OpenVPN
            // worked through transport fallbacks. Either way a blind Retry would reuse a stale code, so
            // tell the user to enter a fresh one.

            // Forget the data-plane code in the reuse guard: it was handed to the sidecar but the tunnel
            // didn't come up, so it may never have been consumed by the firewall (a transport-only failure,
            // or a stale-cached-profile rejection). Let the firewall be the authority on the retry rather
            // than locally blocking a code that might still be valid — especially the optimistic-drop path
            // below, whose whole point is to recover via a fresh re-download.
            _otpReuseGuard.Forget(config.Id);

            // If the profile was reused WITHOUT confirming it against the firewall's current hash (the
            // change-check was unavailable), the failure may mean the cached profile is stale. Drop it so
            // the next connect re-downloads a fresh one rather than looping forever on the same stale
            // profile. A hash-CONFIRMED hit that fails is almost certainly a mistyped/expired code, so we
            // keep that cache for a cheap re-prompt. Best-effort; DeleteAsync never throws.
            if (optimisticCacheHit)
                await _configCache.DeleteAsync(config.Id, CancellationToken.None).ConfigureAwait(false);

            throw new InvalidOperationException(
                "The Stormshield VPN prepared its configuration, but bringing up the OpenVPN tunnel failed: "
                + $"{ex.Message} Your one-time code may have been used or expired during this connection attempt — "
                + "if you retry, enter a NEW one-time code.", ex);
        }

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

    internal static string SummarizeOpenVpnRemotes(string profile)
    {
        var remotes = new List<string>();
        string? openBlock = null;

        foreach (var rawLine in profile.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var trimmed = rawLine.Trim();
            if (openBlock is not null)
            {
                if (IsCloseTag(trimmed, openBlock)) openBlock = null;
                continue;
            }
            if (TryReadOpenTag(trimmed, out var blockName))
            {
                if (IsOpaqueInlineBlock(blockName))
                    openBlock = blockName;
                continue;
            }
            if (trimmed.Length == 0 || trimmed[0] == '#' || trimmed[0] == ';')
                continue;

            var parts = trimmed.Split(s_remoteDirectiveSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].Equals("remote", StringComparison.OrdinalIgnoreCase))
                continue;

            var summary = parts[1];
            if (parts.Length >= 3) summary += ":" + parts[2];
            if (parts.Length >= 4) summary += "/" + parts[3];
            remotes.Add(summary);
        }

        return string.Join(", ", remotes);
    }

    private static bool TryReadOpenTag(string trimmed, out string name)
    {
        name = string.Empty;
        if (trimmed.Length < 3 || trimmed[0] != '<' || trimmed[^1] != '>' || trimmed[1] == '/')
            return false;
        name = trimmed[1..^1];
        foreach (var ch in name)
        {
            if (char.IsWhiteSpace(ch) || ch == '<' || ch == '>') return false;
        }
        return name.Length > 0;
    }

    private static bool IsOpaqueInlineBlock(string blockName) =>
        blockName.Equals("ca", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("cert", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("key", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("tls-auth", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("tls-crypt", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("tls-crypt-v2", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("extra-certs", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("pkcs12", StringComparison.OrdinalIgnoreCase)
        || blockName.Equals("secret", StringComparison.OrdinalIgnoreCase);

    private static bool IsCloseTag(string trimmed, string blockName) =>
        trimmed.Length == blockName.Length + 3
        && trimmed[0] == '<' && trimmed[1] == '/' && trimmed[^1] == '>'
        && trimmed.AsSpan(2, blockName.Length).Equals(blockName, StringComparison.OrdinalIgnoreCase);

    private async Task<(string Profile, string DataPlanePassword, bool OptimisticCacheHit)> ResolveAutomaticAsync(
        TunnelConfig config, StormshieldSettings settings, CancellationToken cancellationToken, IProgress<TunnelProgress>? progress = null)
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

        using var portal = new StormshieldPortalClient(
            settings.Server, settings.Port, settings.TrustServerCertificate, settings.CaPem);

        _logger.LogDebug(
            "Stormshield v5 config resolve from {Server}:{Port} for '{Name}' (OTP={UseOtp}).",
            settings.Server, settings.Port, config.Name, settings.UseOtp);

        // Guard the prompt against the user re-entering a code that was just spent (download) or just rejected
        // (data plane) before their authenticator rolls — the firewall would only reject it again. Transparent
        // to the core resolution logic, so the OTP-routing tests keep calling ResolveAutomaticCoreAsync directly.
        var guardedOtpPrompt = _otpReuseGuard.Wrap(_otpPrompt, config.Id);

        return await ResolveAutomaticCoreAsync(
            portal, _configCache, guardedOtpPrompt, _logger, config.Id, config.Name, settings, cancellationToken, progress)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Core Automatic-mode resolution: returns the OpenVPN profile plus the password the data plane should
    /// authenticate with, applying the OTP-routing / config-cache gate. Static and dependency-injected so it
    /// is unit-testable with a fake <see cref="IStormshieldPortal"/> + <see cref="IStormshieldConfigCache"/>
    /// (no live firewall or sidecar).
    ///
    /// <para>The single-use OTP is spent in exactly one place, mirroring the native v5 client
    /// (<c>SnsService.SetupSns</c> + <c>VpnService</c>):</para>
    /// <list type="bullet">
    ///   <item><b>No OTP</b>: download a fresh profile; the data plane uses the real password.</item>
    ///   <item><b>OTP, cache HIT</b> (firewall reports its config unchanged, or the change-check is
    ///   unavailable but a cached profile exists): reuse the cached profile and route the OTP to the data
    ///   plane (<c>password + otp</c>). This is the steady-state path that brings the tunnel up.</item>
    ///   <item><b>OTP, cache MISS</b> (no or stale cache): download a fresh profile — which spends the OTP
    ///   on the HTTPS step — persist it, then abort with <see cref="StormshieldConfigRefreshedException"/>.
    ///   The code is now used; the next connect finds the cached profile and routes a fresh code to the data
    ///   plane. (Native: RetrieveConfig → OK_OTP_USED → SetupSns NOK_TOTP_USED → abort/reconnect.)</item>
    /// </list>
    /// </summary>
    internal static async Task<(string Profile, string DataPlanePassword, bool OptimisticCacheHit)> ResolveAutomaticCoreAsync(
        IStormshieldPortal portal,
        IStormshieldConfigCache cache,
        IOtpPromptService otpPrompt,
        ILogger logger,
        Guid tunnelId,
        string configName,
        StormshieldSettings settings,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));

        if (!settings.UseOtp)
        {
            // No single-use factor to conserve — download fresh every time, real password on the data
            // plane. (Unchanged behavior for non-OTP firewalls; nothing is cached.)
            progress?.Report(new TunnelProgress(TunnelPhase.DownloadingConfiguration));
            var profileNoOtp = await DownloadProfileV5WrappedAsync(portal, settings, otp: null, cancellationToken).ConfigureAwait(false);
            return (StormshieldProfileNormalizer.Normalize(profileNoOtp), settings.Password, false);
        }

        // Ask the firewall whether its SSL VPN config changed (unauthenticated; null when the endpoint is
        // unsupported or unreachable), and look up any current cached profile for this tunnel.
        var serverHash = await portal.GetConfigHashAsync(cancellationToken).ConfigureAwait(false);
        var cached = await cache.TryReadAsync(tunnelId, settings, cancellationToken).ConfigureAwait(false);

        var hashMatches = cached is not null && serverHash is not null
            && string.Equals(serverHash, cached.ConfigHash, StringComparison.OrdinalIgnoreCase);
        // Change-check unavailable but a cached profile exists: trust the cache rather than re-downloading
        // (and re-spending the OTP). Deliberate improvement over the native client, which re-downloads when
        // the hash check fails — that would loop forever on firmware that lacks the endpoint.
        var optimistic = cached is not null && serverHash is null;

        if (hashMatches || optimistic)
        {
            // Prompt as late as possible so the TOTP window is not spent while the config hash/cache
            // checks run. That matters when the profile's first remote times out before a TCP fallback.
            var dataPlaneOtp = await PromptOtpAsync(otpPrompt, configName, cancellationToken).ConfigureAwait(false);
            logger.LogInformation(
                "Stormshield '{Name}': reusing the cached configuration ({Reason}); routing the one-time code to the OpenVPN data plane.",
                configName, hashMatches ? "firewall reports config unchanged" : "change-check unavailable, cached profile present");
            // optimistic == true only when we could NOT confirm the cache against the firewall's current
            // hash; the caller drops the cache if this (unconfirmed) profile then fails the data-plane auth.
            return (cached!.ProfileOvpn, settings.Password + dataPlaneOtp, optimistic);
        }

        // Cache MISS: download (spends the OTP on the HTTPS step), persist for next time, then stop.
        var downloadOtp = await PromptOtpAsync(otpPrompt, configName, cancellationToken).ConfigureAwait(false);
        logger.LogInformation(
            "Stormshield '{Name}': {Reason}; downloading a fresh configuration (this uses the one-time code).",
            configName, cached is null ? "no cached configuration" : "firewall config changed");
        progress?.Report(new TunnelProgress(TunnelPhase.DownloadingConfiguration));
        var rawProfile = await DownloadProfileV5WrappedAsync(portal, settings, downloadOtp, cancellationToken).ConfigureAwait(false);
        var normalized = StormshieldProfileNormalizer.Normalize(rawProfile);

        // Best-effort persist. The OTP is ALREADY spent on the download above, so a failed cache write
        // must NOT propagate: if it did, the user would get a generic error instead of the "reconnect with
        // a new code" guidance, and — worse — the next connect would be another miss that spends another
        // code, looping forever. Swallow the write failure (logged loudly so the loop is diagnosable) and
        // still surface the reconnect message; the next connect simply re-downloads (one wasted code) rather
        // than looping. (OperationCanceledException is a genuine user/token cancel — let it through.)
        try
        {
            await cache.WriteAsync(tunnelId, settings, serverHash ?? string.Empty, normalized, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Stormshield '{Name}': downloaded a fresh configuration but failed to cache it. The reconnect will "
                + "re-download (and require another one-time code) until the cache can be written.", configName);
        }

        throw new StormshieldConfigRefreshedException(
            $"Downloaded an updated VPN profile for '{configName}'. This used your current one-time code, so "
            + "enter a NEW code from your authenticator and reconnect to bring up the tunnel (re-using the same "
            + "code won't work).");
    }

    private static async Task<string> DownloadProfileV5WrappedAsync(
        IStormshieldPortal portal, StormshieldSettings settings, string? otp, CancellationToken cancellationToken)
    {
        try
        {
            return await portal.DownloadProfileV5Async(settings.Username, settings.Password, otp, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Stormshield configuration download could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                $"Stormshield configuration download timed out talking to '{settings.Server}:{settings.Port}'.", ex);
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

/// <summary>
/// Thrown by the Automatic + OTP flow when a fresh configuration had to be downloaded (because none was
/// cached, or the firewall's config changed) — which consumes the single-use one-time code on the HTTPS
/// download. The freshly-downloaded profile is now cached, so the connection is deliberately NOT brought
/// up on this attempt: the user must reconnect with a NEW code, which the next connect routes to the
/// OpenVPN data plane.
///
/// <para>Its <see cref="Exception.Message"/> is user-facing and states the "downloaded — reconnect with a new
/// code" guidance in success-toned language. It derives from <see cref="TunnelRecoverableNoticeException"/> so
/// the session view-models and the tunnel-test dialog — which catch that base type — render a green
/// success/info notice (titled "Profile downloaded") with a Reconnect affordance instead of a red "connection
/// failed" error. The provider's own tests also assert on the type.</para>
/// </summary>
internal sealed class StormshieldConfigRefreshedException : TunnelRecoverableNoticeException
{
    public StormshieldConfigRefreshedException(string message) : base("Profile downloaded", message) { }
}
