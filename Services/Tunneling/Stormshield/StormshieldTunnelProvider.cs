using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
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
/// to fix the modern-OpenVPN cipher-negotiation gotcha while preserving the firewall's
/// compression/framing directives by default.</para>
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
    private readonly ITlsTrustPromptService _tlsTrustPrompt;
    private readonly ICredentialService _credentials;
    private readonly IStormshieldConfigCache _configCache;
    private readonly IWindowsTemporaryHostRouteService _routeService;
    private readonly ILogger<StormshieldTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;
    // Singleton-lived (the provider is registered AddSingleton), so its memory of the last code per tunnel
    // survives the abort-and-reconnect a cache-miss download forces — letting it catch the user re-entering
    // the just-spent code before their TOTP window rolls. See StormshieldOtpReuseGuard.
    private readonly StormshieldOtpReuseGuard _otpReuseGuard = new();

    public StormshieldTunnelProvider(
        IOtpPromptService otpPrompt,
        ITlsTrustPromptService tlsTrustPrompt,
        ICredentialService credentials,
        IStormshieldConfigCache configCache,
        IWindowsTemporaryHostRouteService routeService,
        ILogger<StormshieldTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _otpPrompt = otpPrompt;
        _tlsTrustPrompt = tlsTrustPrompt;
        _credentials = credentials;
        _configCache = configCache;
        _routeService = routeService;
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

        var routeLeases = new List<WindowsHostRouteLease>();
        try
        {
            if (settings.Mode == StormshieldConnectionMode.Automatic && !string.IsNullOrWhiteSpace(settings.Server))
            {
                routeLeases.Add(await PrepareGatewayRoutesAsync(
                    config.Name,
                    new[] { settings.Server },
                    settings.BypassNativeVpnGatewayRoute,
                    "portal",
                    cancellationToken).ConfigureAwait(false));
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
            profile = ApplyCompressionFramingOverride(config.Name, settings, profile);
            profile = ApplyTransportOverride(config.Name, settings, profile);

            var remoteHosts = ExtractOpenVpnRemotes(profile)
                .Select(r => r.Host)
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            routeLeases.Add(await PrepareGatewayRoutesAsync(
                config.Name,
                remoteHosts,
                settings.BypassNativeVpnGatewayRoute,
                "OpenVPN remote",
                cancellationToken).ConfigureAwait(false));

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
                // tell the user to enter a fresh one. (The reuse guard never recorded this data-plane code — it
                // only records codes a successful download definitively spent — so the firewall stays the
                // authority on whether it's still usable; nothing to clear here.)

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
                    onDispose: () => DisposeHostAndRoutesAsync(host, routeLeases),
                    failureSignal: host.ProcessExited);
            }
            catch
            {
                await DisposeHostAndRoutesAsync(host, routeLeases).ConfigureAwait(false);
                throw;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ShouldEnrichNativeVpnConflict(routeLeases, ex))
        {
            await DisposeRouteLeasesAsync(routeLeases).ConfigureAwait(false);
            throw BuildNativeVpnConflictException(config.Name, settings, routeLeases, ex);
        }
        catch
        {
            await DisposeRouteLeasesAsync(routeLeases).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<WindowsHostRouteLease> PrepareGatewayRoutesAsync(
        string configName,
        string[] hosts,
        bool enableBypass,
        string phase,
        CancellationToken cancellationToken)
    {
        if (hosts.Length == 0)
            return new WindowsHostRouteLease(Array.Empty<WindowsHostRouteDiagnostic>(), Array.Empty<IAsyncDisposable>());

        var lease = await _routeService.PrepareGatewayBypassAsync(configName, hosts, enableBypass, cancellationToken)
            .ConfigureAwait(false);
        LogRouteDiagnostics(configName, phase, lease.Diagnostics, enableBypass);
        return lease;
    }

    private void LogRouteDiagnostics(
        string configName,
        string phase,
        IReadOnlyList<WindowsHostRouteDiagnostic> diagnostics,
        bool enableBypass)
    {
        foreach (var diagnostic in diagnostics)
        {
            if (diagnostic.BypassRouteInstalled)
            {
                _logger.LogInformation("Stormshield '{Name}' {Phase} route bypass: {Message}", configName, phase, diagnostic.Message);
            }
            else if (diagnostic.NativeVpnConflict)
            {
                _logger.LogWarning(
                    "Stormshield '{Name}' {Phase} route warning: {Message} {Hint}",
                    configName,
                    phase,
                    diagnostic.Message,
                    enableBypass
                        ? "The bypass option is enabled, but no temporary route was installed."
                        : "Enable the advanced native-VPN route bypass option and run Wormhole as Administrator if this blocks the connection.");
            }
            else
            {
                _logger.LogDebug("Stormshield '{Name}' {Phase} route diagnostic: {Message}", configName, phase, diagnostic.Message);
            }
        }
    }

    private async ValueTask DisposeHostAndRoutesAsync(OpenVpnProcessHost host, IReadOnlyList<WindowsHostRouteLease> routeLeases)
    {
        try
        {
            await host.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            await DisposeRouteLeasesAsync(routeLeases).ConfigureAwait(false);
        }
    }

    private async ValueTask DisposeRouteLeasesAsync(IReadOnlyList<WindowsHostRouteLease> routeLeases)
    {
        foreach (var routeLease in routeLeases)
        {
            try { await routeLease.DisposeAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to dispose a temporary Stormshield gateway route lease."); }
        }
    }

    internal static bool ShouldEnrichNativeVpnConflict(IReadOnlyList<WindowsHostRouteLease> routeLeases, Exception ex) =>
        routeLeases.Any(l => l.HasNativeVpnConflict) && IsRouteSensitiveFailure(ex);

    internal static bool IsRouteSensitiveFailure(Exception ex)
    {
        if (IsTlsAuthenticationFailure(ex)) return false;

        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is TimeoutException or TaskCanceledException or HttpRequestException or System.IO.IOException)
                return true;

            var message = e.Message;
            if (message.Contains("timed out", StringComparison.OrdinalIgnoreCase)
                || message.Contains("could not reach", StringComparison.OrdinalIgnoreCase)
                || message.Contains("CONNECTION_TIMEOUT", StringComparison.OrdinalIgnoreCase)
                || message.Contains("TRANSPORT_ERROR", StringComparison.OrdinalIgnoreCase)
                || message.Contains("NETWORK_RECV_ERROR", StringComparison.OrdinalIgnoreCase)
                || message.Contains("handshake/auth failure or timeout", StringComparison.OrdinalIgnoreCase)
                || message.Contains("did not produce a READY line", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    internal static InvalidOperationException BuildNativeVpnConflictException(
        string configName,
        StormshieldSettings settings,
        IReadOnlyList<WindowsHostRouteLease> routeLeases,
        Exception inner)
    {
        var conflicts = routeLeases
            .SelectMany(l => l.Diagnostics)
            .Where(d => d.NativeVpnConflict)
            .Select(d => d.Message)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var conflictSummary = conflicts.Length == 0 ? string.Empty : " " + string.Join(" ", conflicts);
        var hint = settings.BypassNativeVpnGatewayRoute
            ? "The advanced route bypass option is enabled; Wormhole installed temporary host routes where Windows allowed it. If the connection still fails, disconnect the native VPN or check for an existing host route owned by it."
            : "Enable the Stormshield advanced option 'Bypass active native VPN route for gateway' and run Wormhole as Administrator, or disconnect the native VPN before connecting this tunnel.";

        return new InvalidOperationException(
            $"Stormshield '{configName}' could not complete because Windows appears to be routing the VPN gateway through an already-active native VPN.{conflictSummary} {hint} Original error: {inner.Message}",
            inner);
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

    private string ApplyTransportOverride(string configName, StormshieldSettings settings, string profile)
    {
        if (settings.OpenVpnTransportOverride == StormshieldOpenVpnTransportOverride.Auto)
            return profile;

        var filtered = StormshieldProfileNormalizer.ApplyTransportOverride(profile, settings.OpenVpnTransportOverride);
        _logger.LogInformation(
            "Stormshield '{Name}': forcing OpenVPN transport override {Transport}.",
            configName, settings.OpenVpnTransportOverride);
        return filtered;
    }

    private string ApplyCompressionFramingOverride(string configName, StormshieldSettings settings, string profile)
    {
        if (settings.OpenVpnCompressionFramingOverride == StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub)
        {
            _logger.LogInformation(
                "Stormshield '{Name}': forcing OpenVPN legacy no-compression framing {Framing}.",
                configName, settings.OpenVpnCompressionFramingOverride);
        }

        return ApplyCompressionFramingPolicy(profile, settings.OpenVpnCompressionFramingOverride);
    }

    internal static string ApplyCompressionFramingPolicy(
        string profile,
        StormshieldOpenVpnCompressionFramingOverride framingOverride)
    {
        return framingOverride switch
        {
            StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub
                => StormshieldProfileNormalizer.ApplyLegacyCompressionStub(profile),
            _ => profile,
        };
    }

    internal static string SummarizeOpenVpnRemotes(string profile)
    {
        var remotes = ExtractOpenVpnRemotes(profile)
            .Select(remote =>
            {
                var summary = remote.Host;
                if (!string.IsNullOrWhiteSpace(remote.Port)) summary += ":" + remote.Port;
                if (!string.IsNullOrWhiteSpace(remote.Protocol)) summary += "/" + remote.Protocol;
                return summary;
            });

        return string.Join(", ", remotes);
    }

    internal static IReadOnlyList<OpenVpnRemoteEndpoint> ExtractOpenVpnRemotes(string profile)
    {
        var remotes = new List<OpenVpnRemoteEndpoint>();
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

            remotes.Add(new OpenVpnRemoteEndpoint(
                parts[1],
                parts.Length >= 3 ? parts[2] : null,
                parts.Length >= 4 ? parts[3] : null));
        }

        return remotes;
    }

    internal sealed record OpenVpnRemoteEndpoint(string Host, string? Port, string? Protocol);

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

        _logger.LogDebug(
            "Stormshield v5 config resolve from {Server}:{Port} for '{Name}' (OTP={UseOtp}).",
            settings.Server, settings.Port, config.Name, settings.UseOtp);

        // Guard the prompt against the user re-entering a code that was already SPENT before their authenticator
        // rolls — the firewall would only reject it again. The wrapped prompt only CHECKS; the code is recorded
        // as spent via onOtpSpent below, which the core invokes ONLY after a successful download actually
        // consumes it. Transparent to the core logic, so the OTP-routing tests keep calling it directly.
        var guardedOtpPrompt = _otpReuseGuard.Wrap(_otpPrompt, config.Id);

        return await ResolveAutomaticWithTlsConsentAsync(
            // The factory reads settings.TrustServerCertificate at call time: the consent flow flips
            // it to true before asking for the retry portal, so no separate "trust override" needs
            // to be threaded through.
            () => new StormshieldPortalClient(
                settings.Server, settings.Port, settings.TrustServerCertificate, settings.CaPem),
            portal => ResolveAutomaticCoreAsync(
                portal, _configCache, guardedOtpPrompt, _logger, config.Id, config.Name, settings,
                cancellationToken, progress, onOtpSpent: code => _otpReuseGuard.Record(config.Id, code)),
            _tlsTrustPrompt,
            reloadPersistedTrustAsync: async () =>
            {
                // Trust granted concurrently counts only if the persisted blob still describes the
                // server this connect (and its pending consent question) is actually about.
                var persisted = await TryReadPersistedSettingsAsync(config.Id).ConfigureAwait(false);
                return persisted is { TrustServerCertificate: true } && DescribesSameServer(persisted, settings);
            },
            persistTrustAsync: () => PersistTrustServerCertificateAsync(config.Id, settings),
            _logger, config.Name, settings, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Persists <c>TrustServerCertificate = true</c> with a read-modify-write: the blob on disk is
    /// re-read and only the trust flag flipped on it, so an editor save that landed while this
    /// connect (and its prompt) was in flight is not clobbered by the connect-time snapshot. The
    /// snapshot is the fallback only when the stored blob is missing/unreadable. Same default
    /// <see cref="JsonSerializer"/> shape the tunnel editor writes
    /// (<c>TunnelConfigsViewModel.SerializeSecret</c>), so the editor round-trips the blob unchanged.
    ///
    /// <para>The consent the user just gave was "skip TLS verification for {snapshot.Server}:{snapshot.Port}".
    /// If the re-read blob now points at a DIFFERENT server/port, or pins a CA — which the portal
    /// constructor would silently bypass, because the trust flag wins over <c>CaPem</c> — persisting
    /// the flag would grant trust the user never consented to. In that case this throws instead, and
    /// the consent wrapper's persist-failure handling keeps the override in-memory for this attempt
    /// only (the prompt returns on the next connect against the new settings).</para>
    /// </summary>
    internal async Task PersistTrustServerCertificateAsync(Guid tunnelConfigId, StormshieldSettings snapshot)
    {
        var current = await TryReadPersistedSettingsAsync(tunnelConfigId).ConfigureAwait(false) ?? snapshot;
        if (!DescribesSameServer(current, snapshot) || !string.IsNullOrWhiteSpace(current.CaPem))
        {
            throw new InvalidOperationException(
                "The tunnel settings changed while the trust prompt was open (different server/port, or a CA "
                + "is now pinned), so 'Trust server certificate' was not persisted.");
        }
        current.TrustServerCertificate = true;
        await _credentials.StoreTunnelConfigAsync(tunnelConfigId, JsonSerializer.SerializeToUtf8Bytes(current))
            .ConfigureAwait(false);
    }

    private static bool DescribesSameServer(StormshieldSettings a, StormshieldSettings b) =>
        string.Equals(a.Server, b.Server, StringComparison.OrdinalIgnoreCase) && a.Port == b.Port;

    private async Task<StormshieldSettings?> TryReadPersistedSettingsAsync(Guid tunnelConfigId)
    {
        try
        {
            var blob = await _credentials.ReadTunnelConfigAsync(tunnelConfigId).ConfigureAwait(false);
            return blob is null ? null : JsonSerializer.Deserialize<StormshieldSettings>(blob);
        }
        catch (Exception)
        {
            // Missing/corrupt blob or malformed JSON — callers fall back to their in-memory snapshot.
            return null;
        }
    }

    // Serializes the consent flow (recheck → prompt → persist) so two establishes that hit the TLS
    // failure at the same time ask the user ONCE: the second waiter re-reads the persisted settings
    // under the gate and skips the prompt when the first already granted trust. Static because the
    // provider is a DI singleton; the rare consent path tolerates app-wide serialization.
    private static readonly SemaphoreSlim s_tlsConsentGate = new(1, 1);

    /// <summary>
    /// Runs one resolve <paramref name="attempt"/> with a one-shot TLS-trust recovery. When the portal
    /// rejects the firewall's certificate — the common case: SNS factory certificates are signed by an
    /// appliance-local CA the OS does not trust — the user is told what failed and asked whether to trust
    /// the server. Accepting flips <see cref="StormshieldSettings.TrustServerCertificate"/> on, persists
    /// it (so the question is asked once, not on every connect), and retries the attempt with TLS
    /// verification off. Declining surfaces an actionable error instead of the raw handshake failure.
    ///
    /// <para>The recovery triggers only when <see cref="IStormshieldPortal.LastTlsFailure"/> is set —
    /// i.e. the validation callback actually rejected a certificate. A protocol-level handshake failure
    /// (which trusting the server would not fix) never reaches the callback and is not offered the
    /// prompt. Tunnels with a pinned CA (<see cref="StormshieldSettings.CaPem"/>) are NEVER offered the
    /// prompt either: the user explicitly opted into verification, and a pin miss may mean interception —
    /// one habituated click would permanently bypass the pin (the portal constructor honors the trust
    /// flag BEFORE the pin). They get a hard, precise error instead.</para>
    ///
    /// <para>Static + seam-injected (portal factory, attempt, trust prompt, reload/persist callbacks) so
    /// the consent/persist/retry choreography is unit-testable without a live firewall, a real dialog,
    /// or DPAPI.</para>
    /// </summary>
    /// <param name="portalFactory">Creates a portal from the CURRENT <paramref name="settings"/> — called
    /// again for the retry after the consent flow has flipped <c>TrustServerCertificate</c>.</param>
    /// <param name="attempt">The resolve to run against a portal (production: <see cref="ResolveAutomaticCoreAsync"/>
    /// with its dependencies closed over).</param>
    /// <param name="reloadPersistedTrustAsync">Re-reads the persisted settings and returns whether trust is
    /// already granted — true when a concurrent connect answered the prompt while this one was failing.</param>
    internal static async Task<(string Profile, string DataPlanePassword, bool OptimisticCacheHit)> ResolveAutomaticWithTlsConsentAsync(
        Func<IStormshieldPortal> portalFactory,
        Func<IStormshieldPortal, Task<(string Profile, string DataPlanePassword, bool OptimisticCacheHit)>> attempt,
        ITlsTrustPromptService tlsTrustPrompt,
        Func<Task<bool>> reloadPersistedTrustAsync,
        Func<Task> persistTrustAsync,
        ILogger logger,
        string configName,
        StormshieldSettings settings,
        CancellationToken cancellationToken)
    {
        StormshieldTlsFailure tlsFailure;
        Exception original;
        using (var portal = portalFactory())
        {
            try
            {
                return await attempt(portal).ConfigureAwait(false);
            }
            catch (Exception ex) when (
                !settings.TrustServerCertificate
                && portal.LastTlsFailure is not null
                && (ex is StormshieldTlsPreflightException || IsTlsAuthenticationFailure(ex)))
            {
                if (!string.IsNullOrWhiteSpace(settings.CaPem))
                {
                    // A pin miss is a strong signal (rotated certificate — or interception). Fail
                    // hard with the precise reason; never offer to skip verification here.
                    throw new InvalidOperationException(
                        $"The TLS certificate presented by '{settings.Server}:{settings.Port}' does not chain to "
                        + "the CA pinned in this tunnel's settings. If the firewall's certificate legitimately "
                        + "changed, update the pinned CA (PEM) in the tunnel editor. Certificate: "
                        + $"{portal.LastTlsFailure.Subject ?? "(unknown)"}, issued by {portal.LastTlsFailure.Issuer ?? "(unknown)"}.",
                        ex);
                }
                // The filter guarantees LastTlsFailure is non-null; nothing runs on this portal
                // between the filter and here.
                tlsFailure = portal.LastTlsFailure!;
                original = ex;
            }
        }

        await s_tlsConsentGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (await reloadPersistedTrustAsync().ConfigureAwait(false))
            {
                // A concurrent connect for this tunnel was granted trust while this one was failing —
                // don't ask the user the same question twice in a row (and don't re-persist).
                logger.LogInformation(
                    "Stormshield '{Name}': server trust was granted by a concurrent connection; skipping the prompt.",
                    configName);
            }
            else if (await tlsTrustPrompt.ConfirmTrustAsync(
                $"Unverified VPN server certificate — {configName}",
                BuildTlsTrustPromptMessage(settings, tlsFailure),
                cancellationToken).ConfigureAwait(false))
            {
                // A failed secret write must not block the connect the user just approved: log loudly
                // and continue with trust for this attempt only (the prompt simply returns on the next
                // connect). The persist callback flips the flag on whatever it writes, so it does not
                // depend on the in-memory snapshot being updated first.
                try
                {
                    await persistTrustAsync().ConfigureAwait(false);
                    logger.LogInformation(
                        "Stormshield '{Name}': user chose to trust '{Server}:{Port}' despite a TLS certificate "
                        + "validation failure; 'Trust server certificate' is now enabled on the tunnel settings.",
                        configName, settings.Server, settings.Port);
                }
                catch (Exception persistEx)
                {
                    logger.LogWarning(persistEx,
                        "Stormshield '{Name}': failed to persist 'Trust server certificate' after the user trusted "
                        + "the server; connecting with TLS verification skipped for this attempt only (the prompt "
                        + "will return on the next connect).", configName);
                }
            }
            else
            {
                throw new InvalidOperationException(
                    $"The TLS certificate presented by '{settings.Server}:{settings.Port}' could not be verified, "
                    + "and you chose not to trust it. To connect, paste the firewall's CA certificate (PEM) into this "
                    + $"tunnel's settings — or reconnect and choose \"{ITlsTrustPromptService.AcceptButtonLabel}\" "
                    + "to skip TLS verification for this tunnel from now on.",
                    original);
            }

            // Both granted paths continue here: flip the snapshot BEFORE the retry so portalFactory
            // builds the next portal with verification off.
            settings.TrustServerCertificate = true;
        }
        finally
        {
            s_tlsConsentGate.Release();
        }

        using var trustedPortal = portalFactory();
        return await attempt(trustedPortal).ConfigureAwait(false);
    }

    /// <summary>
    /// True when the exception chain contains a TLS authentication failure — HttpClient surfaces a
    /// rejected server certificate as <see cref="HttpRequestException"/> wrapping an
    /// <see cref="AuthenticationException"/> (possibly re-wrapped by
    /// <see cref="DownloadProfileV5WrappedAsync"/>). The caller additionally requires
    /// <see cref="IStormshieldPortal.LastTlsFailure"/> to be set, which narrows the match to
    /// certificate validation specifically.
    /// </summary>
    internal static bool IsTlsAuthenticationFailure(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is AuthenticationException) return true;
        }
        return false;
    }

    /// <summary>
    /// Builds the user-facing body of the trust prompt: what failed (in plain words derived from the
    /// <see cref="SslPolicyErrors"/> bits plus the OS chain verdict, so an expired or revoked
    /// certificate isn't misdiagnosed as merely self-signed), the identity of the certificate that
    /// would be trusted, why this is commonly benign on SNS appliances, and exactly what accepting
    /// changes (the persisted "Trust server certificate" setting) plus the risk it carries. Only
    /// shown for tunnels WITHOUT a pinned CA — pin misses fail hard instead. Never includes credentials.
    /// </summary>
    private static string BuildTlsTrustPromptMessage(StormshieldSettings settings, StormshieldTlsFailure failure)
    {
        var sb = new StringBuilder();
        sb.Append("The TLS certificate presented by '").Append(settings.Server).Append(':').Append(settings.Port)
            .Append("' could not be verified: ")
            .Append(DescribeTlsPolicyErrors(failure.PolicyErrors))
            .Append('.');

        sb.AppendLine().AppendLine();
        if (!string.IsNullOrEmpty(failure.Subject)) sb.Append("Certificate: ").Append(failure.Subject).AppendLine();
        if (!string.IsNullOrEmpty(failure.Issuer)) sb.Append("Issued by: ").Append(failure.Issuer).AppendLine();
        if (!string.IsNullOrEmpty(failure.Thumbprint)) sb.Append("Thumbprint (SHA-1): ").Append(failure.Thumbprint).AppendLine();
        if (failure.NotBefore is { } from && failure.NotAfter is { } until)
            sb.Append("Valid: ").Append(from.ToString("yyyy-MM-dd")).Append(" to ").Append(until.ToString("yyyy-MM-dd")).AppendLine();
        if (!string.IsNullOrEmpty(failure.ChainStatus))
            sb.Append("Windows reported: ").Append(failure.ChainStatus).AppendLine();

        sb.AppendLine();
        sb.AppendLine(
            "Stormshield firewalls ship with a factory certificate that public authorities do not vouch for, "
            + "so on many networks this is expected.");
        sb.AppendLine();
        sb.Append(
            $"Choosing \"{ITlsTrustPromptService.AcceptButtonLabel}\" updates this tunnel's settings to skip TLS "
            + "verification for this server from now on (the \"Trust server certificate\" option), so you will not "
            + "be asked again. Only do this if you are sure you are talking to your own firewall — with "
            + "verification off, a machine impersonating it could capture your VPN username, password");
        if (settings.UseOtp) sb.Append(" and one-time codes");
        sb.Append('.');
        return sb.ToString();
    }

    private static string DescribeTlsPolicyErrors(SslPolicyErrors errors)
    {
        // RemoteCertificateChainErrors covers more than "untrusted root" — expiry, revocation, and
        // partial chains land here too — so keep the wording open and let the "Windows reported:"
        // chain-status line in the prompt carry the specific verdict.
        var parts = new List<string>();
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
            parts.Add("the server did not present a certificate");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
            parts.Add("it could not be chained to a certificate authority this machine trusts "
                + "(it may be self-signed, from a private CA, expired, or revoked)");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
            parts.Add("its name does not match the server address");
        return parts.Count > 0 ? string.Join(", and ", parts) : "certificate validation failed";
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
        IProgress<TunnelProgress>? progress = null,
        Action<string>? onOtpSpent = null)
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

        // Cache MISS with the change-check having just failed TLS certificate validation: the
        // download below is doomed to the identical handshake failure — but only AFTER consuming
        // the user's attention on an OTP prompt. Fail fast BEFORE prompting; the consent wrapper
        // turns this into the trust prompt, and the post-consent retry collects a code exactly once.
        // (serverHash == null with a cached profile never reaches here — that's the optimistic hit.)
        if (serverHash is null && portal.LastTlsFailure is not null)
        {
            throw new StormshieldTlsPreflightException(
                $"The TLS certificate presented by '{settings.Server}:{settings.Port}' could not be verified.");
        }

        // Cache MISS: download (spends the OTP on the HTTPS step), persist for next time, then stop.
        var downloadOtp = await PromptOtpAsync(otpPrompt, configName, cancellationToken).ConfigureAwait(false);
        logger.LogInformation(
            "Stormshield '{Name}': {Reason}; downloading a fresh configuration (this uses the one-time code).",
            configName, cached is null ? "no cached configuration" : "firewall config changed");
        progress?.Report(new TunnelProgress(TunnelPhase.DownloadingConfiguration));
        var rawProfile = await DownloadProfileV5WrappedAsync(portal, settings, downloadOtp, cancellationToken).ConfigureAwait(false);
        // The download succeeded, so the firewall has now DEFINITIVELY consumed this one-time code. Record it
        // (only here — never on a failed download) so an immediate same-code retry, the cold-start trap this
        // whole path exists for, is rejected locally instead of replayed at the firewall.
        onOtpSpent?.Invoke(downloadOtp);
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

/// <summary>
/// Thrown by the Automatic + OTP flow when the unauthenticated change-check has already failed TLS
/// certificate validation and no cached profile exists: the configuration download would fail the
/// same handshake, but only after spending the user's attention on an OTP prompt. The consent
/// wrapper (<see cref="StormshieldTunnelProvider.ResolveAutomaticWithTlsConsentAsync"/>) intercepts
/// it and shows the trust prompt; it derives from <see cref="InvalidOperationException"/> so it
/// degrades to a normal actionable error anywhere the wrapper deliberately does not intercept
/// (e.g. CA-pinned tunnels).
/// </summary>
internal sealed class StormshieldTlsPreflightException : InvalidOperationException
{
    public StormshieldTlsPreflightException(string message) : base(message) { }
}
