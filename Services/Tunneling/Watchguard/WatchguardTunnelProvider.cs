using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services.Tunneling.OpenVpn;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Provides <see cref="TunnelKind.Watchguard"/> tunnels for WatchGuard Mobile VPN with SSL.
///
/// WatchGuard SSL is OpenVPN over TCP/443 with a Firebox CA + client cert chain, so this
/// provider does the WatchGuard-specific work in managed code — optional HTTPS pre-auth +
/// OTP prompt against `/?action=sslvpn_logon`, then synthesizes an in-memory `.ovpn` from
/// <see cref="WatchguardSettings"/> and delegates to the existing OpenVPN sidecar
/// (<c>wormhole-ovpnproxy.exe</c>). No new sidecar binary is bundled.
/// </summary>
public sealed class WatchguardTunnelProvider : ITunnelProvider
{
    /// <summary>
    /// Cap for follow-up challenge rounds. WatchGuard's documented 2FA flows complete in one
    /// challenge round (OTP). RADIUS-backed deployments occasionally issue a second round
    /// (new-PIN). Anything past 3 rounds is almost certainly the gateway misbehaving and we
    /// stop to avoid an infinite OTP-prompt loop.
    /// </summary>
    private const int MaxChallengeRounds = 3;

    private readonly IOtpPromptService _otpPrompt;
    private readonly IWatchguardSamlAuthService _samlAuth;
    private readonly IWatchguardProfileCache _profileCache;
    private readonly ILogger<WatchguardTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public WatchguardTunnelProvider(
        IOtpPromptService otpPrompt,
        IWatchguardSamlAuthService samlAuth,
        IWatchguardProfileCache profileCache,
        ILogger<WatchguardTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _otpPrompt = otpPrompt;
        _samlAuth = samlAuth;
        _profileCache = profileCache;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.Watchguard;

    public async Task<ITunnelInstance> EstablishAsync(
        TunnelConfig config,
        byte[] secretBlob,
        CancellationToken cancellationToken,
        IProgress<TunnelProgress>? progress = null)
    {
        var settings = JsonSerializer.Deserialize<WatchguardSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Watchguard payload.");

        // Symmetric pre-flight with TunnelConfigsViewModel.ValidateWatchguard: catch the
        // kind/blob-mismatch case here too so the user gets an actionable error rather than a
        // cryptic HTTP error from the pre-auth request or a confused OpenVPN profile parse.
        if (string.IsNullOrWhiteSpace(settings.Server))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has an unreadable Watchguard payload (empty Server). " +
                "Open the tunnel editor to re-enter settings.");
        }

        // Authenticating covers the whole credential-resolution step (status probe, SAML or
        // username/password + any OTP, and config download) so the connecting stepper shows a live
        // sub-status before the longer tunnel bring-up below.
        progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));
        var resolved = await ResolveProfileAndCredentialsAsync(config, settings, cancellationToken)
            .ConfigureAwait(false);

        // Log the synthesized .ovpn DIRECTIVES (remote/proto/cipher/tls-crypt presence) with every
        // inline PEM/key body redacted, so a failed OpenVPN3 handshake can be diagnosed against the
        // actual profile without ever writing the client private key (or CA/cert bodies) to disk.
        // Pairs with the shim's stderr event/log trace: directives say WHAT we asked for, the trace
        // says WHERE the core failed.
        _logger.LogInformation(
            "Watchguard '{Name}' OpenVPN profile directives (key material redacted):\n{Directives}",
            config.Name, RedactProfileForLog(resolved.Profile));

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = resolved.Profile,
            Username = resolved.Username,
            Password = resolved.Password,
            // Carries the user's single second factor (OTP or "p") so the sidecar can answer an
            // OpenVPN-layer dynamic challenge (CRV1) WITHOUT a second prompt. Null when 2FA was
            // satisfied at the web portal (download fallback) or not required.
            ChallengeResponse = resolved.ChallengeResponse,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        _logger.LogDebug("Launching OpenVPN sidecar (Watchguard provider) at {Path}.", sidecarPath);

        progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));

        // Tells a real one-time code apart from "p"/the web-portal path, so a gateway rejection of a
        // typed code can be reframed with a code-specific hint (see the catch below).
        var isOneTimeCode = !string.IsNullOrEmpty(resolved.ChallengeResponse)
            && !resolved.ChallengeResponse.Equals("p", StringComparison.OrdinalIgnoreCase);

        OpenVpnProcessHost host;
        try
        {
            host = await OpenVpnProcessHost.StartAsync(
                sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (resolved.FromCache && ex is not OperationCanceledException
            && !IsAuthOrChallengeFailure(ex) && !IsTransientTransportFailure(ex))
        {
            // A cached profile failed for a reason that is NEITHER a 2FA/auth outcome NOR a transient
            // transport/timeout — i.e. the kind of failure a STALE profile actually produces (the firewall
            // rotated the client cert/key under an unchanged server/username, a TLS verify error, an
            // unparseable profile). Only then drop it so the NEXT connect re-downloads. We deliberately do
            // NOT drop on:
            //   - auth / dynamic-challenge failures (rejected OTP, unanswered/timed-out push, re-challenge):
            //     the PROFILE is fine, only the second factor failed; or
            //   - transport / timeout failures (CONNECTION_TIMEOUT, NETWORK_RECV_ERROR — e.g. the gateway
            //     rate-limiting a rapid reconnect by going silent mid-handshake): also not the profile's fault.
            // Dropping on either would force the next connect onto the web-portal path (which can't answer the
            // tunnel's CRV1, and re-fires the portal logon) and oscillate, instead of letting the user just
            // retry the factor on the cached profile.
            _logger.LogWarning(ex,
                "Watchguard '{Name}': the cached profile failed to start the tunnel (not an auth or transport error); dropping it so the next connect re-downloads.",
                config.Name);
            await _profileCache.DeleteAsync(config.Id, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch (Exception ex) when (isOneTimeCode && ex is not OperationCanceledException
            && (IsAuthOrChallengeFailure(ex) || IsTransientTransportFailure(ex)))
        {
            // A typed one-time code failed to bring up the tunnel — either rejected at the OpenVPN dynamic
            // challenge (CRV1 AUTH_FAILED) or the gateway accepted the response then went silent until the
            // connect timed out (TRANSPORT_ERROR / CONNECTION_TIMEOUT). On this firmware the dominant cause of
            // BOTH is AuthPoint's brief post-authentication cooldown: for ~20-30s after a recent push approval
            // or login, the next attempt is rate-limited server-side (a measured >24s window that escalates
            // from an instant reject to a silent hang). Only waiting clears it — we do NOT auto-retry, which
            // would just burn attempts toward the gateway's failed-auth lockout. Replace the raw sidecar dump
            // with an actionable hint.
            _logger.LogWarning(ex,
                "Watchguard '{Name}': the one-time code did not complete the tunnel (rejected or timed out — most likely AuthPoint's post-push/login cooldown).",
                config.Name);
            throw new InvalidOperationException(
                "WatchGuard couldn't complete the connection with your one-time code. Right after a push approval " +
                "or login, AuthPoint briefly rate-limits the next attempt for ~20-30 seconds — it may reject the " +
                "code or stop responding mid-handshake. Wait about half a minute and try again, or type \"p\" to " +
                "approve with a push instead. (If it keeps failing when you haven't just logged in, check that the " +
                "gateway is reachable.)", ex);
        }

        // Wrap-after-start safety: same pattern as Fortinet/OpenVPN providers — if the
        // SocksTunnelInstance ctor ever throws (today its args can't trigger one, but a future
        // ArgumentNullException.ThrowIfNull added inside the ctor would), the host would be
        // left running with no managed reference to dispose it.
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

    /// <summary>
    /// The resolved inputs for the OpenVPN sidecar: the synthesized profile, the username/password,
    /// and an optional OpenVPN-layer 2FA response (CRV1) carried for the dynamic-challenge case.
    /// <paramref name="FromCache"/> marks a profile that came from the per-tunnel cache (not a fresh
    /// download or imported material), so a failed bring-up can drop the cache and re-download next
    /// time rather than loop on a profile the firewall may have rotated.
    /// </summary>
    private sealed record ResolvedConnection(
        string Profile, string Username, string Password, string? ChallengeResponse, bool FromCache = false);

    private async Task<ResolvedConnection> ResolveProfileAndCredentialsAsync(
        TunnelConfig config, WatchguardSettings settings, CancellationToken cancellationToken)
    {
        // Preferred path: connect via OpenVPN directly and do 2FA exactly ONCE — at the OpenVPN
        // data-channel dynamic challenge (CRV1) — with NO web sslvpn_logon, so the user is never
        // prompted twice and the portal's spurious push never fires (the native client behaves the
        // same way). We can take it whenever we already hold a complete profile: either the user
        // imported one (CA + client cert + key), or a prior connect cached the profile this tunnel
        // downloaded. SAML (a browser flow) and configs with neither fall through to the web-portal
        // path below — which, for username/password, caches the profile it downloads so the NEXT
        // connect upgrades to this single-2FA path.
        if (settings.AuthMode != WatchguardAuthMode.Saml
            && !string.IsNullOrWhiteSpace(settings.Username)
            && !string.IsNullOrWhiteSpace(settings.Password))
        {
            if (HasCompleteManualProfile(settings))
            {
                return await ResolveViaStoredProfileAsync(
                    config, settings, WatchguardProfileBuilder.Build(settings),
                    source: "imported profile", fromCache: false, cancellationToken).ConfigureAwait(false);
            }

            var cachedProfile = await _profileCache.TryReadProfileAsync(config.Id, settings, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(cachedProfile))
            {
                return await ResolveViaStoredProfileAsync(
                    config, settings, cachedProfile,
                    source: "cached profile", fromCache: true, cancellationToken).ConfigureAwait(false);
            }
        }

        using var portal = new WatchguardConfigClient(
            settings.TrustServerCertificate, settings.CaPem, _loggerFactory.CreateLogger<WatchguardConfigClient>());
        var status = await ProbeGatewayStatusAsync(portal, settings, cancellationToken).ConfigureAwait(false);
        ApplyEffectiveDomain(settings, status, config.Name);
        var authMode = ResolveAuthMode(settings, status);

        return authMode == WatchguardAuthMode.Saml
            ? await ResolveSamlAsync(portal, config, settings, cancellationToken).ConfigureAwait(false)
            : await ResolveUsernamePasswordAsync(portal, config, settings, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves the connection from a complete profile (imported .wgssl material OR a cached download)
    /// and prompts ONCE for the second factor. The factor type then decides how 2FA is satisfied:
    ///
    /// <list type="bullet">
    ///   <item><b>one-time passcode</b> — answered deterministically at the OpenVPN data-channel
    ///   dynamic challenge (CRV1): carried as <see cref="ResolvedConnection.ChallengeResponse"/>, no
    ///   web logon, no portal push. The reliable path.</item>
    ///   <item><b>"p" (push)</b> — approved once at the web <c>sslvpn_logon</c> long-poll (the reliable
    ///   primitive that BLOCKS until the phone tap), THEN the OpenVPN connect carries <c>"p"</c> as the
    ///   CRV1 answer. The bet: this firewall always re-challenges the tunnel, so we lean on AuthPoint's
    ///   grace window — primed by the just-approved web push — to let the tunnel's <c>"p"</c> through
    ///   WITHOUT a second push. If the grace window doesn't carry, the armed <c>"p"</c> fires a second
    ///   push (the connect still succeeds, at the cost of a second tap) rather than failing.</item>
    /// </list>
    /// </summary>
    private async Task<ResolvedConnection> ResolveViaStoredProfileAsync(
        TunnelConfig config, WatchguardSettings settings, string profile, string source, bool fromCache,
        CancellationToken cancellationToken)
    {
        var entered = await PromptForSecondFactorAsync(config.Name, cancellationToken).ConfigureAwait(false);

        if (entered.Equals("p", StringComparison.OrdinalIgnoreCase))
        {
            await ApprovePushViaWebLogonAsync(config, settings, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation(
                "Watchguard '{Name}': push approved at the web layer; connecting via the {Source} with an armed CRV1 push fallback (grace window may absorb it).",
                config.Name, source);
            return new ResolvedConnection(profile, settings.Username, settings.Password, "p", fromCache);
        }

        _logger.LogInformation(
            "Watchguard '{Name}': connecting via the {Source} (no web logon); the one-time code answers the OpenVPN challenge.",
            config.Name, source);
        return new ResolvedConnection(profile, settings.Username, settings.Password, entered, fromCache);
    }

    /// <summary>
    /// Approves an AuthPoint push through the web <c>sslvpn_logon</c> long-poll — the reliable push
    /// primitive the native client uses: a bare logon to obtain the <c>logon_id</c>, then the distinct
    /// <c>mfa_response&amp;mfa_choice=p</c> leg, which BLOCKS (up to ~120s) until the phone tap returns
    /// <c>logon_status=1</c>. Throws an actionable error on denial/timeout/failure. Downloads nothing —
    /// it only approves the second factor; the OpenVPN connect that follows uses the stored profile.
    /// </summary>
    private async Task ApprovePushViaWebLogonAsync(
        TunnelConfig config, WatchguardSettings settings, CancellationToken cancellationToken)
    {
        var domain = ResolveEffectiveDomain(settings.Domain, null);
        using var portal = new WatchguardConfigClient(
            settings.TrustServerCertificate, settings.CaPem, _loggerFactory.CreateLogger<WatchguardConfigClient>());

        async Task<PreAuthOutcome> SendAsync(Func<Task<PreAuthOutcome>> call, string what, bool isPush)
        {
            try
            {
                return await call().ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Watchguard push {what} could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new InvalidOperationException(
                    isPush
                        ? "Watchguard push approval timed out — approve the notification on your phone and retry."
                        : $"Watchguard push {what} timed out talking to '{settings.Server}:{settings.Port}'.", ex);
            }
        }

        var bare = await SendAsync(
            () => portal.LogonAsync(settings.Server, settings.Port, settings.Username, settings.Password, domain, cancellationToken),
            "pre-auth", isPush: false).ConfigureAwait(false);

        switch (bare)
        {
            case PreAuthOutcome.Ok:
                // Gateway accepted the bare password with no 2FA — nothing to approve.
                return;
            case PreAuthOutcome.Failure f:
                throw new InvalidOperationException($"Watchguard push pre-auth failed: {f.Reason}");
            case PreAuthOutcome.Challenge ch:
                _logger.LogInformation("Watchguard '{Name}': sending an AuthPoint push and waiting for approval.", config.Name);
                var resp = await SendAsync(
                    () => portal.RespondToMfaChoiceAsync(settings.Server, settings.Port, ch.LogonId, "p", cancellationToken),
                    "approval", isPush: true).ConfigureAwait(false);
                switch (resp)
                {
                    case PreAuthOutcome.Ok:
                        return; // approved on the phone
                    case PreAuthOutcome.Failure rf:
                        throw new InvalidOperationException($"Watchguard push was not approved: {rf.Reason}");
                    default:
                        throw new InvalidOperationException(
                            "Watchguard push did not complete — approve the notification on your phone and retry.");
                }
            default:
                throw new InvalidOperationException(
                    $"Watchguard push produced an unexpected outcome: {bare?.GetType().Name ?? "null"}.");
        }
    }

    /// <summary>
    /// True when an OpenVPN sidecar start failure was an AUTHENTICATION / 2FA outcome rather than a
    /// stale-profile (cert/transport) failure — a rejected code, an unanswered/timed-out push, or a
    /// re-challenge the response didn't satisfy. Matched on the sidecar stderr folded into the
    /// exception message by OpenVpnProcessHost. Used so a 2FA failure does NOT evict the (valid)
    /// cached profile.
    /// </summary>
    private static bool IsAuthOrChallengeFailure(Exception ex) =>
        ex.Message.Contains("AUTH_FAILED", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("dynamic-challenge", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("DYNAMIC_CHALLENGE", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when a sidecar start failure was a transient TRANSPORT / network / readiness-timeout outcome
    /// (CONNECTION_TIMEOUT, TRANSPORT_ERROR, NETWORK_RECV/EOF_ERROR, or our own ready-timeout) rather than
    /// an auth or stale-profile failure. On this firmware the gateway rate-limits a rapid reconnect by
    /// accepting the TCP and then going silent mid-handshake, which surfaces here — so, like a 2FA failure,
    /// it must NOT evict the (valid) cached profile, and for a typed one-time code it folds into the same
    /// post-auth-cooldown hint. Matched on the sidecar stderr folded into the message by OpenVpnProcessHost.
    /// </summary>
    private static bool IsTransientTransportFailure(Exception ex) =>
        ex is TimeoutException
        || ex.Message.Contains("CONNECTION_TIMEOUT", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("TRANSPORT_ERROR", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("NETWORK_RECV_ERROR", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("NETWORK_EOF_ERROR", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("did not become ready", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("did not produce a READY", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Prompts the user once for an AuthPoint second factor: a one-time passcode, or "p" to request
    /// a push notification. Returns the value to feed into the OpenVPN dynamic-challenge response
    /// ("p" normalized for the push selector). Throws on cancel/empty, matching the pre-auth loop.
    /// </summary>
    private async Task<string> PromptForSecondFactorAsync(string configName, CancellationToken cancellationToken)
    {
        var entered = await _otpPrompt.PromptAsync(
            $"Watchguard 2FA — {configName}",
            "Enter your one-time passcode, or type 'p' to approve with a push notification.",
            cancellationToken).ConfigureAwait(false);
        if (entered is null)
            throw new InvalidOperationException("Watchguard 2FA prompt was cancelled by the user.");
        entered = entered.Trim();
        if (entered.Length == 0)
            throw new InvalidOperationException("Watchguard 2FA prompt returned an empty code.");
        return entered.Equals("p", StringComparison.OrdinalIgnoreCase) ? "p" : entered;
    }

    private async Task<WatchguardGatewayStatus?> ProbeGatewayStatusAsync(
        WatchguardConfigClient portal, WatchguardSettings settings, CancellationToken cancellationToken)
    {
        if (settings.AuthMode != WatchguardAuthMode.Automatic
            && !IsDefaultDomain(settings.Domain)
            && !string.IsNullOrWhiteSpace(settings.Domain))
        {
            return null;
        }

        try
        {
            var status = await portal.GetStatusAsync(settings.Server, settings.Port, cancellationToken).ConfigureAwait(false);
            _logger.LogDebug(
                "Watchguard status from {Server}:{Port}: SAML={SamlEnabled}, IdP={Idp}, Domains={Domains}.",
                settings.Server,
                settings.Port,
                status.SamlEnabled,
                status.SamlIdentityProviderName,
                string.Join(", ", status.AuthDomains));
            return status;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogInformation(
                ex,
                "Watchguard status check failed for {Server}:{Port}; using configured Watchguard authentication settings.",
                settings.Server, settings.Port);
            return null;
        }
    }

    private static WatchguardAuthMode ResolveAuthMode(WatchguardSettings settings, WatchguardGatewayStatus? status)
    {
        if (settings.AuthMode != WatchguardAuthMode.Automatic)
            return settings.AuthMode;

        return status is null
            ? WatchguardAuthMode.UsernamePassword
            : ResolveAutomaticAuthMode(settings, status);
    }

    internal static WatchguardAuthMode ResolveAutomaticAuthMode(
        WatchguardSettings settings,
        WatchguardGatewayStatus status)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!string.IsNullOrWhiteSpace(settings.Username) && !string.IsNullOrWhiteSpace(settings.Password))
            return WatchguardAuthMode.UsernamePassword;
        return status.SamlEnabled ? WatchguardAuthMode.Saml : WatchguardAuthMode.UsernamePassword;
    }

    internal static string ResolveEffectiveDomain(string? configuredDomain, WatchguardGatewayStatus? status)
    {
        // The native wgsslvpnc.exe 2026.2 client has NO domain field — it sends an EMPTY fw_domain
        // and lets the Firebox use its default SSL-VPN authentication path. We mirror that whenever
        // the user hasn't set a domain. This matters beyond cosmetics: auto-detecting and sending an
        // explicit domain (e.g. "AuthPoint") selects that specific AuthPoint policy, which fires a
        // push notification even on an OTP login. The empty/default path validates the OTP with no
        // push — the behavior users get from the native client. `status` is no longer consulted for
        // the domain (it is still used upstream for SAML detection).
        _ = status;
        var trimmed = configuredDomain?.Trim() ?? string.Empty;
        // Empty OR the built-in "Firebox-DB" default both mean "the user didn't choose a domain" →
        // send empty, like the native client. Only an explicitly chosen non-default domain is sent.
        return string.IsNullOrEmpty(trimmed) || IsDefaultDomain(trimmed) ? string.Empty : trimmed;
    }

    private void ApplyEffectiveDomain(WatchguardSettings settings, WatchguardGatewayStatus? status, string configName)
    {
        var configured = settings.Domain;
        var effective = ResolveEffectiveDomain(configured, status);
        settings.Domain = effective;
        if (!string.Equals(configured?.Trim() ?? string.Empty, effective, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation(
                "Watchguard '{Name}' sending authentication domain '{Domain}' (empty = native client default).",
                configName, effective);
        }
    }

    private static bool IsDefaultDomain(string? domain) =>
        string.Equals(domain?.Trim(), WatchguardSettings.DefaultDomain, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns the .ovpn profile with every inline block body (<c>&lt;ca&gt;</c>,
    /// <c>&lt;cert&gt;</c>, <c>&lt;key&gt;</c>, <c>&lt;tls-crypt&gt;</c>, <c>&lt;tls-auth&gt;</c>, …)
    /// collapsed to a one-line "(N lines redacted)" marker so the directive structure can be logged
    /// for diagnosis WITHOUT ever emitting the client private key or other key material. The
    /// directive lines (remote, proto, cipher, data-ciphers, auth-user-pass, verify-x509-name, the
    /// presence/absence of a tls-crypt block, …) are exactly what's needed to compare against a
    /// working native-client connection; the base64 bodies are not.
    /// </summary>
    internal static string RedactProfileForLog(string profile)
    {
        if (string.IsNullOrEmpty(profile)) return string.Empty;

        var sb = new System.Text.StringBuilder(profile.Length);
        string? openBlock = null;
        var redactedLines = 0;
        foreach (var rawLine in profile.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var trimmed = rawLine.Trim();
            if (openBlock is not null)
            {
                // Inside a block: count body lines, emit nothing until the close tag.
                if (trimmed.Length == openBlock.Length + 3
                    && trimmed.StartsWith("</", StringComparison.Ordinal)
                    && trimmed.EndsWith('>')
                    && trimmed.AsSpan(2, openBlock.Length).Equals(openBlock, StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append("  (").Append(redactedLines).Append(" line(s) redacted)\n");
                    sb.Append(rawLine).Append('\n');
                    openBlock = null;
                }
                else
                {
                    redactedLines++;
                }
                continue;
            }

            // A bare "<tag>" line (not "</tag>") opens an inline block whose body we redact.
            if (trimmed.Length > 2 && trimmed[0] == '<' && trimmed[^1] == '>' && trimmed[1] != '/'
                && !trimmed.AsSpan(1, trimmed.Length - 2).ContainsAny(' ', '<', '>'))
            {
                openBlock = trimmed[1..^1];
                redactedLines = 0;
                sb.Append(rawLine).Append('\n');
                continue;
            }

            sb.Append(rawLine).Append('\n');
        }
        return sb.ToString();
    }

    private async Task<ResolvedConnection> ResolveUsernamePasswordAsync(
        IWatchguardConfigClient portal,
        TunnelConfig config,
        WatchguardSettings settings,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.Username) || string.IsNullOrWhiteSpace(settings.Password))
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' is missing a username or password for Watchguard username/password authentication.");

        var manualFallbackProfile = BuildManualProfileFallbackIfPresent(settings);
        var password = await RunPreAuthLoopAsync(portal, _otpPrompt, _logger, config.Name, settings, cancellationToken)
            .ConfigureAwait(false);
        var profile = await DownloadAndBuildProfileAsync(
                portal,
                config.Name,
                settings,
                cookies: null,
                manualFallbackProfile: manualFallbackProfile,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        // Cache the freshly downloaded profile so the NEXT connect skips the web sslvpn_logon
        // entirely and routes the user's single 2FA factor to the OpenVPN CRV1 layer (no portal
        // logon = no spurious push, no double prompt). Only cache a real download — when a manual
        // fallback profile was used the material is already in settings (and we'd never have reached
        // this path with a complete manual profile anyway).
        if (manualFallbackProfile is null)
        {
            await TryCacheProfileAsync(config.Id, settings, profile, cancellationToken).ConfigureAwait(false);
        }

        // Web-portal download path: 2FA was already satisfied at the sslvpn_logon layer, so no
        // OpenVPN-layer challenge response is carried (ChallengeResponse = null).
        return new ResolvedConnection(profile, settings.Username, password, null);
    }

    /// <summary>
    /// Best-effort persist of a downloaded profile into the per-tunnel cache. A write failure must
    /// never fail the current connection — its 2FA was already spent on the portal download — so any
    /// non-cancellation error is logged and swallowed; the next connect just re-downloads.
    /// </summary>
    private async Task TryCacheProfileAsync(
        Guid tunnelConfigId, WatchguardSettings settings, string profile, CancellationToken cancellationToken)
    {
        try
        {
            await _profileCache.WriteProfileAsync(tunnelConfigId, settings, profile, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation(
                "Watchguard: cached the downloaded profile for tunnel {TunnelId}; the next connect will skip the web logon and use a single OpenVPN-layer 2FA.",
                tunnelConfigId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Watchguard: failed to cache the downloaded profile for tunnel {TunnelId}; the next connect will re-download (web logon) until the cache can be written.",
                tunnelConfigId);
        }
    }

    private async Task<ResolvedConnection> ResolveSamlAsync(
        IWatchguardConfigClient portal,
        TunnelConfig config,
        WatchguardSettings settings,
        CancellationToken cancellationToken)
    {
        var saml = await _samlAuth.AuthenticateAsync(settings, config.Name, cancellationToken).ConfigureAwait(false);
        var profile = await DownloadAndBuildProfileAsync(
                portal,
                config.Name,
                settings,
                saml.Cookies,
                manualFallbackProfile: null,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return new ResolvedConnection(profile, saml.Username, saml.Token, null);
    }

    private async Task<string> DownloadAndBuildProfileAsync(
        IWatchguardConfigClient portal,
        string configName,
        WatchguardSettings settings,
        System.Collections.Generic.IEnumerable<System.Net.Cookie>? cookies,
        string? manualFallbackProfile,
        CancellationToken cancellationToken)
    {
        try
        {
            var bytes = await portal.DownloadConfigAsync(settings.Server, settings.Port, cookies, cancellationToken)
                .ConfigureAwait(false);
            using var stream = new MemoryStream(bytes, writable: false);
            var imported = await WatchguardWgsslImporter.ImportAsync(stream, cancellationToken).ConfigureAwait(false);
            imported.Username = settings.Username;
            imported.Password = settings.Password;
            imported.Domain = settings.Domain;
            imported.AuthMode = settings.AuthMode;
            imported.VerifyX509Name = string.IsNullOrWhiteSpace(settings.VerifyX509Name)
                ? WatchguardSettings.DefaultVerifyX509Name
                : settings.VerifyX509Name;
            imported.TrustServerCertificate = settings.TrustServerCertificate;
            return WatchguardProfileBuilder.Build(imported);
        }
        catch (Exception ex) when (
            ex is not OperationCanceledException
            && manualFallbackProfile is not null)
        {
            _logger.LogWarning(
                ex,
                "Watchguard '{Name}' could not download client.wgssl; using manually imported profile material.",
                configName);
            return manualFallbackProfile;
        }
    }

    private static string? BuildManualProfileFallbackIfPresent(WatchguardSettings settings) =>
        HasCompleteManualProfile(settings)
            ? WatchguardProfileBuilder.Build(settings)
            : null;

    private static bool HasCompleteManualProfile(WatchguardSettings settings) =>
        !string.IsNullOrWhiteSpace(settings.CaPem)
        && !string.IsNullOrWhiteSpace(settings.ClientCertPem)
        && !string.IsNullOrWhiteSpace(settings.ClientKeyPem);

    /// <summary>
    /// Runs the WatchGuard pre-auth dance and returns the password to feed to OpenVPN: either
    /// the user's stored password (no 2FA) or the OTP code accepted by the gateway. Wraps
    /// raw HttpRequestException / TaskCanceledException into actionable InvalidOperationException
    /// so the session UI sees a Watchguard-specific error instead of a generic socket error.
    ///
    /// Static helper takes everything as parameters so it's directly unit-testable with a fake
    /// <see cref="IWatchguardPreAuth"/> + <see cref="IOtpPromptService"/>.
    /// </summary>
    internal static async Task<string> RunPreAuthLoopAsync(
        IWatchguardPreAuth preAuth,
        IOtpPromptService otpPrompt,
        ILogger logger,
        string configName,
        WatchguardSettings settings,
        CancellationToken cancellationToken)
    {
        logger.LogDebug(
            "Watchguard pre-auth request to {Server}:{Port} (domain {Domain}) for '{Name}'.",
            settings.Server, settings.Port, settings.Domain, configName);

        // Local helper: issue the initial `logon` request with the standard Watchguard-specific
        // error wrapping. The 2FA answer (OTP or push selector) goes back via the `response` leg,
        // not a second logon — see the Challenge case below.
        async Task<PreAuthOutcome> SendLogonAsync(string password)
        {
            try
            {
                return await preAuth.LogonAsync(
                    settings.Server, settings.Port, settings.Username, password, settings.Domain,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Genuine token cancellation — bubble up unchanged so callers can distinguish.
                throw;
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Watchguard pre-auth could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                // TaskCanceledException with the request-timeout token (not our caller's token)
                // means the WatchGuard request budget expired.
                throw new InvalidOperationException(
                    $"Watchguard pre-auth timed out talking to '{settings.Server}:{settings.Port}'.", ex);
            }
        }

        // Local helper: surface the OTP prompt and apply the defensive trim / empty / user-cancel
        // checks. Shared by the status-4 (Firebox-DB) and status-8 (AuthPoint) challenge flows,
        // which are identical at the protocol level.
        async Task<string> PromptForOtpAsync(string challengeText)
        {
            var promptText = string.IsNullOrWhiteSpace(challengeText)
                ? "Enter an AuthPoint OTP code, or type 'p' to send a push notification."
                : challengeText + Environment.NewLine + Environment.NewLine
                  + "Enter an AuthPoint OTP code, or type 'p' to send a push notification.";
            var entered = await otpPrompt.PromptAsync(
                $"Watchguard 2FA — {configName}", promptText, cancellationToken).ConfigureAwait(false);
            if (entered is null)
            {
                // User clicked Cancel. Convention from IOtpPromptService: returning null is a user
                // action, not a token-cancel — surface as a regular InvalidOperation so upstream
                // cancellation-aware retry logic doesn't confuse this for a transient cancellation.
                throw new InvalidOperationException("Watchguard 2FA prompt was cancelled by the user.");
            }
            // Trim defensively. Most prompt impls already do this, but a clipboard paste that
            // includes a trailing newline would survive into the request and the credential the
            // gateway later records — gateway behavior around "123456\n" is firmware-dependent.
            entered = entered.Trim();
            if (entered.Length == 0)
            {
                throw new InvalidOperationException("Watchguard 2FA prompt returned an empty code.");
            }
            return entered;
        }

        // Local helper: answer a challenge via the response leg (an entered OTP or the "p" push
        // selector), with the same Watchguard-specific error wrapping as the initial logon. isPush
        // selects the longer push-approval timeout and tunes the timeout message.
        async Task<PreAuthOutcome> RespondAsync(string logonId, string value, bool isPush)
        {
            try
            {
                return isPush
                    ? await preAuth.RespondToMfaChoiceAsync(settings.Server, settings.Port, logonId, value, cancellationToken).ConfigureAwait(false)
                    : await preAuth.RespondToChallengeAsync(settings.Server, settings.Port, logonId, value, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Watchguard 2FA challenge response could not reach '{settings.Server}:{settings.Port}': {ex.Message}", ex);
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new InvalidOperationException(
                    isPush
                        ? $"Watchguard push approval timed out talking to '{settings.Server}:{settings.Port}'."
                        : $"Watchguard 2FA challenge response timed out talking to '{settings.Server}:{settings.Port}'.", ex);
            }
        }

        // AuthPoint / RADIUS (named) domains: collect the OTP (or the "p" push choice) UP FRONT, the
        // way the native wgsslvpnc.exe client does (username + password + passcode are entered on one
        // screen before connecting). We then fire the bare `logon` and the `response`/`mfa_response`
        // leg BACK-TO-BACK. This matters: the firewall returns the status-8 challenge in well under a
        // second, but only fires the AuthPoint push a few seconds later if no second factor has
        // arrived. Prompting AFTER the challenge (the old flow) left that window open while the user
        // typed — the spurious push. Answering within milliseconds closes it. Firebox-DB (the local
        // database) has no 2FA, so it keeps the plain bare-logon flow below.
        if (!IsDefaultDomain(settings.Domain) && !string.IsNullOrWhiteSpace(settings.Domain))
        {
            var answer = await PromptForOtpAsync(string.Empty).ConfigureAwait(false);
            var isPush = answer.Equals("p", StringComparison.OrdinalIgnoreCase);
            var bare = await SendLogonAsync(settings.Password).ConfigureAwait(false);
            switch (bare)
            {
                case PreAuthOutcome.Ok:
                    return settings.Password; // gateway accepted the bare password with no 2FA
                case PreAuthOutcome.Failure bf:
                    throw new InvalidOperationException($"Watchguard pre-auth failed: {bf.Reason}");
                case PreAuthOutcome.Challenge ch:
                    logger.LogInformation(
                        "Watchguard '{Name}': answering AuthPoint challenge with {Factor}.",
                        configName, isPush ? "a push request" : "the one-time passcode");
                    var resp = await RespondAsync(ch.LogonId, isPush ? "p" : answer, isPush).ConfigureAwait(false);
                    return resp switch
                    {
                        // OTP: the code itself is the OpenVPN credential (gateway one-shot). Push: MFA
                        // is satisfied out-of-band, so OpenVPN re-presents the account password.
                        PreAuthOutcome.Ok => isPush ? settings.Password : answer,
                        PreAuthOutcome.Failure rf => throw new InvalidOperationException($"Watchguard pre-auth failed: {rf.Reason}"),
                        _ => throw new InvalidOperationException(
                            isPush
                                ? "Watchguard push approval did not complete — approve the notification on your phone and retry."
                                : "Watchguard 2FA did not complete after the passcode response."),
                    };
                default:
                    throw new InvalidOperationException(
                        $"Watchguard pre-auth produced an unexpected outcome type: {bare?.GetType().Name ?? "null"}.");
            }
        }

        // Firebox-DB / local accounts: bare-password logon, then drive any challenge interactively.
        // mfaCredential tracks what OpenVPN presents on success: the OTP itself (the gateway records
        // the (user, OTP) one-shot) or the account password after a push.
        var outcome = await SendLogonAsync(settings.Password).ConfigureAwait(false);
        string? mfaCredential = null;
        var challengesPrompted = 0;
        while (true)
        {
            switch (outcome)
            {
                case PreAuthOutcome.Ok:
                    if (challengesPrompted == 0)
                    {
                        logger.LogDebug("Watchguard pre-auth accepted password without 2FA for '{Name}'.", configName);
                        return settings.Password;
                    }
                    return mfaCredential ?? settings.Password;

                case PreAuthOutcome.Challenge challenge:
                    {
                        if (challengesPrompted >= MaxChallengeRounds)
                        {
                            // Bound the OTP-prompt count to keep a misconfigured / hostile gateway from
                            // looping the user forever. Hit only after MaxChallengeRounds successful
                            // requests all came back as further Challenges; a final Ok is handled above
                            // before we get here.
                            throw new InvalidOperationException(
                                $"Watchguard 2FA exceeded {MaxChallengeRounds} challenge rounds — the gateway may be misconfigured.");
                        }
                        challengesPrompted++;
                        logger.LogInformation(
                            "Watchguard gateway requested 2FA challenge round {Round} for '{Name}'.",
                            challengesPrompted, configName);
                        var otp = await PromptForOtpAsync(challenge.ChallengeText).ConfigureAwait(false);
                        var isPush = otp.Equals("p", StringComparison.OrdinalIgnoreCase);
                        mfaCredential = isPush ? settings.Password : otp;
                        outcome = await RespondAsync(challenge.LogonId, isPush ? "p" : otp, isPush).ConfigureAwait(false);
                        continue;
                    }

                case PreAuthOutcome.Failure failure:
                    throw new InvalidOperationException($"Watchguard pre-auth failed: {failure.Reason}");

                default:
                    // PreAuthOutcome is a sealed-record hierarchy; this is a future-proofing guard
                    // so a new outcome type doesn't silently fall through.
                    throw new InvalidOperationException(
                        $"Watchguard pre-auth produced an unexpected outcome type: {outcome?.GetType().Name ?? "null"}.");
            }
        }
    }
}
