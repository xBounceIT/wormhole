using System;
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
    private readonly ILogger<WatchguardTunnelProvider> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public WatchguardTunnelProvider(
        IOtpPromptService otpPrompt,
        ILogger<WatchguardTunnelProvider> logger,
        ILoggerFactory loggerFactory)
    {
        _otpPrompt = otpPrompt;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public TunnelKind Kind => TunnelKind.Watchguard;

    public async Task<ITunnelInstance> EstablishAsync(TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken)
    {
        var settings = JsonSerializer.Deserialize<WatchguardSettings>(secretBlob)
            ?? throw new InvalidOperationException($"Tunnel config '{config.Name}' has an empty/invalid Watchguard payload.");

        // Symmetric pre-flight with TunnelConfigsViewModel.ValidateWatchguard: catch the
        // kind/blob-mismatch case here too so the user gets an actionable error rather than a
        // cryptic HTTP error from the pre-auth POST or a confused OpenVPN profile parse.
        if (string.IsNullOrWhiteSpace(settings.Server))
        {
            throw new InvalidOperationException(
                $"Tunnel config '{config.Name}' has an unreadable Watchguard payload (empty Server). " +
                "Open the tunnel editor to re-enter settings.");
        }

        // Build the profile BEFORE the pre-auth POST so client-side validation errors
        // (malformed PEM, control chars in Server / VerifyX509Name, etc.) fail fast and never
        // consume a one-time code or increment the gateway's failed-auth counter. The synthesized
        // profile is only used after pre-auth succeeds, but the validation it triggers belongs
        // before any network IO.
        var profile = WatchguardProfileBuilder.Build(settings);

        // Pre-auth dance: always POST to discover whether the gateway wants a 2FA code. The
        // official client does the same on every connect (no checkbox), and the round-trip is
        // fast (~100ms on a healthy Firebox).
        string effectivePassword;
        // Pass the user-supplied CA to the pre-auth client so self-signed Firebox deployments
        // (where the OS trust store doesn't vouch for the cert) can still complete the HTTPS
        // pre-flight without TrustServerCertificate. The OpenVPN sidecar's downstream <ca>
        // block validates the SAME chain, so this just brings the pre-auth path to parity.
        using (var preAuth = new WatchguardPreAuthClient(settings.TrustServerCertificate, settings.CaPem))
        {
            effectivePassword = await RunPreAuthLoopAsync(preAuth, _otpPrompt, _logger, config.Name, settings, cancellationToken)
                .ConfigureAwait(false);
        }

        var sidecar = new OpenVpnSidecarConfig
        {
            ProfileOvpn = profile,
            Username = settings.Username,
            Password = effectivePassword,
            Mock = false,
        };

        var sidecarPath = AppPaths.GetOvpnProxyExecutablePath();
        _logger.LogDebug("Launching OpenVPN sidecar (Watchguard provider) at {Path}.", sidecarPath);

        var host = await OpenVpnProcessHost.StartAsync(
            sidecarPath, sidecar, _loggerFactory.CreateLogger<OpenVpnProcessHost>(), cancellationToken)
            .ConfigureAwait(false);

        // Wrap-after-start safety: same pattern as Fortinet/OpenVPN providers — if the
        // SocksTunnelInstance ctor ever throws (today its args can't trigger one, but a future
        // ArgumentNullException.ThrowIfNull added inside the ctor would), the host would be
        // left running with no managed reference to dispose it.
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
        PreAuthOutcome outcome;
        logger.LogDebug(
            "Watchguard pre-auth POST to {Server}:{Port} (domain {Domain}) for '{Name}'.",
            settings.Server, settings.Port, settings.Domain, configName);
        try
        {
            outcome = await preAuth.LogonAsync(
                settings.Server, settings.Port, settings.Username, settings.Password, settings.Domain,
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
            // TaskCanceledException with the request-timeout token (not our caller's token) =
            // HttpClient.Timeout fired.
            throw new InvalidOperationException(
                $"Watchguard pre-auth timed out talking to '{settings.Server}:{settings.Port}'.", ex);
        }

        // Drive a multi-stage RADIUS flow (initial OTP → new-PIN challenge → confirm) to
        // completion. The cap counts CHALLENGES PROMPTED, not loop iterations — so the gateway's
        // response to the final challenge is always re-dispatched through the switch (an Ok at
        // round N must short-circuit out as success, not get thrown away). lastOtp tracks the
        // most-recent code the user typed; that's what becomes the OpenVPN password on success
        // because the gateway records the (username, OTP) tuple as a one-shot accept.
        string? lastOtp = null;
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
                    return lastOtp ?? settings.Password;

                case PreAuthOutcome.Challenge challenge:
                    if (challengesPrompted >= MaxChallengeRounds)
                    {
                        // Bound the OTP-prompt count to keep a misconfigured / hostile gateway from
                        // looping the user forever. Hit only after MaxChallengeRounds successful
                        // POSTs all came back as further Challenges; a final Ok is handled above
                        // before we get here.
                        throw new InvalidOperationException(
                            $"Watchguard 2FA exceeded {MaxChallengeRounds} challenge rounds — the gateway may be misconfigured.");
                    }
                    challengesPrompted++;
                    logger.LogInformation(
                        "Watchguard gateway requested 2FA challenge round {Round} for '{Name}'.",
                        challengesPrompted, configName);
                    var promptText = string.IsNullOrWhiteSpace(challenge.ChallengeText)
                        ? "Enter the one-time code from your authenticator."
                        : challenge.ChallengeText;
                    var otp = await otpPrompt.PromptAsync(
                        $"Watchguard 2FA — {configName}", promptText, cancellationToken).ConfigureAwait(false);
                    if (otp is null)
                    {
                        // User clicked Cancel. Convention from IOtpPromptService: returning null is
                        // a user action, not a token-cancel — surface as a regular InvalidOperation
                        // so upstream cancellation-aware retry logic doesn't confuse this for a
                        // transient cancellation that should be retried.
                        throw new InvalidOperationException("Watchguard 2FA prompt was cancelled by the user.");
                    }
                    // Trim defensively. Most prompt impls already do this, but a clipboard paste
                    // that includes a trailing newline would survive into the challenge response
                    // POST and the (user, otp) tuple OpenVPN later presents — gateway behavior
                    // around (user, "123456\n") is firmware-dependent.
                    otp = otp.Trim();
                    if (otp.Length == 0)
                    {
                        throw new InvalidOperationException("Watchguard 2FA prompt returned an empty code.");
                    }
                    lastOtp = otp;
                    try
                    {
                        outcome = await preAuth.RespondToChallengeAsync(
                            settings.Server, settings.Port, challenge.LogonId, otp, cancellationToken)
                            .ConfigureAwait(false);
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
                            $"Watchguard 2FA challenge response timed out talking to '{settings.Server}:{settings.Port}'.", ex);
                    }
                    continue;

                case PreAuthOutcome.Failure failure:
                    throw new InvalidOperationException($"Watchguard pre-auth failed: {failure.Reason}");

                default:
                    // PreAuthOutcome is a sealed-record hierarchy with three cases; this is a
                    // future-proofing guard so a new outcome type doesn't silently fall through.
                    throw new InvalidOperationException(
                        $"Watchguard pre-auth produced an unexpected outcome type: {outcome?.GetType().Name ?? "null"}.");
            }
        }
    }
}
