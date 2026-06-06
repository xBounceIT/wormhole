using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardTunnelProviderTests
{
    [Fact]
    public void Kind_IsWatchguard()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            new NullSamlAuthService(),
            new NullWatchguardProfileCache(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

        Assert.Equal(TunnelKind.Watchguard, provider.Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            new NullSamlAuthService(),
            new NullWatchguardProfileCache(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            provider.EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_RejectsKindMismatchedBlob()
    {
        // A blob serialized from a different kind's settings shape will deserialize into
        // WatchguardSettings with empty/default fields. The provider's symmetric pre-flight
        // catches this and surfaces a "re-enter settings" error before any network IO.
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            new NullSamlAuthService(),
            new NullWatchguardProfileCache(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };
        var emptyJson = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new WatchguardSettings());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.EstablishAsync(cfg, emptyJson, CancellationToken.None));
        Assert.Contains("Server", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EstablishAsync_UsernamePasswordManualFallback_ValidatesProfileBeforePreAuth()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
            new NullSamlAuthService(),
            new NullWatchguardProfileCache(),
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };
        var settings = new WatchguardSettings
        {
            Server = "127.0.0.1",
            Port = 443,
            AuthMode = WatchguardAuthMode.UsernamePassword,
            Username = "alice",
            Password = "stored-password",
            TrustServerCertificate = true,
            CaPem = "-----BEGIN CERTIFICATE-----\nBAD<CA\n-----END CERTIFICATE-----",
            ClientCertPem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
            ClientKeyPem = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
        };
        var secret = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(settings);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.EstablishAsync(cfg, secret, CancellationToken.None));

        Assert.Contains("angle bracket", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResolveAutomaticAuthMode_SamlStatusWithSavedCredentials_UsesUsernamePassword()
    {
        var settings = ValidSettings();
        settings.AuthMode = WatchguardAuthMode.Automatic;
        var status = new WatchguardGatewayStatus(
            SamlEnabled: true,
            SamlIdentityProviderName: "Entra ID",
            AuthDomains: Array.Empty<string>());

        var mode = WatchguardTunnelProvider.ResolveAutomaticAuthMode(settings, status);

        Assert.Equal(WatchguardAuthMode.UsernamePassword, mode);
    }

    [Fact]
    public void ResolveAutomaticAuthMode_SamlStatusWithoutSavedPassword_UsesSaml()
    {
        var settings = ValidSettings();
        settings.AuthMode = WatchguardAuthMode.Automatic;
        settings.Password = "";
        var status = new WatchguardGatewayStatus(
            SamlEnabled: true,
            SamlIdentityProviderName: "Entra ID",
            AuthDomains: Array.Empty<string>());

        var mode = WatchguardTunnelProvider.ResolveAutomaticAuthMode(settings, status);

        Assert.Equal(WatchguardAuthMode.Saml, mode);
    }

    [Fact]
    public void ResolveEffectiveDomain_DefaultOrUnsetDomain_SendsEmptyLikeNativeClient()
    {
        // The native 2026.2 client has no domain field; it sends an empty fw_domain. Auto-detecting
        // and sending the advertised "AuthPoint" instead selects a push-on-OTP policy. So both an
        // unset domain and the built-in "Firebox-DB" default resolve to empty.
        var authDomains = new[] { "AuthPoint" };
        var status = new WatchguardGatewayStatus(
            SamlEnabled: false,
            SamlIdentityProviderName: null,
            AuthDomains: authDomains);

        Assert.Equal(string.Empty, WatchguardTunnelProvider.ResolveEffectiveDomain(WatchguardSettings.DefaultDomain, status));
        Assert.Equal(string.Empty, WatchguardTunnelProvider.ResolveEffectiveDomain("", status));
        Assert.Equal(string.Empty, WatchguardTunnelProvider.ResolveEffectiveDomain(null, status));
    }

    [Fact]
    public void ResolveEffectiveDomain_CustomConfiguredDomain_IsPreserved()
    {
        var authDomains = new[] { "AuthPoint" };
        var status = new WatchguardGatewayStatus(
            SamlEnabled: false,
            SamlIdentityProviderName: null,
            AuthDomains: authDomains);

        var domain = WatchguardTunnelProvider.ResolveEffectiveDomain("RADIUS", status);

        Assert.Equal("RADIUS", domain);
    }

    [Fact]
    public void ResolveEffectiveDomain_IgnoresAdvertisedDomains()
    {
        // The advertised auth-domain list is no longer consulted for the fw_domain value — we always
        // mirror the native client (empty unless the user explicitly set a non-default domain).
        var authDomains = new[] { "Firebox-DB", "AuthPoint" };
        var status = new WatchguardGatewayStatus(
            SamlEnabled: false,
            SamlIdentityProviderName: null,
            AuthDomains: authDomains);

        Assert.Equal(string.Empty, WatchguardTunnelProvider.ResolveEffectiveDomain(WatchguardSettings.DefaultDomain, status));
        Assert.Equal("RADIUS-Corp", WatchguardTunnelProvider.ResolveEffectiveDomain("RADIUS-Corp", status));
    }

    // ----- Multi-stage 2FA loop tests -----
    //
    // These exercise RunPreAuthLoopAsync directly via the IWatchguardPreAuth seam. The real
    // network-talking client (WatchguardPreAuthClient) is covered separately by the
    // WatchguardPreAuthClientTests; here we focus on the loop's state machine to lock in the
    // fixes for multi-round 2FA, last-round-Ok handling, and user-cancel propagation.

    private static WatchguardSettings ValidSettings() => new()
    {
        Server = "firebox.example.com",
        Port = 443,
        Username = "alice",
        Password = "stored-password",
        Domain = "Firebox-DB",
    };

    [Fact]
    public async Task RunPreAuthLoop_NoChallenge_ReturnsStoredPassword()
    {
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt(/* never called */);
        var settings = ValidSettings();

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", settings, CancellationToken.None);

        Assert.Equal(settings.Password, result);
        Assert.Equal(0, otp.PromptCount);
    }

    [Fact]
    public async Task RunPreAuthLoop_SingleChallengeThenOk_ReturnsOtp()
    {
        // The OTP becomes the OpenVPN password — that's the WatchGuard quirk the loop has
        // to enforce. Regression-locks the (challengesPrompted > 0 → return lastOtp) branch.
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code"));
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("123456");

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None);

        Assert.Equal("123456", result);
        Assert.Equal(1, otp.PromptCount);
        // The challenge response leg must POST the OTP and the LogonId from the first leg.
        Assert.Equal("session-1", pre.LastChallengeLogonId);
        Assert.Equal("123456", pre.LastOtp);
    }

    [Fact]
    public async Task RunPreAuthLoop_Status8ChallengeThenOk_ReturnsOtp()
    {
        // Live AuthPoint behavior: the bare-password logon returns status 8, which ParseLogonResponse
        // maps to Challenge. The loop answers via the response leg and the entered OTP becomes the
        // OpenVPN credential — identical to the status-4 path.
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("1810", "Type \"p\" ... or type your one-time password"));
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("112233");

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None);

        Assert.Equal("112233", result);
        Assert.Equal("1810", pre.LastChallengeLogonId);
        Assert.Equal("112233", pre.LastOtp);
    }

    [Fact]
    public async Task RunPreAuthLoop_PushChoiceThenOk_ReturnsAccountPassword()
    {
        // Push ("p") goes through the response leg (RespondToMfaChoiceAsync). Because MFA is
        // satisfied out-of-band, the OpenVPN credential returned is the account password, not "p".
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code or p"));
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("p");

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None);

        Assert.Equal("stored-password", result);
        Assert.Equal("session-1", pre.LastMfaChoiceLogonId);
        Assert.Equal("p", pre.LastMfaChoice);
        Assert.Null(pre.LastOtp);
    }

    [Fact]
    public async Task RunPreAuthLoop_AuthPointDomain_ChallengeThenOtp_UsesResponseLegNotAppend()
    {
        // AuthPoint domains take the SAME bare-logon → response-leg path as Firebox-DB — there is no
        // appended-OTP branch (the native wgsslvpnc.exe client doesn't append for this firmware; the
        // gateway answers <errStr>501</errStr>). The bare password opens the challenge and the OTP is
        // answered via the response leg, becoming the OpenVPN credential. No push (no mfa_choice).
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("1810", "type p or your one-time password"));
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("112233");
        var settings = ValidSettings();
        settings.Domain = "AuthPoint";

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", settings, CancellationToken.None);

        Assert.Equal("112233", result);
        Assert.Equal("stored-password", pre.LastLogonPassword); // bare password, NOT appended
        Assert.Equal("112233", pre.LastOtp);                     // response leg used
        Assert.Null(pre.LastMfaChoice);                          // no push fired
    }

    [Fact]
    public async Task RunPreAuthLoop_AuthPointDomain_PushUpFront_UsesMfaResponse()
    {
        // "p" entered up front: bare logon opens the challenge and we answer immediately with the
        // mfa_response leg, which is the request that legitimately triggers the push.
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("1900", "type p or otp")); // bare logon -> challenge
        pre.Queue(new PreAuthOutcome.Ok());                                // mfa_response -> ok
        var otp = new ScriptedOtpPrompt("p");
        var settings = ValidSettings();
        settings.Domain = "AuthPoint";

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", settings, CancellationToken.None);

        Assert.Equal("stored-password", result);   // account password after a push
        Assert.Equal("p", pre.LastMfaChoice);
        Assert.Equal("1900", pre.LastMfaChoiceLogonId);
        Assert.Null(pre.LastOtp);
    }

    [Fact]
    public async Task RunPreAuthLoop_MultiRoundChallengeThenOk_ReturnsLastOtp()
    {
        // Two-round RADIUS-style flow: initial Challenge → user OTP → new Challenge → user OTP
        // → Ok. Regression-locks the loop boundary fix: a final Ok must short-circuit out as
        // success even on the last allowed round, NOT throw "exceeded rounds".
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code"));
        pre.Queue(new PreAuthOutcome.Challenge("session-2", "enter new pin"));
        pre.Queue(new PreAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("first-code", "new-pin");

        var result = await WatchguardTunnelProvider.RunPreAuthLoopAsync(
            pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None);

        // The most-recent OTP is what the gateway recorded in its session table — that's what
        // OpenVPN's auth-user-pass must re-present.
        Assert.Equal("new-pin", result);
        Assert.Equal(2, otp.PromptCount);
    }

    [Fact]
    public async Task RunPreAuthLoop_ExceedsMaxChallengeRounds_Throws()
    {
        // Keep returning Challenge forever — the loop should bail after MaxChallengeRounds
        // prompts so a misconfigured gateway can't trap the user in an infinite OTP loop.
        var pre = new ScriptedPreAuth();
        for (var i = 0; i < 10; i++)
            pre.Queue(new PreAuthOutcome.Challenge($"session-{i}", "enter code"));
        var otp = new ScriptedOtpPrompt("123456", "234567", "345678", "456789");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("exceeded", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunPreAuthLoop_UserCancelsOtp_ThrowsInvalidOperation()
    {
        // IOtpPromptService contract: returning null means user dismissed. The provider
        // surfaces this as InvalidOperationException, NOT OperationCanceledException, so
        // upstream retry logic doesn't confuse a deliberate dismiss with token cancellation.
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code"));
        var otp = new ScriptedOtpPrompt(/* null returned */);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("cancelled", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunPreAuthLoop_EmptyOtpAfterTrim_Throws()
    {
        // A whitespace-only OTP would trip gateway-side firmware bugs in unpredictable ways;
        // reject client-side instead.
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code"));
        var otp = new ScriptedOtpPrompt("   ");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunPreAuthLoop_FirstLogonFailure_Throws()
    {
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Failure("bad password"));
        var otp = new ScriptedOtpPrompt(/* never called */);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("bad password", ex.Message);
        Assert.Equal(0, otp.PromptCount);
    }

    [Fact]
    public async Task RunPreAuthLoop_ChallengeResponseFails_Throws()
    {
        // Gateway accepted the username/password but rejected the OTP — surface the gateway's
        // reason rather than a generic "challenge failed".
        var pre = new ScriptedPreAuth();
        pre.Queue(new PreAuthOutcome.Challenge("session-1", "enter code"));
        pre.Queue(new PreAuthOutcome.Failure("invalid OTP"));
        var otp = new ScriptedOtpPrompt("wrong-code");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("invalid OTP", ex.Message);
    }

    [Fact]
    public async Task RunPreAuthLoop_NetworkErrorWrapped_NotRawHttpRequestException()
    {
        // HttpRequestException from the underlying socket should be wrapped as a Watchguard-
        // specific InvalidOperationException so the session UI shows actionable text.
        var pre = new ScriptedPreAuth();
        pre.QueueThrow(new HttpRequestException("connection refused"));
        var otp = new ScriptedOtpPrompt(/* never called */);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("could not reach", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task RunPreAuthLoop_TokenCancellation_BubblesUpUnwrapped()
    {
        // Genuine caller-cancellation must propagate as OperationCanceledException so callers
        // can distinguish it from a Watchguard-specific failure.
        var pre = new ScriptedPreAuth();
        pre.QueueThrow(new TaskCanceledException("cancelled"));
        var otp = new ScriptedOtpPrompt(/* never called */);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            WatchguardTunnelProvider.RunPreAuthLoopAsync(
                pre, otp, NullLogger<WatchguardTunnelProvider>.Instance, "cfg", ValidSettings(), cts.Token));
    }

    private sealed class NullOtpPromptService : IOtpPromptService
    {
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }

    private sealed class NullSamlAuthService : IWatchguardSamlAuthService
    {
        public Task<WatchguardSamlAuthResult> AuthenticateAsync(
            WatchguardSettings settings,
            string configName,
            CancellationToken cancellationToken) =>
            Task.FromException<WatchguardSamlAuthResult>(new InvalidOperationException("not scripted"));
    }

    // Always a cache miss; records writes/deletes so a test can assert the provider cached a
    // downloaded profile (the single-2FA upgrade) without touching DPAPI or the real filesystem.
    private sealed class NullWatchguardProfileCache : IWatchguardProfileCache
    {
        public int Writes { get; private set; }
        public string? LastWrittenProfile { get; private set; }

        public Task<string?> TryReadProfileAsync(Guid tunnelConfigId, WatchguardSettings settings, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task WriteProfileAsync(Guid tunnelConfigId, WatchguardSettings settings, string profileOvpn, CancellationToken cancellationToken)
        {
            Writes++;
            LastWrittenProfile = profileOvpn;
            return Task.CompletedTask;
        }

        public Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>
    /// Scripted IWatchguardPreAuth fake. Each LogonAsync or RespondToChallengeAsync dequeues the
    /// next pre-queued outcome (or throws the next pre-queued exception). Records the most
    /// recent challenge LogonId and OTP for verification.
    /// </summary>
    private sealed class ScriptedPreAuth : IWatchguardPreAuth
    {
        private readonly Queue<object> _script = new();
        public string? LastChallengeLogonId { get; private set; }
        public string? LastOtp { get; private set; }
        public string? LastMfaChoiceLogonId { get; private set; }
        public string? LastMfaChoice { get; private set; }
        public string? LastLogonPassword { get; private set; }

        public void Queue(PreAuthOutcome outcome) => _script.Enqueue(outcome);
        public void QueueThrow(Exception ex) => _script.Enqueue(ex);

        public Task<PreAuthOutcome> LogonAsync(string server, int port, string username, string password, string domain, CancellationToken cancellationToken)
        {
            LastLogonPassword = password;
            return DequeueOrThrow();
        }

        public Task<PreAuthOutcome> RespondToChallengeAsync(string server, int port, string logonId, string otpCode, CancellationToken cancellationToken)
        {
            LastChallengeLogonId = logonId;
            LastOtp = otpCode;
            return DequeueOrThrow();
        }

        public Task<PreAuthOutcome> RespondToMfaChoiceAsync(string server, int port, string logonId, string choice, CancellationToken cancellationToken)
        {
            LastMfaChoiceLogonId = logonId;
            LastMfaChoice = choice;
            return DequeueOrThrow();
        }

        private Task<PreAuthOutcome> DequeueOrThrow()
        {
            if (_script.Count == 0)
                throw new InvalidOperationException("ScriptedPreAuth: script exhausted.");
            var next = _script.Dequeue();
            return next is Exception ex
                ? Task.FromException<PreAuthOutcome>(ex)
                : Task.FromResult((PreAuthOutcome)next);
        }
    }

    /// <summary>
    /// Scripted IOtpPromptService fake. Each PromptAsync call returns the next pre-queued code
    /// (or null if the queue is empty — that's the user-cancel signal in the contract).
    /// </summary>
    private sealed class ScriptedOtpPrompt : IOtpPromptService
    {
        private readonly Queue<string?> _codes;
        public int PromptCount { get; private set; }

        public ScriptedOtpPrompt(params string?[] codes)
        {
            _codes = new Queue<string?>(codes);
        }

        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken)
        {
            PromptCount++;
            var code = _codes.Count > 0 ? _codes.Dequeue() : null;
            return Task.FromResult(code);
        }
    }
}
