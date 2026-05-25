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
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

        Assert.Equal(TunnelKind.Watchguard, provider.Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var provider = new WatchguardTunnelProvider(
            new NullOtpPromptService(),
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
            NullLogger<WatchguardTunnelProvider>.Instance,
            NullLoggerFactory.Instance);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Watchguard };
        var emptyJson = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new WatchguardSettings());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.EstablishAsync(cfg, emptyJson, CancellationToken.None));
        Assert.Contains("Server", ex.Message, StringComparison.OrdinalIgnoreCase);
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

        public void Queue(PreAuthOutcome outcome) => _script.Enqueue(outcome);
        public void QueueThrow(Exception ex) => _script.Enqueue(ex);

        public Task<PreAuthOutcome> LogonAsync(string server, int port, string username, string password, string domain, CancellationToken cancellationToken)
            => DequeueOrThrow();

        public Task<PreAuthOutcome> RespondToChallengeAsync(string server, int port, string logonId, string otpCode, CancellationToken cancellationToken)
        {
            LastChallengeLogonId = logonId;
            LastOtp = otpCode;
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
