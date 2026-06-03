using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class StormshieldTunnelProviderTests
{
    private static StormshieldTunnelProvider NewProvider(IOtpPromptService? otp = null) =>
        new(otp ?? new NullOtpPromptService(),
            NullLogger<StormshieldTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

    [Fact]
    public void Kind_IsStormshield()
    {
        Assert.Equal(TunnelKind.Stormshield, NewProvider().Kind);
    }

    [Fact]
    public async Task EstablishAsync_RejectsEmptySecretBlob()
    {
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Stormshield };
        await Assert.ThrowsAnyAsync<Exception>(() =>
            NewProvider().EstablishAsync(cfg, Array.Empty<byte>(), CancellationToken.None));
    }

    [Fact]
    public async Task EstablishAsync_RejectsSingleSignOn_AsNotSupported()
    {
        // SSO is browser/OIDC-mediated and can't be a silent POST — the provider must fail with an
        // actionable message rather than attempt a credential-less password auth.
        var settings = new StormshieldSettings
        {
            Server = "rpv.example.com",
            Mode = StormshieldConnectionMode.Automatic,
            UseSingleSignOn = true,
        };
        var blob = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(settings);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Stormshield };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider().EstablishAsync(cfg, blob, CancellationToken.None));
        Assert.Contains("single sign-on", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EstablishAsync_RejectsKindMismatchedBlob_EmptyServer()
    {
        // A blob from another kind deserializes into StormshieldSettings with empty fields. In
        // Automatic mode the empty-Server pre-flight catches it before any network IO.
        var blob = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new StormshieldSettings());
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Stormshield };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider().EstablishAsync(cfg, blob, CancellationToken.None));
        Assert.Contains("Server", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EstablishAsync_ImportMode_RejectsEmptyProfile()
    {
        var settings = new StormshieldSettings
        {
            Server = "rpv.example.com",
            Mode = StormshieldConnectionMode.Import,
            ProfileOvpn = "",
        };
        var blob = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(settings);
        var cfg = new TunnelConfig { Id = Guid.NewGuid(), Name = "x", Kind = TunnelKind.Stormshield };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider().EstablishAsync(cfg, blob, CancellationToken.None));
        Assert.Contains("profile", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ----- RunAuthLoopAsync state machine -----

    private static StormshieldSettings ValidSettings(bool useOtp = false) => new()
    {
        Server = "rpv.example.com",
        Port = 443,
        Username = "alice",
        Password = "stored-password",
        Mode = StormshieldConnectionMode.Automatic,
        UseOtp = useOtp,
        AppToken = "sslclient",
    };

    [Fact]
    public async Task RunAuthLoop_NoOtp_SucceedsWithoutPrompting()
    {
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt(/* never called */);

        await StormshieldTunnelProvider.RunAuthLoopAsync(
            portal, otp, NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None);

        Assert.Equal(0, otp.PromptCount);
        Assert.Equal(1, portal.AuthCalls);
        Assert.Null(portal.LastOtp);
    }

    [Fact]
    public async Task RunAuthLoop_UseOtp_PromptsUpFrontAndSendsCode()
    {
        // "Use an OTP" is checked → the code is collected before the first POST and sent with it.
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("123456");

        await StormshieldTunnelProvider.RunAuthLoopAsync(
            portal, otp, NullLogger.Instance, "cfg", ValidSettings(useOtp: true), CancellationToken.None);

        Assert.Equal(1, otp.PromptCount);
        Assert.Equal(1, portal.AuthCalls);
        Assert.Equal("123456", portal.LastOtp);
    }

    [Fact]
    public async Task RunAuthLoop_ServerDemandsOtp_PromptsAndRetries()
    {
        // UseOtp not set, but the firewall returns NEED_TOTP_AUTH → prompt, then re-POST with code.
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.NeedOtp());
        portal.Queue(new StormshieldAuthOutcome.Ok());
        var otp = new ScriptedOtpPrompt("654321");

        await StormshieldTunnelProvider.RunAuthLoopAsync(
            portal, otp, NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None);

        Assert.Equal(1, otp.PromptCount);
        Assert.Equal(2, portal.AuthCalls);
        Assert.Equal("654321", portal.LastOtp);
    }

    [Fact]
    public async Task RunAuthLoop_RepeatedNeedOtp_ExceedsCap()
    {
        var portal = new ScriptedPortal();
        for (var i = 0; i < 10; i++) portal.Queue(new StormshieldAuthOutcome.NeedOtp());
        var otp = new ScriptedOtpPrompt("1", "2", "3", "4", "5");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, otp, NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("exceeded", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuthLoop_UserCancelsOtp_ThrowsInvalidOperation()
    {
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.NeedOtp());
        var otp = new ScriptedOtpPrompt(/* null = user dismissed */);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, otp, NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("cancelled", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuthLoop_EmptyOtpAfterTrim_Throws()
    {
        var otp = new ScriptedOtpPrompt("   ");
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                new ScriptedPortal(), otp, NullLogger.Instance, "cfg", ValidSettings(useOtp: true), CancellationToken.None));

        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAuthLoop_AuthFailed_Throws()
    {
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.Failure("bad credentials"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, new ScriptedOtpPrompt(), NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("bad credentials", ex.Message);
    }

    [Fact]
    public async Task RunAuthLoop_Bruteforce_SurfacesDelay()
    {
        var portal = new ScriptedPortal();
        portal.Queue(new StormshieldAuthOutcome.Bruteforce(45));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, new ScriptedOtpPrompt(), NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("45", ex.Message);
    }

    [Fact]
    public async Task RunAuthLoop_NetworkError_WrappedNotRawHttpRequestException()
    {
        var portal = new ScriptedPortal();
        portal.QueueThrow(new HttpRequestException("connection refused"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, new ScriptedOtpPrompt(), NullLogger.Instance, "cfg", ValidSettings(), CancellationToken.None));

        Assert.Contains("could not reach", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task RunAuthLoop_TokenCancellation_BubblesUnwrapped()
    {
        var portal = new ScriptedPortal();
        portal.QueueThrow(new TaskCanceledException("cancelled"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            StormshieldTunnelProvider.RunAuthLoopAsync(
                portal, new ScriptedOtpPrompt(), NullLogger.Instance, "cfg", ValidSettings(), cts.Token));
    }

    private sealed class NullOtpPromptService : IOtpPromptService
    {
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }

    /// <summary>
    /// Scripted <see cref="IStormshieldPortal"/> fake: each AuthenticateAsync dequeues the next
    /// outcome (or throws the next queued exception) and records the OTP it was handed.
    /// </summary>
    private sealed class ScriptedPortal : IStormshieldPortal
    {
        private readonly Queue<object> _script = new();
        public string? LastOtp { get; private set; }
        public int AuthCalls { get; private set; }

        public void Queue(StormshieldAuthOutcome outcome) => _script.Enqueue(outcome);
        public void QueueThrow(Exception ex) => _script.Enqueue(ex);

        public Task<StormshieldAuthOutcome> AuthenticateAsync(
            string username, string password, string? otp, string app, CancellationToken cancellationToken)
        {
            AuthCalls++;
            LastOtp = otp;
            if (_script.Count == 0)
                throw new InvalidOperationException("ScriptedPortal: script exhausted.");
            var next = _script.Dequeue();
            return next is Exception ex
                ? Task.FromException<StormshieldAuthOutcome>(ex)
                : Task.FromResult((StormshieldAuthOutcome)next);
        }

        public Task<string> DownloadProfileAsync(string app, CancellationToken cancellationToken) =>
            Task.FromResult("client\ndev tun\nremote fw 443\n");

        public void Dispose() { }
    }

    /// <summary>Scripted OTP prompt: returns the next queued code, or null (user dismiss) when empty.</summary>
    private sealed class ScriptedOtpPrompt : IOtpPromptService
    {
        private readonly Queue<string?> _codes;
        public int PromptCount { get; private set; }

        public ScriptedOtpPrompt(params string?[] codes) => _codes = new Queue<string?>(codes);

        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken)
        {
            PromptCount++;
            return Task.FromResult(_codes.Count > 0 ? _codes.Dequeue() : null);
        }
    }
}
