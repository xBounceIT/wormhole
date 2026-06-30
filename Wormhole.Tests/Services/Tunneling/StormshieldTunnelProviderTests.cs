using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Stormshield;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class StormshieldTunnelProviderTests
{
    private static StormshieldTunnelProvider NewProvider(
        IOtpPromptService? otp = null,
        FakeCredentialService? credentials = null,
        IWindowsTemporaryHostRouteService? routeService = null) =>
        new(otp ?? new NullOtpPromptService(),
            new ScriptedTlsTrustPrompt(),
            credentials ?? new FakeCredentialService(),
            new FakeStormshieldConfigCache(),
            routeService ?? new NoopWindowsTemporaryHostRouteService(),
            NullLogger<StormshieldTunnelProvider>.Instance,
            NullLoggerFactory.Instance);

    [Fact]
    public void Kind_IsStormshield()
    {
        Assert.Equal(TunnelKind.Stormshield, NewProvider().Kind);
    }

    [Fact]
    public void StormshieldSettings_OldJson_DefaultsNativeVpnBypassOff()
    {
        const string json = "{\"Server\":\"rpv.example.com\",\"Mode\":0,\"TrustServerCertificate\":true}";

        var settings = System.Text.Json.JsonSerializer.Deserialize<StormshieldSettings>(json)!;

        Assert.False(settings.BypassNativeVpnGatewayRoute);
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

    [Theory]
    [InlineData("client\ndev tun\nremote fw.example.com 443 tcp\n")]
    [InlineData("client\ndev tun\nremote fw.example.com 443\ncompress lz4\n")]
    [InlineData("client\ndev tun\nremote fw.example.com 443\ncomp-lzo yes\n")]
    [InlineData("client\ndev tun\nremote fw.example.com 443\ncomp-noadapt\n")]
    public void ApplyCompressionFramingPolicy_PreserveProfile_ReturnsProfileUnchanged(string profile)
    {
        var result = StormshieldTunnelProvider.ApplyCompressionFramingPolicy(
            profile,
            StormshieldOpenVpnCompressionFramingOverride.PreserveProfile);

        Assert.Equal(profile, result);
    }

    [Fact]
    public void ApplyCompressionFramingPolicy_ForceLegacyStub_AddsLegacyStub_WhenMissing()
    {
        const string profile = "client\ndev tun\nremote fw.example.com 443 tcp\n";

        var result = StormshieldTunnelProvider.ApplyCompressionFramingPolicy(
            profile,
            StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub);

        Assert.Equal(1, CountDirectiveLine(result, "comp-lzo no"));
    }

    [Theory]
    [InlineData("comp-lzo no")]
    [InlineData("compress lz4")]
    [InlineData("comp-lzo yes")]
    [InlineData("compress")]
    [InlineData("compress stub")]
    [InlineData("compress stub-v2")]
    public void ApplyCompressionFramingPolicy_ForceLegacyStub_DoesNotDuplicateExistingCompressionOrFraming(string compressionLine)
    {
        var profile = $"client\ndev tun\n{compressionLine}\n";

        var result = StormshieldTunnelProvider.ApplyCompressionFramingPolicy(
            profile,
            StormshieldOpenVpnCompressionFramingOverride.ForceLegacyStub);

        Assert.Equal(1, CountDirectiveLine(result, compressionLine));
        Assert.Equal(
            compressionLine.Equals("comp-lzo no", StringComparison.OrdinalIgnoreCase) ? 1 : 0,
            CountDirectiveLine(result, "comp-lzo no"));
    }

    // Shared valid Automatic-mode settings for the ResolveAutomaticCoreAsync tests below.
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

    // ----- ResolveAutomaticCoreAsync: OTP routing + config-cache gate -----
    //
    // The single-use OTP must be spent in exactly one place: the HTTPS download OR the OpenVPN data-plane
    // password, never both. Which one is chosen by whether a current cached profile lets us skip the download.

    [Fact]
    public async Task ResolveAutomatic_NoOtp_DownloadsFresh_UsesRealPassword_NoCache()
    {
        var portal = new ScriptedPortal();
        var cache = new FakeStormshieldConfigCache();
        var otp = new ScriptedOtpPrompt(/* never prompted */);
        var id = Guid.NewGuid();

        var (profile, password, optimistic) = await StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
            portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: false), CancellationToken.None);

        Assert.Equal(1, portal.DownloadV5Calls);
        Assert.Null(portal.LastDownloadV5Otp);            // no OTP on the download
        Assert.Equal("stored-password", password);        // real password on the data plane (today's behavior)
        Assert.Contains("remote fw 443", profile);
        Assert.False(optimistic);                         // fresh download, not an unconfirmed cache reuse
        Assert.Equal(0, otp.PromptCount);
        Assert.Equal(0, cache.WriteCalls);                // the no-OTP path never caches
        Assert.Equal(0, portal.ConfigHashCalls);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_CacheHit_ReusesProfile_AppendsOtpToDataPlane()
    {
        // Server hash matches the cached hash (case-insensitively) → reuse the cached profile, no download,
        // and route the one-time code to the OpenVPN data-plane password.
        var portal = new ScriptedPortal { ConfigHashResult = "abc123" };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        cache.Seed(id, configHash: "ABC123", profileOvpn: "client\ndev tun\nremote fw 443\n<ca>cached</ca>\n");
        var otp = new ScriptedOtpPrompt("999111");

        var (profile, password, optimistic) = await StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
            portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None);

        Assert.Equal(0, portal.DownloadV5Calls);          // cache hit → NO download
        Assert.Equal("stored-password999111", password);  // OTP appended to the data-plane password
        Assert.Contains("cached", profile);               // the cached profile was reused verbatim
        Assert.False(optimistic);                         // hash-CONFIRMED hit → cache kept on a later failure
        Assert.Equal(0, cache.WriteCalls);
        Assert.Equal(1, otp.PromptCount);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_CacheMiss_NoCache_Downloads_Caches_ThrowsReconnect()
    {
        var portal = new ScriptedPortal
        {
            ConfigHashResult = "NEWHASH",
            DownloadV5Result = "client\ndev tun\nremote fw 443\n<ca>fresh</ca>\n",
        };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        var otp = new ScriptedOtpPrompt("424242");

        await Assert.ThrowsAsync<StormshieldConfigRefreshedException>(() =>
            StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
                portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None));

        Assert.Equal(1, portal.DownloadV5Calls);
        Assert.Equal("424242", portal.LastDownloadV5Otp);   // OTP spent on the download
        Assert.Equal(1, cache.WriteCalls);                  // the fresh profile is cached for next time
        Assert.Equal("NEWHASH", cache.LastWritten!.ConfigHash);
        Assert.Contains("fresh", cache.LastWritten!.ProfileOvpn);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_HashDiffersFromCache_Downloads_ThrowsReconnect()
    {
        var portal = new ScriptedPortal { ConfigHashResult = "NEW" };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        cache.Seed(id, configHash: "OLD", profileOvpn: "client\ndev tun\nremote fw 443\n");
        var otp = new ScriptedOtpPrompt("123123");

        await Assert.ThrowsAsync<StormshieldConfigRefreshedException>(() =>
            StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
                portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None));

        Assert.Equal(1, portal.DownloadV5Calls);            // changed config → re-download
        Assert.Equal("NEW", cache.LastWritten!.ConfigHash);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_HashUnavailable_WithCache_OptimisticHit_NoDownload()
    {
        // Change-check unreachable/unsupported but we hold a cached profile → trust it (don't re-spend the
        // OTP). This is the deliberate improvement over the native client (which would re-download).
        var portal = new ScriptedPortal { ConfigHashResult = null };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        cache.Seed(id, configHash: "WHATEVER", profileOvpn: "client\ndev tun\nremote fw 443\n<ca>cached</ca>\n");
        var otp = new ScriptedOtpPrompt("707070");

        var (profile, password, optimistic) = await StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
            portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None);

        Assert.Equal(0, portal.DownloadV5Calls);
        Assert.Equal("stored-password707070", password);
        Assert.Contains("cached", profile);
        Assert.True(optimistic);                          // change-check unavailable → unconfirmed reuse
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_HashUnavailable_NoCache_Downloads_ThrowsReconnect()
    {
        var portal = new ScriptedPortal { ConfigHashResult = null };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        var otp = new ScriptedOtpPrompt("313131");

        await Assert.ThrowsAsync<StormshieldConfigRefreshedException>(() =>
            StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
                portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None));

        Assert.Equal(1, portal.DownloadV5Calls);
        Assert.Equal(1, cache.WriteCalls);
        Assert.Equal(string.Empty, cache.LastWritten!.ConfigHash);  // no hash was available to store
    }

    // ----- ResolveAutomaticWithTlsConsentAsync: TLS-trust recovery -----
    //
    // When the portal rejects the firewall's certificate, the user is asked once whether to trust the
    // server; accepting persists TrustServerCertificate=true and retries with verification off.

    /// <summary>The shape HttpClient + DownloadProfileV5WrappedAsync produce for a rejected certificate:
    /// InvalidOperationException → HttpRequestException → AuthenticationException.</summary>
    private static InvalidOperationException NewTlsValidationException() =>
        new(
            "Stormshield configuration download could not reach 'rpv.example.com:443': "
            + "The SSL connection could not be established, see inner exception.",
            new HttpRequestException(
                "The SSL connection could not be established, see inner exception.",
                new AuthenticationException(
                    "The remote certificate was rejected by the provided RemoteCertificateValidationCallback.")));

    private static StormshieldTlsFailure NewTlsFailureDetails() => new(
        SslPolicyErrors.RemoteCertificateChainErrors,
        Subject: "CN=SN710A00000000A",
        Issuer: "CN=SNS-WebServer-default-authority",
        Thumbprint: "ABCDEF0123456789",
        NotBefore: null,
        NotAfter: null,
        ChainStatus: "UntrustedRoot");

    /// <summary>Runs the consent wrapper around the production attempt (ResolveAutomaticCoreAsync)
    /// with test seams defaulted, mirroring how ResolveAutomaticAsync wires it.</summary>
    private static Task<(string Profile, string DataPlanePassword, bool OptimisticCacheHit)> RunTlsConsentAsync(
        Func<IStormshieldPortal> portalFactory,
        StormshieldSettings settings,
        ITlsTrustPromptService tlsPrompt,
        IOtpPromptService? otp = null,
        FakeStormshieldConfigCache? cache = null,
        Func<Task<bool>>? reloadTrust = null,
        Func<Task>? persistTrust = null)
    {
        var theCache = cache ?? new FakeStormshieldConfigCache();
        var theOtp = otp ?? new ScriptedOtpPrompt();
        var id = Guid.NewGuid();
        return StormshieldTunnelProvider.ResolveAutomaticWithTlsConsentAsync(
            portalFactory,
            portal => StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
                portal, theCache, theOtp, NullLogger.Instance, id, "cfg", settings, CancellationToken.None),
            tlsPrompt,
            reloadTrust ?? (() => Task.FromResult(false)),
            persistTrust ?? (() => Task.CompletedTask),
            NullLogger.Instance, "cfg", settings, CancellationToken.None);
    }

    [Fact]
    public async Task TlsConsent_Accepted_PersistsTrust_RetriesWithVerificationOff()
    {
        var trustAtCreate = new List<bool>();
        var failing = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
        var working = new ScriptedPortal { DownloadV5Result = "client\ndev tun\nremote fw 443\n<ca>trusted-retry</ca>\n" };
        var portals = new Queue<ScriptedPortal>(new[] { failing, working });
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: true);
        var settings = ValidSettings(useOtp: false);
        var persistCalls = 0;

        var (profile, password, _) = await RunTlsConsentAsync(
            () => { trustAtCreate.Add(settings.TrustServerCertificate); return portals.Dequeue(); },
            settings, tlsPrompt,
            persistTrust: () => { persistCalls++; return Task.CompletedTask; });

        Assert.Collection(trustAtCreate, Assert.False, Assert.True);  // retry portal built with verification off
        Assert.Equal(1, tlsPrompt.PromptCount);
        Assert.Equal(1, persistCalls);
        Assert.True(settings.TrustServerCertificate);
        Assert.Contains("trusted-retry", profile);
        Assert.Equal("stored-password", password);
        // The prompt names the tunnel and server, and shows the rejected certificate's identity
        // including the OS chain verdict.
        Assert.Contains("cfg", tlsPrompt.LastTitle);
        Assert.Contains("rpv.example.com:443", tlsPrompt.LastMessage);
        Assert.Contains("SNS-WebServer-default-authority", tlsPrompt.LastMessage);
        Assert.Contains("UntrustedRoot", tlsPrompt.LastMessage);
        Assert.Contains("Trust server certificate", tlsPrompt.LastMessage);
    }

    [Fact]
    public async Task TlsConsent_Declined_ThrowsActionable_NoPersist_NoRetry()
    {
        var created = 0;
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: false);
        var settings = ValidSettings();
        var persistCalls = 0;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunTlsConsentAsync(
                () =>
                {
                    created++;
                    return new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
                },
                settings, tlsPrompt,
                persistTrust: () => { persistCalls++; return Task.CompletedTask; }));

        Assert.Contains("chose not to trust", ex.Message);
        Assert.Equal(1, tlsPrompt.PromptCount);
        Assert.Equal(1, created);                        // no retry portal
        Assert.Equal(0, persistCalls);
        Assert.False(settings.TrustServerCertificate);
        Assert.NotNull(ex.InnerException);               // original TLS failure preserved for diagnostics
    }

    [Fact]
    public async Task TlsConsent_NotOffered_WhenCaIsPinned_FailsWithPinMessage()
    {
        // The user explicitly pinned a CA: a validation failure may mean interception, and accepting
        // a trust prompt would permanently bypass the pin (the portal constructor honors the trust
        // flag BEFORE CaPem). Never offer the prompt — fail hard with the pin-specific reason.
        var settings = ValidSettings();
        settings.CaPem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        var portal = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: true);
        var persistCalls = 0;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunTlsConsentAsync(() => portal, settings, tlsPrompt,
                persistTrust: () => { persistCalls++; return Task.CompletedTask; }));

        Assert.Contains("pinned", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, tlsPrompt.PromptCount);
        Assert.Equal(0, persistCalls);
        Assert.False(settings.TrustServerCertificate);
    }

    [Fact]
    public async Task TlsConsent_SkipsPrompt_WhenConcurrentConnectAlreadyPersistedTrust()
    {
        // Two tabs sharing the tunnel can both fail TLS before either prompt is answered. The second
        // one must re-read the persisted settings and, finding trust already granted, retry without
        // asking the user the same question twice in a row.
        var failing = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
        var working = new ScriptedPortal { DownloadV5Result = "client\ndev tun\nremote fw 443\n<ca>ok</ca>\n" };
        var portals = new Queue<ScriptedPortal>(new[] { failing, working });
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: false);  // would decline if it were asked
        var settings = ValidSettings();
        var persistCalls = 0;

        var (profile, _, _) = await RunTlsConsentAsync(
            () => portals.Dequeue(), settings, tlsPrompt,
            reloadTrust: () => Task.FromResult(true),
            persistTrust: () => { persistCalls++; return Task.CompletedTask; });

        Assert.Contains("ok", profile);
        Assert.Equal(0, tlsPrompt.PromptCount);          // never asked — trust was already granted
        Assert.Equal(0, persistCalls);                   // already persisted by the other connect
        Assert.True(settings.TrustServerCertificate);
    }

    [Fact]
    public async Task TlsConsent_NotPrompted_WhenFailureIsNotCertificateValidation()
    {
        // A firewall-side error (no AuthenticationException in the chain, nothing recorded by the
        // validation callback) must propagate untouched — trusting the server wouldn't fix it.
        var portal = new ScriptedPortal
        {
            DownloadV5Exception = new InvalidOperationException(
                "Stormshield configuration download failed: the firewall rejected the configuration request."),
        };
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunTlsConsentAsync(() => portal, ValidSettings(), tlsPrompt));

        Assert.Equal(0, tlsPrompt.PromptCount);
    }

    [Fact]
    public async Task TlsConsent_NotPrompted_WhenNoValidationRejectionRecorded()
    {
        // A protocol-level TLS failure (alert/handshake) raises AuthenticationException WITHOUT ever
        // invoking the validation callback. Trusting the server would not help, so no prompt.
        var portal = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = null };
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunTlsConsentAsync(() => portal, ValidSettings(), tlsPrompt));

        Assert.Equal(0, tlsPrompt.PromptCount);
    }

    [Fact]
    public async Task TlsConsent_NotPrompted_WhenTrustAlreadyEnabled()
    {
        // TrustServerCertificate is already on — a TLS failure here is something else entirely
        // (should not even validate); never re-ask a question the user already answered.
        var portal = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
        var tlsPrompt = new ScriptedTlsTrustPrompt(accept: true);
        var settings = ValidSettings();
        settings.TrustServerCertificate = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunTlsConsentAsync(() => portal, settings, tlsPrompt));

        Assert.Equal(0, tlsPrompt.PromptCount);
    }

    [Fact]
    public async Task TlsConsent_PersistFailure_DoesNotBlockTheApprovedConnect()
    {
        // The DPAPI write failing must not turn the user's explicit "trust and connect" into an
        // error — connect with trust for this attempt; the prompt simply returns next time.
        var failing = new ScriptedPortal { DownloadV5Exception = NewTlsValidationException(), LastTlsFailure = NewTlsFailureDetails() };
        var working = new ScriptedPortal { DownloadV5Result = "client\ndev tun\nremote fw 443\n<ca>ok</ca>\n" };
        var portals = new Queue<ScriptedPortal>(new[] { failing, working });

        var (profile, _, _) = await RunTlsConsentAsync(
            () => portals.Dequeue(), ValidSettings(), new ScriptedTlsTrustPrompt(accept: true),
            persistTrust: () => throw new InvalidOperationException("simulated secret write failure"));

        Assert.Contains("ok", profile);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_TlsFailureOnChangeCheck_NoCache_FailsBeforePromptingCode()
    {
        // The hash GET's handshake already proved the certificate is rejected; the core must not
        // collect a one-time code for a download that is doomed to the identical failure.
        var portal = new ScriptedPortal { ConfigHashResult = null, LastTlsFailure = NewTlsFailureDetails() };
        var otp = new ScriptedOtpPrompt("111111");

        await Assert.ThrowsAsync<StormshieldTlsPreflightException>(() =>
            StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
                portal, new FakeStormshieldConfigCache(), otp, NullLogger.Instance, Guid.NewGuid(), "cfg",
                ValidSettings(useOtp: true), CancellationToken.None));

        Assert.Equal(0, otp.PromptCount);
        Assert.Equal(0, portal.DownloadV5Calls);
    }

    [Fact]
    public async Task ResolveAutomatic_Otp_TlsFailureOnChangeCheck_WithCache_StillTakesOptimisticHit()
    {
        // A broken portal TLS handshake must not block the optimistic cache path: the cached profile
        // carries its own CA and the OpenVPN data plane never touches the portal again.
        var portal = new ScriptedPortal { ConfigHashResult = null, LastTlsFailure = NewTlsFailureDetails() };
        var cache = new FakeStormshieldConfigCache();
        var id = Guid.NewGuid();
        cache.Seed(id, configHash: "ANY", profileOvpn: "client\ndev tun\nremote fw 443\n<ca>cached</ca>\n");
        var otp = new ScriptedOtpPrompt("707070");

        var (profile, password, optimistic) = await StormshieldTunnelProvider.ResolveAutomaticCoreAsync(
            portal, cache, otp, NullLogger.Instance, id, "cfg", ValidSettings(useOtp: true), CancellationToken.None);

        Assert.Contains("cached", profile);
        Assert.Equal("stored-password707070", password);
        Assert.True(optimistic);
    }

    [Fact]
    public async Task TlsConsent_WithOtp_TrustPromptComesBeforeAnyCodePrompt()
    {
        // OTP + no cache + rejected certificate: the change-check preflight fails the first attempt
        // BEFORE any code prompt, the trust prompt runs, and the retry collects exactly one code for
        // the download (which then stops with the documented "reconnect with a new code" notice).
        var failing = new ScriptedPortal { ConfigHashResult = null, LastTlsFailure = NewTlsFailureDetails() };
        var working = new ScriptedPortal { ConfigHashResult = null };
        var portals = new Queue<ScriptedPortal>(new[] { failing, working });
        var otp = new ScriptedOtpPrompt("111111", "222222");
        var cache = new FakeStormshieldConfigCache();

        await Assert.ThrowsAsync<StormshieldConfigRefreshedException>(() =>
            RunTlsConsentAsync(() => portals.Dequeue(), ValidSettings(useOtp: true),
                new ScriptedTlsTrustPrompt(accept: true), otp: otp, cache: cache));

        Assert.Equal(0, failing.DownloadV5Calls);        // preflight aborted before the doomed download
        Assert.Equal(1, otp.PromptCount);                // exactly one code collected, on the trusted retry
        Assert.Equal("111111", working.LastDownloadV5Otp);
        Assert.Equal(1, cache.WriteCalls);               // fresh profile cached by the successful retry
    }

    // ----- PersistTrustServerCertificateAsync: consent-scope guard on the read-modify-write -----
    //
    // The user's consent was "skip TLS verification for {server}:{port}". If an editor save changed
    // the blob while the prompt was open, the persist must not extend that consent to a different
    // server or silently outrank a freshly pinned CA.

    [Fact]
    public async Task PersistTrust_FlipsOnlyTheFlag_PreservingConcurrentEdits()
    {
        // An editor save (new password, same server) landed while the prompt was open: keep it.
        var id = Guid.NewGuid();
        var stored = ValidSettings();
        stored.Password = "edited-password";
        var credentials = new FakeCredentialService();
        credentials.TunnelConfigs[id] = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(stored);

        await NewProvider(credentials: credentials).PersistTrustServerCertificateAsync(id, ValidSettings());

        var written = System.Text.Json.JsonSerializer.Deserialize<StormshieldSettings>(credentials.TunnelConfigs[id])!;
        Assert.True(written.TrustServerCertificate);
        Assert.Equal("edited-password", written.Password);
    }

    [Fact]
    public async Task PersistTrust_Refuses_WhenStoredSettingsPointAtDifferentServer()
    {
        var id = Guid.NewGuid();
        var stored = ValidSettings();
        stored.Server = "other.example.com";
        var credentials = new FakeCredentialService();
        credentials.TunnelConfigs[id] = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(stored);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider(credentials: credentials).PersistTrustServerCertificateAsync(id, ValidSettings()));

        var written = System.Text.Json.JsonSerializer.Deserialize<StormshieldSettings>(credentials.TunnelConfigs[id])!;
        Assert.False(written.TrustServerCertificate);    // blob left untouched
    }

    [Fact]
    public async Task PersistTrust_Refuses_WhenStoredSettingsNowPinACa()
    {
        // The user pasted a CA while the prompt was open; the trust flag would silently outrank it
        // (the portal constructor honors TrustServerCertificate before CaPem).
        var id = Guid.NewGuid();
        var stored = ValidSettings();
        stored.CaPem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        var credentials = new FakeCredentialService();
        credentials.TunnelConfigs[id] = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(stored);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            NewProvider(credentials: credentials).PersistTrustServerCertificateAsync(id, ValidSettings()));

        var written = System.Text.Json.JsonSerializer.Deserialize<StormshieldSettings>(credentials.TunnelConfigs[id])!;
        Assert.False(written.TrustServerCertificate);    // blob left untouched
    }

    [Fact]
    public async Task PersistTrust_FallsBackToSnapshot_WhenBlobMissing()
    {
        var id = Guid.NewGuid();
        var credentials = new FakeCredentialService();

        await NewProvider(credentials: credentials).PersistTrustServerCertificateAsync(id, ValidSettings());

        var written = System.Text.Json.JsonSerializer.Deserialize<StormshieldSettings>(credentials.TunnelConfigs[id])!;
        Assert.True(written.TrustServerCertificate);
        Assert.Equal("rpv.example.com", written.Server);
    }

    [Fact]
    public void IsTlsAuthenticationFailure_WalksTheInnerChain()
    {
        Assert.True(StormshieldTunnelProvider.IsTlsAuthenticationFailure(NewTlsValidationException()));
        Assert.True(StormshieldTunnelProvider.IsTlsAuthenticationFailure(new AuthenticationException("boom")));
        Assert.False(StormshieldTunnelProvider.IsTlsAuthenticationFailure(
            new InvalidOperationException("x", new HttpRequestException("connection refused"))));
    }

    [Fact]
    public void NativeVpnConflictEnrichment_PortalTimeout_BuildsActionableMessage()
    {
        var lease = NativeVpnConflictLease();
        var inner = new InvalidOperationException(
            "Stormshield configuration download timed out talking to 'rpv.example.com:443'.",
            new TaskCanceledException("timeout"));

        Assert.True(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(new[] { lease }, inner));
        var enriched = StormshieldTunnelProvider.BuildNativeVpnConflictException(
            "cfg", new StormshieldSettings(), new[] { lease }, inner);

        Assert.Same(inner, enriched.InnerException);
        Assert.Contains("native VPN", enriched.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Bypass active native VPN route", enriched.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rpv.example.com", enriched.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NativeVpnConflictEnrichment_TlsAuthenticationFailure_IsNotRouteSensitive()
    {
        var lease = NativeVpnConflictLease();

        Assert.False(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(
            new[] { lease }, NewTlsValidationException()));
    }

    [Fact]
    public void NativeVpnConflictEnrichment_OpenVpnSidecarTimeout_IsRouteSensitive()
    {
        var lease = NativeVpnConflictLease();
        var inner = new InvalidOperationException(
            "OpenVPN sidecar did not produce a READY line within the startup timeout.");

        Assert.True(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(new[] { lease }, inner));
        Assert.False(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(
            Array.Empty<WindowsHostRouteLease>(), inner));
    }

    [Fact]
    public void NativeVpnConflictEnrichment_OpenVpnTransportIoFailure_IsRouteSensitive()
    {
        var lease = NativeVpnConflictLease();
        var inner = new IOException("OpenVPN sidecar exited with code 1. Sidecar reported: CONNECTION_TIMEOUT");

        Assert.True(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(new[] { lease }, inner));
    }

    [Fact]
    public void NativeVpnConflictEnrichment_OpenVpnSidecarSetupIoFailure_IsNotRouteSensitive()
    {
        var lease = NativeVpnConflictLease();
        var inner = new FileNotFoundException("OpenVPN sidecar binary not found at 'wormhole-ovpnproxy.exe'.");

        Assert.False(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(new[] { lease }, inner));
    }

    [Fact]
    public void NativeVpnConflictEnrichment_OpenVpnSidecarTimeoutAfterBypassInstall_IsNotRouteSensitive()
    {
        var lease = NativeVpnConflictLease(bypassRouteInstalled: true);
        var inner = new InvalidOperationException(
            "OpenVPN sidecar did not produce a READY line within the startup timeout.");

        Assert.False(StormshieldTunnelProvider.ShouldEnrichNativeVpnConflict(new[] { lease }, inner));
    }

    [Fact]
    public async Task PrepareOpenVpnRemoteRoutesAsync_SkipsUnresolvedRemoteAndContinues()
    {
        var routeService = new ScriptedWindowsTemporaryHostRouteService();
        routeService.UnresolvedHosts.Add("stale.example.com");
        var provider = NewProvider(routeService: routeService);
        var hosts = new List<string> { "stale.example.com", "healthy.example.com" };

        var leases = await provider.PrepareOpenVpnRemoteRoutesAsync(
            "cfg",
            hosts,
            enableBypass: true,
            CancellationToken.None);

        Assert.Equal(hosts, routeService.Hosts);
        Assert.Single(leases);
    }

    [Fact]
    public async Task PrepareOpenVpnRemoteRoutesAsync_PropagatesNonResolutionFailures()
    {
        var routeService = new ScriptedWindowsTemporaryHostRouteService
        {
            Failure = new InvalidOperationException("The Stormshield native-VPN route bypass requires Wormhole to be running as Administrator."),
        };
        var provider = NewProvider(routeService: routeService);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.PrepareOpenVpnRemoteRoutesAsync(
                "cfg",
                new List<string> { "healthy.example.com" },
                enableBypass: true,
                CancellationToken.None));

        Assert.Contains("Administrator", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PrepareOpenVpnRemoteRoutesAsync_DisposesPreparedRoutesWhenLaterRemoteFails()
    {
        var routeService = new ScriptedWindowsTemporaryHostRouteService();
        routeService.FailuresByHost["blocked.example.com"] = new InvalidOperationException(
            "Native-VPN route bypass cannot override an existing host route owned by a VPN-like adapter.");
        var provider = NewProvider(routeService: routeService);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.PrepareOpenVpnRemoteRoutesAsync(
                "cfg",
                new List<string> { "healthy.example.com", "blocked.example.com" },
                enableBypass: true,
                CancellationToken.None));

        Assert.Contains("existing host route", ex.Message, StringComparison.OrdinalIgnoreCase);
        var release = Assert.Single(routeService.RouteReleases);
        Assert.True(release.IsDisposed);
    }

    [Fact]
    public void ExtractOpenVpnRemotes_IncludesTopLevelAndConnectionBlocks_SkipsInlineDataBlocks()
    {
        const string profile =
            "client\n"
            + "remote top.example.com 1194 udp\n"
            + "<connection>\n"
            + "remote rpv.example.com 443 tcp\n"
            + "</connection>\n"
            + "<connection>\n"
            + "remote rpv.example.com 8443 udp\n"
            + "</connection>\n"
            + "<ca>\n"
            + "remote should-not-log 1194 udp\n"
            + "</ca>\n"
            + "<key>\n"
            + "remote key-material.example 443 tcp\n"
            + "</key>\n";

        var remotes = StormshieldTunnelProvider.ExtractOpenVpnRemotes(profile);

        Assert.Collection(
            remotes,
            remote =>
            {
                Assert.Equal("top.example.com", remote.Host);
                Assert.Equal("1194", remote.Port);
                Assert.Equal("udp", remote.Protocol);
            },
            remote =>
            {
                Assert.Equal("rpv.example.com", remote.Host);
                Assert.Equal("443", remote.Port);
                Assert.Equal("tcp", remote.Protocol);
            },
            remote =>
            {
                Assert.Equal("rpv.example.com", remote.Host);
                Assert.Equal("8443", remote.Port);
                Assert.Equal("udp", remote.Protocol);
            });
        Assert.Equal(
            "top.example.com:1194/udp, rpv.example.com:443/tcp, rpv.example.com:8443/udp",
            StormshieldTunnelProvider.SummarizeOpenVpnRemotes(profile));
    }

    private static WindowsHostRouteLease NativeVpnConflictLease(
        string message = "Windows currently routes rpv.example.com (203.0.113.10) through VPN-like adapter 'Stormshield VPN' (interface 7).",
        bool bypassRouteInstalled = false) =>
        new(
            new[]
            {
                new WindowsHostRouteDiagnostic(
                    "rpv.example.com",
                    System.Net.IPAddress.Parse("203.0.113.10"),
                    NativeVpnConflict: true,
                    BypassRouteInstalled: bypassRouteInstalled,
                    Message: message),
            },
            Array.Empty<IAsyncDisposable>());

    private sealed class ScriptedWindowsTemporaryHostRouteService : IWindowsTemporaryHostRouteService
    {
        public List<string> Hosts { get; } = new();
        public HashSet<string> UnresolvedHosts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Exception> FailuresByHost { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<TrackingAsyncDisposable> RouteReleases { get; } = new();
        public Exception? Failure { get; set; }

        public Task<WindowsHostRouteLease> PrepareGatewayBypassAsync(
            string configName,
            IReadOnlyCollection<string> hosts,
            bool enableBypass,
            CancellationToken cancellationToken)
        {
            var host = Assert.Single(hosts);
            Hosts.Add(host);

            if (Failure is not null) throw Failure;
            if (FailuresByHost.TryGetValue(host, out var hostFailure)) throw hostFailure;
            if (UnresolvedHosts.Contains(host))
            {
                throw new InvalidOperationException(
                    $"Native-VPN route bypass is enabled, but Wormhole could not resolve Stormshield gateway '{host}' to an IPv4 address before installing a host route.");
            }

            var release = new TrackingAsyncDisposable();
            RouteReleases.Add(release);
            return Task.FromResult(new WindowsHostRouteLease(
                Array.Empty<WindowsHostRouteDiagnostic>(),
                new IAsyncDisposable[] { release }));
        }
    }

    private sealed class TrackingAsyncDisposable : IAsyncDisposable
    {
        public bool IsDisposed { get; private set; }

        public ValueTask DisposeAsync()
        {
            IsDisposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class NoopWindowsTemporaryHostRouteService : IWindowsTemporaryHostRouteService
    {
        public Task<WindowsHostRouteLease> PrepareGatewayBypassAsync(
            string configName,
            IReadOnlyCollection<string> hosts,
            bool enableBypass,
            CancellationToken cancellationToken) =>
            Task.FromResult(new WindowsHostRouteLease(
                Array.Empty<WindowsHostRouteDiagnostic>(),
                Array.Empty<IAsyncDisposable>()));
    }

    private sealed class NullOtpPromptService : IOtpPromptService
    {
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }

    private static int CountDirectiveLine(string text, string line) =>
        text.Split('\n').Count(l => l.Trim().Equals(line, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Scripted <see cref="IStormshieldPortal"/> fake for the ResolveAutomaticCoreAsync tests: returns a
    /// canned config-change hash and a canned downloaded profile, and records what it was asked for so the
    /// tests can assert whether a download happened (and with which OTP) vs. a cache hit.
    /// </summary>
    private sealed class ScriptedPortal : IStormshieldPortal
    {
        public string? ConfigHashResult { get; set; }
        public int ConfigHashCalls { get; private set; }
        public string DownloadV5Result { get; set; } = "client\ndev tun\nremote fw 443\n<ca>x</ca>\n";
        public int DownloadV5Calls { get; private set; }
        public string? LastDownloadV5Otp { get; private set; }
        /// <summary>Thrown by every download when set — drives the TLS-consent recovery tests.</summary>
        public Exception? DownloadV5Exception { get; set; }
        public StormshieldTlsFailure? LastTlsFailure { get; set; }

        public Task<string> DownloadProfileV5Async(
            string username, string password, string? otp, CancellationToken cancellationToken)
        {
            DownloadV5Calls++;
            LastDownloadV5Otp = otp;
            if (DownloadV5Exception is not null) throw DownloadV5Exception;
            return Task.FromResult(DownloadV5Result);
        }

        public Task<string?> GetConfigHashAsync(CancellationToken cancellationToken)
        {
            ConfigHashCalls++;
            return Task.FromResult(ConfigHashResult);
        }

        public void Dispose() { }
    }

    /// <summary>Scripted TLS-trust prompt: answers every confirmation with the configured choice and
    /// records what it was asked, so tests can assert on the prompt content (or that none was shown).</summary>
    private sealed class ScriptedTlsTrustPrompt : ITlsTrustPromptService
    {
        private readonly bool _accept;
        public int PromptCount { get; private set; }
        public string? LastTitle { get; private set; }
        public string? LastMessage { get; private set; }

        public ScriptedTlsTrustPrompt(bool accept = false) => _accept = accept;

        public Task<bool> ConfirmTrustAsync(string title, string message, CancellationToken cancellationToken)
        {
            PromptCount++;
            LastTitle = title;
            LastMessage = message;
            return Task.FromResult(_accept);
        }
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
