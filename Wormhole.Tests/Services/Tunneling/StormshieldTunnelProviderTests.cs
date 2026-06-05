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
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class StormshieldTunnelProviderTests
{
    private static StormshieldTunnelProvider NewProvider(IOtpPromptService? otp = null) =>
        new(otp ?? new NullOtpPromptService(),
            new FakeStormshieldConfigCache(),
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

    [Fact]
    public void SummarizeOpenVpnRemotes_IncludesConnectionBlocks_SkipsInlineDataBlocks()
    {
        const string profile =
            "client\n"
            + "<connection>\n"
            + "remote rpv.example.com 443 tcp\n"
            + "</connection>\n"
            + "<connection>\n"
            + "remote rpv.example.com 8443 udp\n"
            + "</connection>\n"
            + "<ca>\n"
            + "remote should-not-log 1194 udp\n"
            + "</ca>\n";

        var summary = StormshieldTunnelProvider.SummarizeOpenVpnRemotes(profile);

        Assert.Equal("rpv.example.com:443/tcp, rpv.example.com:8443/udp", summary);
    }

    private sealed class NullOtpPromptService : IOtpPromptService
    {
        public Task<string?> PromptAsync(string title, string subtitle, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }

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

        public Task<string> DownloadProfileV5Async(
            string username, string password, string? otp, CancellationToken cancellationToken)
        {
            DownloadV5Calls++;
            LastDownloadV5Otp = otp;
            return Task.FromResult(DownloadV5Result);
        }

        public Task<string?> GetConfigHashAsync(CancellationToken cancellationToken)
        {
            ConfigHashCalls++;
            return Task.FromResult(ConfigHashResult);
        }

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
