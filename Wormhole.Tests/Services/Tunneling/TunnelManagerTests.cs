using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class TunnelManagerTests
{
    [Fact]
    public async Task Establish_ReturnsNull_WhenTunnelDisabled()
    {
        var mgr = BuildManager(out _, out _);
        var profile = Profile(tunnelEnabled: false, tunnelConfigId: null);

        var result = await mgr.EstablishAsync(profile, CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task Establish_Throws_WhenEnabledWithNoConfigId()
    {
        var mgr = BuildManager(out _, out _);
        var profile = Profile(tunnelEnabled: true, tunnelConfigId: null);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            mgr.EstablishAsync(profile, CancellationToken.None));
    }

    [Fact]
    public async Task Establish_Throws_WhenConfigMissing()
    {
        var mgr = BuildManager(out _, out var creds);
        creds.TunnelConfigs[Guid.NewGuid()] = new byte[] { 1 };
        var profile = Profile(tunnelEnabled: true, tunnelConfigId: Guid.NewGuid());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            mgr.EstablishAsync(profile, CancellationToken.None));
    }

    [Fact]
    public async Task Establish_Throws_WhenProviderMissing()
    {
        var mgr = BuildManager(out var repo, out var creds, providers: Array.Empty<ITunnelProvider>());
        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "wg", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[configId] = new byte[] { 1 };
        var profile = Profile(tunnelEnabled: true, tunnelConfigId: configId);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            mgr.EstablishAsync(profile, CancellationToken.None));
    }

    [Fact]
    public async Task Establish_DispatchesToProvider_AndCallerDisposes()
    {
        var provider = new FakeProvider();
        var mgr = BuildManager(out var repo, out var creds, providers: new ITunnelProvider[] { provider });

        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "wg", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };

        var profile = Profile(tunnelEnabled: true, tunnelConfigId: configId);

        var instance = await mgr.EstablishAsync(profile, CancellationToken.None);

        Assert.NotNull(instance);
        Assert.Equal(1, provider.EstablishCount);
        Assert.Equal(new byte[] { 1, 2, 3 }, provider.LastSecret);

        await instance!.DisposeAsync();
        Assert.Equal(1, provider.LastInstance!.DisposeCount);
    }

    [Fact]
    public async Task EstablishConfig_DispatchesToProvider_AndCallerDisposes()
    {
        var provider = new FakeProvider();
        var mgr = BuildManager(out var repo, out var creds, providers: new ITunnelProvider[] { provider });

        var configId = Guid.NewGuid();
        var config = new TunnelConfig { Id = configId, Name = "wg", Kind = TunnelKind.WireGuard };
        repo.Configs[configId] = config;
        creds.TunnelConfigs[configId] = new byte[] { 4, 5, 6 };

        var instance = await mgr.EstablishConfigAsync(config, CancellationToken.None);

        Assert.Equal(1, provider.EstablishCount);
        Assert.Equal(new byte[] { 4, 5, 6 }, provider.LastSecret);

        await instance.DisposeAsync();
        Assert.Equal(1, provider.LastInstance!.DisposeCount);
    }

    [Fact]
    public async Task Establish_DispatchesByKind_OpenVpn()
    {
        // With both providers registered, a config of Kind = OpenVpn must route to the OpenVPN
        // provider and not the WireGuard one. This regression-locks the per-Kind dispatch in
        // TunnelManager.EstablishAsync.
        var wg = new FakeProvider(TunnelKind.WireGuard);
        var ovpn = new FakeProvider(TunnelKind.OpenVpn);
        var mgr = BuildManager(out var repo, out var creds, providers: new ITunnelProvider[] { wg, ovpn });

        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp-ovpn", Kind = TunnelKind.OpenVpn };
        creds.TunnelConfigs[configId] = new byte[] { 9, 9, 9 };

        var profile = Profile(tunnelEnabled: true, tunnelConfigId: configId);

        var instance = await mgr.EstablishAsync(profile, CancellationToken.None);

        Assert.NotNull(instance);
        Assert.Equal(0, wg.EstablishCount);
        Assert.Equal(1, ovpn.EstablishCount);
        Assert.Equal(new byte[] { 9, 9, 9 }, ovpn.LastSecret);

        await instance!.DisposeAsync();
    }

    [Fact]
    public async Task Establish_DispatchesByKind_Watchguard()
    {
        // Same dispatch lock for Watchguard: a Watchguard-kind config must reach the Watchguard
        // provider, not the OpenVPN one (even though Watchguard reuses the OpenVPN sidecar
        // under the hood — the dispatch is by Kind, not by transport).
        var ovpn = new FakeProvider(TunnelKind.OpenVpn);
        var wgg = new FakeProvider(TunnelKind.Watchguard);
        var mgr = BuildManager(out var repo, out var creds, providers: new ITunnelProvider[] { ovpn, wgg });

        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp-wgg", Kind = TunnelKind.Watchguard };
        creds.TunnelConfigs[configId] = new byte[] { 7, 7, 7 };

        var profile = Profile(tunnelEnabled: true, tunnelConfigId: configId);

        var instance = await mgr.EstablishAsync(profile, CancellationToken.None);

        Assert.NotNull(instance);
        Assert.Equal(0, ovpn.EstablishCount);
        Assert.Equal(1, wgg.EstablishCount);
        Assert.Equal(new byte[] { 7, 7, 7 }, wgg.LastSecret);

        await instance!.DisposeAsync();
    }

    [Fact]
    public async Task Establish_ReportsPreparing_ThenForwardsProviderProgress()
    {
        var provider = new FakeProvider();
        var mgr = BuildManager(out var repo, out var creds, providers: new ITunnelProvider[] { provider });

        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "wg", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[configId] = new byte[] { 1 };
        var profile = Profile(tunnelEnabled: true, tunnelConfigId: configId);

        var reports = new List<TunnelPhase>();
        var progress = new RecordingProgress(p => reports.Add(p.Phase));

        var instance = await mgr.EstablishAsync(profile, CancellationToken.None, progress);
        await instance!.DisposeAsync();

        // Manager reports Preparing up front, then the provider's own report flows through the
        // same IProgress in order.
        Assert.Equal(new[] { TunnelPhase.Preparing, TunnelPhase.StartingTunnel }, reports);
    }

    [Fact]
    public async Task Establish_TunnelDisabled_ReportsNothing()
    {
        var mgr = BuildManager(out _, out _);
        var profile = Profile(tunnelEnabled: false, tunnelConfigId: null);

        var reports = new List<TunnelPhase>();
        var result = await mgr.EstablishAsync(profile, CancellationToken.None, new RecordingProgress(p => reports.Add(p.Phase)));

        Assert.Null(result);
        Assert.Empty(reports);
    }

    private sealed class RecordingProgress : IProgress<TunnelProgress>
    {
        private readonly Action<TunnelProgress> _onReport;
        public RecordingProgress(Action<TunnelProgress> onReport) => _onReport = onReport;
        public void Report(TunnelProgress value) => _onReport(value);
    }

    private static TunnelManager BuildManager(
        out FakeTunnelConfigRepository repo,
        out FakeCredentialService credentials,
        IEnumerable<ITunnelProvider>? providers = null)
    {
        repo = new FakeTunnelConfigRepository();
        credentials = new FakeCredentialService();
        return new TunnelManager(
            providers ?? Array.Empty<ITunnelProvider>(),
            repo,
            credentials,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());
    }

    private static ConnectionProfile Profile(bool tunnelEnabled, Guid? tunnelConfigId) => new()
    {
        NodeId = Guid.NewGuid(),
        Name = "n",
        Protocol = ProtocolType.Ssh,
        Host = "h",
        Port = 22,
        Username = "u",
        TunnelEnabled = tunnelEnabled,
        TunnelConfigId = tunnelConfigId,
    };

    // CA1001: LastInstance is IAsyncDisposable; tests dispose it directly when they care.
    // FakeProvider itself has no DI-managed lifecycle and is never wrapped in `using`.
#pragma warning disable CA1001
    private sealed class FakeProvider : ITunnelProvider
#pragma warning restore CA1001
    {
        public int EstablishCount;
        public byte[]? LastSecret;
        public FakeInstance? LastInstance;
        public TunnelKind Kind { get; }

        public FakeProvider() : this(TunnelKind.WireGuard) { }
        public FakeProvider(TunnelKind kind) { Kind = kind; }

        public Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config,
            byte[] secretBlob,
            CancellationToken cancellationToken,
            IProgress<TunnelProgress>? progress = null)
        {
            EstablishCount++;
            LastSecret = secretBlob;
            // Emit a representative provider-side report so a test can assert the manager forwards
            // the IProgress to the resolved provider (and reports Preparing itself beforehand).
            progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
            LastInstance = new FakeInstance();
            return Task.FromResult<ITunnelInstance>(LastInstance);
        }
    }

    private sealed class FakeInstance : ITunnelInstance
    {
        public int DisposeCount;
        public TunnelState State { get; private set; } = TunnelState.Up;
        public event EventHandler<TunnelStateChangedEventArgs>? StateChanged;
        public IPEndPoint? Socks5Endpoint => new(IPAddress.Loopback, 0);
        public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            State = TunnelState.Closed;
            StateChanged?.Invoke(this, new TunnelStateChangedEventArgs(TunnelState.Closed));
            return ValueTask.CompletedTask;
        }
    }
}
