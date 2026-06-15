using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

/// <summary>
/// Locks the shared-tunnel pool semantics of <see cref="TunnelManager"/>: one ref-counted tunnel
/// per config id, leases that close the real instance only when the last one is released, eviction
/// of dead/edited configs, and coalescing of concurrent establishments.
/// </summary>
public class TunnelManagerSharingTests
{
    [Fact]
    public async Task SecondEstablish_SameConfig_ReusesTunnel_AndLastReleaseCloses()
    {
        var (mgr, provider, profile, _) = Build();

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);
        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);

        Assert.NotNull(lease1);
        Assert.NotNull(lease2);
        Assert.Equal(1, provider.EstablishCount);

        await lease1!.DisposeAsync();
        Assert.Equal(0, provider.Instances[0].DisposeCount); // still leased by lease2

        await lease2!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount); // last lease released → closed

        // A fully-released tunnel is gone from the pool; the next connect establishes fresh.
        var lease3 = await mgr.EstablishAsync(profile, CancellationToken.None);
        Assert.Equal(2, provider.EstablishCount);
        await lease3!.DisposeAsync();
    }

    [Fact]
    public async Task Establish_DifferentConfigs_DoNotShare()
    {
        var provider = new SimpleProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profileA = ProfileFor(AddConfig(repo, creds));
        var profileB = ProfileFor(AddConfig(repo, creds));

        var leaseA = await mgr.EstablishAsync(profileA, CancellationToken.None);
        var leaseB = await mgr.EstablishAsync(profileB, CancellationToken.None);

        Assert.Equal(2, provider.EstablishCount);

        await leaseA!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount); // A's only lease → closed
        Assert.Equal(0, provider.Instances[1].DisposeCount); // B untouched

        await leaseB!.DisposeAsync();
        Assert.Equal(1, provider.Instances[1].DisposeCount);
    }

    [Fact]
    public async Task LeaseDispose_IsIdempotent_ReleasesOnlyOnce()
    {
        var (mgr, provider, profile, _) = Build();

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);
        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);

        // Multiple teardown paths (disconnect + close, retry + close) may dispose the same handle;
        // double-disposing lease1 must not steal lease2's ref and close the tunnel under it.
        await lease1!.DisposeAsync();
        await lease1.DisposeAsync();
        Assert.Equal(0, provider.Instances[0].DisposeCount);

        await lease2!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount);
    }

    [Fact]
    public async Task FailedTunnel_IsNotHandedToNewConnections()
    {
        var (mgr, provider, profile, _) = Build();

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);
        provider.Instances[0].RaiseState(TunnelState.Failed); // sidecar died under a live lease

        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);
        Assert.Equal(2, provider.EstablishCount); // fresh establishment, not the dead instance

        // The dead instance is still owned by its outstanding lease and closes on release.
        await lease1!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount);
        await lease2!.DisposeAsync();
        Assert.Equal(1, provider.Instances[1].DisposeCount);
    }

    [Fact]
    public async Task EditedConfig_GetsFreshTunnel_WhileOldLeasesDrain()
    {
        var (mgr, provider, profile, repo) = Build();

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);

        // Saving the tunnel editor bumps the row's UpdatedAt (even payload-only edits).
        repo.Configs[profile.TunnelConfigId!.Value].UpdatedAt = DateTime.UtcNow.AddMinutes(1);

        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);
        Assert.Equal(2, provider.EstablishCount);

        await lease1!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount); // old instance closed by its last lease
        Assert.Equal(0, provider.Instances[1].DisposeCount);

        await lease2!.DisposeAsync();
        Assert.Equal(1, provider.Instances[1].DisposeCount);
    }

    [Fact]
    public async Task ConcurrentEstablishes_CoalesceIntoOneProviderCall()
    {
        var provider = new GatedProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        var first = mgr.EstablishAsync(profile, CancellationToken.None);
        await provider.Started.Task;
        var second = mgr.EstablishAsync(profile, CancellationToken.None);

        var instance = new RecordingTunnel();
        provider.Gate.SetResult(instance);

        var lease1 = await first;
        var lease2 = await second;
        Assert.Equal(1, provider.EstablishCount); // one OTP prompt / one VPN login serves both

        await lease1!.DisposeAsync();
        Assert.Equal(0, instance.DisposeCount);
        await lease2!.DisposeAsync();
        Assert.Equal(1, instance.DisposeCount);
    }

    [Fact]
    public async Task WaiterCancellation_DoesNotAbortEstablishmentForOthers()
    {
        var provider = new GatedProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        using var cts = new CancellationTokenSource();
        var first = mgr.EstablishAsync(profile, cts.Token);
        await provider.Started.Task;
        var second = mgr.EstablishAsync(profile, CancellationToken.None);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.False(provider.LastToken.IsCancellationRequested); // second waiter keeps it alive

        var instance = new RecordingTunnel();
        provider.Gate.SetResult(instance);
        var lease = await second;

        await lease!.DisposeAsync();
        Assert.Equal(1, instance.DisposeCount);
    }

    [Fact]
    public async Task AllWaitersCancelled_AbortsEstablishment_AndDisposesLateResult()
    {
        var provider = new GatedProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        using var cts = new CancellationTokenSource();
        var first = mgr.EstablishAsync(profile, cts.Token);
        await provider.Started.Task;

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.True(provider.LastToken.IsCancellationRequested); // last waiter gone → abort signalled

        // A provider that never observed the cancellation and completes anyway must not leak the
        // instance: nobody owns it, so the pool closes it.
        var instance = new RecordingTunnel();
        provider.Gate.SetResult(instance);
        await instance.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, instance.DisposeCount);

        // And the abandoned entry is gone: the next connect starts a fresh establishment.
        provider.Reset();
        var retry = mgr.EstablishAsync(profile, CancellationToken.None);
        await provider.Started.Task;
        provider.Gate.SetResult(new RecordingTunnel());
        var lease = await retry;
        Assert.Equal(2, provider.EstablishCount);
        await lease!.DisposeAsync();
    }

    [Fact]
    public async Task AllWaitersCancelled_DisposesEstablishCancellationWaitHandle()
    {
        var provider = new GatedProvider { CaptureWaitHandle = true };
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        using var cts = new CancellationTokenSource();
        var first = mgr.EstablishAsync(profile, cts.Token);
        await provider.Started.Task;
        var waitHandle = Assert.IsAssignableFrom<WaitHandle>(provider.LastWaitHandle);
        Assert.False(waitHandle.SafeWaitHandle.IsClosed);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.True(provider.LastToken.IsCancellationRequested);

        var instance = new RecordingTunnel();
        provider.Gate.SetResult(instance);
        await WaitUntilAsync(() => waitHandle.SafeWaitHandle.IsClosed);
        Assert.Equal(1, instance.DisposeCount);
    }

    [Fact]
    public async Task ReuseProbe_LiveSocksEndpoint_IsReused()
    {
        var (mgr, provider, profile, _) = Build();

        // A real loopback listener stands in for a healthy sidecar's SOCKS endpoint.
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);
            provider.Instances[0].Endpoint = (IPEndPoint)listener.LocalEndpoint;

            var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);
            Assert.Equal(1, provider.EstablishCount); // probe passed → reused

            await lease1!.DisposeAsync();
            await lease2!.DisposeAsync();
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ReuseProbe_DeadSocksEndpoint_EvictsAndEstablishesFresh()
    {
        var (mgr, provider, profile, _) = Build();

        // A bound-but-never-listening socket refuses connections while keeping the port reserved
        // (so no parallel test can rebind it mid-run) — exactly how a crashed sidecar's port looks
        // while the instance still reports State == Up.
        using var reserved = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork,
            System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var deadEndpoint = (IPEndPoint)reserved.LocalEndPoint!;

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);
        provider.Instances[0].Endpoint = deadEndpoint;

        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None);
        Assert.Equal(2, provider.EstablishCount); // probe failed → fresh establishment

        // The dead instance still belongs to its outstanding lease and closes on release.
        await lease1!.DisposeAsync();
        Assert.Equal(1, provider.Instances[0].DisposeCount);
        await lease2!.DisposeAsync();
        Assert.Equal(1, provider.Instances[1].DisposeCount);
    }

    [Fact]
    public async Task FailedEstablishment_IsNotCached()
    {
        var provider = new SimpleProvider { Throw = true };
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        await Assert.ThrowsAsync<IOException>(() => mgr.EstablishAsync(profile, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => mgr.EstablishAsync(profile, CancellationToken.None));
        Assert.Equal(2, provider.EstablishCount); // each attempt retried the provider

        provider.Throw = false;
        var lease = await mgr.EstablishAsync(profile, CancellationToken.None);
        Assert.NotNull(lease);
        await lease!.DisposeAsync();
    }

    [Fact]
    public async Task JoiningWaiter_GetsLatestPhaseReplayed_ThenLiveReports()
    {
        var provider = new GatedProvider(); // reports Authenticating before parking on the gate
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        var first = mgr.EstablishAsync(profile, CancellationToken.None);
        await provider.Started.Task;

        var joinerReports = new List<TunnelProgress>();
        var second = mgr.EstablishAsync(profile, CancellationToken.None, new RecordingProgress(joinerReports.Add));

        // The joiner sees the manager's own Preparing, then the in-flight establishment's latest
        // phase replayed so its overlay isn't blank until the next provider report.
        Assert.Equal(
            new[] { TunnelPhase.Preparing, TunnelPhase.Authenticating },
            joinerReports.ConvertAll(r => r.Phase));

        provider.LastProgress!.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
        Assert.Equal(TunnelPhase.StartingTunnel, joinerReports[^1].Phase); // live report fans out

        provider.Gate.SetResult(new RecordingTunnel());
        await Task.WhenAll(first, second);
        await (await first)!.DisposeAsync();
        await (await second)!.DisposeAsync();
    }

    [Fact]
    public async Task ProviderProgress_ThrowingSink_DoesNotStarveOtherSinksOrFailEstablishment()
    {
        var provider = new TwoPhaseProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));

        var first = mgr.EstablishAsync(profile, CancellationToken.None);
        await provider.Started.Task;

        var throwingReports = new List<TunnelPhase>();
        var throwing = new RecordingProgress(progress =>
        {
            throwingReports.Add(progress.Phase);
            if (progress.Phase == TunnelPhase.DownloadingConfiguration)
            {
                throw new InvalidOperationException("Progress sink failed.");
            }
        });

        var goodReports = new List<TunnelPhase>();
        var throwingWaiter = mgr.EstablishAsync(profile, CancellationToken.None, throwing);
        var goodWaiter = mgr.EstablishAsync(
            profile,
            CancellationToken.None,
            new RecordingProgress(progress => goodReports.Add(progress.Phase)));

        Assert.Equal(new[] { TunnelPhase.Preparing, TunnelPhase.Authenticating }, throwingReports);
        Assert.Equal(new[] { TunnelPhase.Preparing, TunnelPhase.Authenticating }, goodReports);

        provider.Proceed.SetResult();

        var leases = await Task.WhenAll(first, throwingWaiter, goodWaiter);
        Assert.Equal(
            new[] { TunnelPhase.Preparing, TunnelPhase.Authenticating, TunnelPhase.DownloadingConfiguration },
            throwingReports);
        Assert.Equal(
            new[]
            {
                TunnelPhase.Preparing,
                TunnelPhase.Authenticating,
                TunnelPhase.DownloadingConfiguration,
                TunnelPhase.StartingTunnel,
            },
            goodReports);

        foreach (var lease in leases)
        {
            await lease!.DisposeAsync();
        }
    }

    [Fact]
    public async Task ReusingLiveTunnel_ReportsReuseDetail()
    {
        var (mgr, _, profile, _) = Build();

        var lease1 = await mgr.EstablishAsync(profile, CancellationToken.None);

        var reports = new List<TunnelProgress>();
        var lease2 = await mgr.EstablishAsync(profile, CancellationToken.None, new RecordingProgress(reports.Add));

        Assert.Equal(TunnelPhase.Preparing, reports[0].Phase);
        Assert.Contains(reports, r => r.Detail is not null && r.Detail.Contains("Reusing", StringComparison.Ordinal));

        await lease1!.DisposeAsync();
        await lease2!.DisposeAsync();
    }

    // === Helpers ===========================================================

    private static (TunnelManager Mgr, SimpleProvider Provider, ConnectionProfile Profile, FakeTunnelConfigRepository Repo) Build()
    {
        var provider = new SimpleProvider();
        var (repo, creds) = Stores();
        var mgr = Manager(repo, creds, provider);
        var profile = ProfileFor(AddConfig(repo, creds));
        return (mgr, provider, profile, repo);
    }

    private static (FakeTunnelConfigRepository Repo, FakeCredentialService Creds) Stores() =>
        (new FakeTunnelConfigRepository(), new FakeCredentialService());

    private static TunnelManager Manager(
        FakeTunnelConfigRepository repo, FakeCredentialService creds, ITunnelProvider provider) =>
        new(new[] { provider }, repo, creds, NullLogger<TunnelManager>.Instance);

    private static Guid AddConfig(FakeTunnelConfigRepository repo, FakeCredentialService creds)
    {
        var configId = Guid.NewGuid();
        repo.Configs[configId] = new TunnelConfig { Id = configId, Name = "wg-" + configId.ToString("N"), Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };
        return configId;
    }

    private static ConnectionProfile ProfileFor(Guid configId) => new()
    {
        NodeId = Guid.NewGuid(),
        Name = "n",
        Protocol = ProtocolType.Ssh,
        Host = "h",
        Port = 22,
        Username = "u",
        TunnelEnabled = true,
        TunnelConfigId = configId,
    };

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }
        Assert.True(condition());
    }

    /// <summary>Completes establishment synchronously with a fresh instance per call.</summary>
    private sealed class SimpleProvider : ITunnelProvider
    {
        public int EstablishCount;
        public bool Throw;
        public List<RecordingTunnel> Instances { get; } = new();
        public TunnelKind Kind => TunnelKind.WireGuard;

        public Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken, IProgress<TunnelProgress>? progress = null)
        {
            EstablishCount++;
            if (Throw) throw new IOException("gateway unreachable");
            var instance = new RecordingTunnel();
            Instances.Add(instance);
            return Task.FromResult<ITunnelInstance>(instance);
        }
    }

    /// <summary>
    /// Parks establishment on <see cref="Gate"/> after reporting Authenticating, so tests can hold
    /// the shared establishment in flight while waiters join, cancel, or observe progress.
    /// </summary>
    private sealed class GatedProvider : ITunnelProvider
    {
        public int EstablishCount;
        public CancellationToken LastToken;
        public IProgress<TunnelProgress>? LastProgress;
        public bool CaptureWaitHandle;
        public WaitHandle? LastWaitHandle;
        public TaskCompletionSource<ITunnelInstance> Gate { get; private set; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started { get; private set; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TunnelKind Kind => TunnelKind.WireGuard;

        public void Reset()
        {
            Gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public async Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken, IProgress<TunnelProgress>? progress = null)
        {
            Interlocked.Increment(ref EstablishCount);
            LastToken = cancellationToken;
            LastProgress = progress;
            if (CaptureWaitHandle) LastWaitHandle = cancellationToken.WaitHandle;
            progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));
            Started.TrySetResult();
            // Deliberately ignores cancellation: the abandoned-result test needs a provider that
            // completes anyway so the pool's nobody-owns-it disposal is exercised.
            return await Gate.Task.ConfigureAwait(false);
        }
    }

    private sealed class TwoPhaseProvider : ITunnelProvider
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Proceed { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TunnelKind Kind => TunnelKind.WireGuard;

        public async Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken, IProgress<TunnelProgress>? progress = null)
        {
            progress?.Report(new TunnelProgress(TunnelPhase.Authenticating));
            Started.TrySetResult();
            await Proceed.Task.ConfigureAwait(false);
            progress?.Report(new TunnelProgress(TunnelPhase.DownloadingConfiguration));
            progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
            return new RecordingTunnel();
        }
    }

}
