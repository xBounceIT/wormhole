using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class TunnelTestDialogViewModelTests
{
    [Fact]
    public async Task Run_Success_EstablishesDisposesAndReportsSuccess()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard);
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        await vm.RunAsync(config);

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.True(vm.IsSuccess);
        Assert.Equal(1, provider.EstablishCount);
        Assert.Equal(config.Id, provider.LastConfig?.Id);
        Assert.Equal(new byte[] { 1, 2, 3 }, provider.LastSecret);
        // The diagnostic must always tear the test tunnel back down.
        Assert.Equal(1, provider.LastInstance!.DisposeCount);
        Assert.Equal("Tunnel test succeeded", vm.ResultTitle);
        // The log streamed the establish phases plus the closing line.
        Assert.Contains(vm.Log, l => l.Contains("Bringing up the VPN tunnel", StringComparison.Ordinal));
        Assert.Contains(vm.Log, l => l.Contains("established successfully", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Run_ProviderThrows_ReportsFailureWithLastStep()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard)
        {
            EstablishFailure = new InvalidOperationException("simulated auth failure"),
        };
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        await vm.RunAsync(config);

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsSuccess);
        Assert.Equal("Tunnel test failed", vm.ResultTitle);
        Assert.Contains("simulated auth failure", vm.ResultMessage);
        Assert.Contains("Last step: starting tunnel.", vm.ResultMessage);
        Assert.Contains(vm.Log, l => l.Contains("simulated auth failure", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Run_MissingSecret_ReportsFailureBeforeDispatch()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard);
        var (vm, config) = CreateVm(provider, secret: null);

        await vm.RunAsync(config);

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsSuccess);
        Assert.Equal(0, provider.EstablishCount); // bailed before reaching the provider
    }

    [Fact]
    public async Task Cancel_AbortsInFlightEstablish()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard) { BlockUntilCancelled = true };
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        var run = vm.RunAsync(config);
        Assert.True(vm.IsBusy);

        vm.RequestCancelForClose();
        await run;

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsSuccess);
        Assert.Equal("Tunnel test cancelled", vm.ResultTitle);
    }

    private static (TunnelTestDialogViewModel Vm, TunnelConfig Config) CreateVm(FakeTunnelProvider provider, byte[]? secret)
    {
        var repo = new FakeTunnelConfigRepository();
        var creds = new FakeCredentialService();
        var id = Guid.NewGuid();
        var config = new TunnelConfig { Id = id, Name = "alpha", Kind = provider.Kind };
        repo.Configs[id] = config;
        if (secret is not null) creds.TunnelConfigs[id] = secret;
        var tunnelManager = new TunnelManager(
            new ITunnelProvider[] { provider }, repo, creds, NullLogger<TunnelManager>.Instance);
        var vm = new TunnelTestDialogViewModel(tunnelManager, NullLogger<TunnelTestDialogViewModel>.Instance);
        return (vm, config);
    }

    private sealed class FakeTunnelProvider : ITunnelProvider
    {
        public FakeTunnelProvider(TunnelKind kind) => Kind = kind;

        public TunnelKind Kind { get; }
        public int EstablishCount { get; private set; }
        public TunnelConfig? LastConfig { get; private set; }
        public byte[]? LastSecret { get; private set; }
        public FakeTunnelInstance? LastInstance { get; private set; }
        public Exception? EstablishFailure { get; set; }
        public bool BlockUntilCancelled { get; set; }

        public async Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config,
            byte[] secretBlob,
            CancellationToken cancellationToken,
            IProgress<TunnelProgress>? progress = null)
        {
            EstablishCount++;
            LastConfig = config;
            LastSecret = secretBlob;
            progress?.Report(new TunnelProgress(TunnelPhase.StartingTunnel));
            if (BlockUntilCancelled)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            }
            if (EstablishFailure is not null) throw EstablishFailure;
            LastInstance = new FakeTunnelInstance();
            return LastInstance;
        }
    }

    private sealed class FakeTunnelInstance : ITunnelInstance
    {
        public int DisposeCount { get; private set; }
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
