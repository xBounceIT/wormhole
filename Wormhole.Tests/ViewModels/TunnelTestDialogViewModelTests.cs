using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.Stormshield;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class TunnelTestDialogViewModelTests
{
    [Fact]
    public void Prepare_DoesNotStartTunnel()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard);
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        vm.Prepare(config);

        Assert.Equal("Ready to test.", vm.Status);
        Assert.True(vm.CanStart);
        Assert.False(vm.HasResult);
        Assert.Equal(0, provider.EstablishCount);
    }

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
    public async Task Run_WithProbeTarget_DialsThroughTunnelBeforeSuccess()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard);
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });
        vm.TargetHost = "192.0.2.10";
        vm.TargetPort = "22";

        await vm.RunAsync(config);

        Assert.True(vm.IsSuccess);
        Assert.Equal(1, provider.LastInstance!.DialCount);
        Assert.Equal("192.0.2.10", provider.LastInstance.LastDialHost);
        Assert.Equal(22, provider.LastInstance.LastDialPort);
        Assert.Contains("reached the target", vm.ResultMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_WithProbeTargetFailure_ReportsTargetProbeFailed()
    {
        var provider = new FakeTunnelProvider(TunnelKind.WireGuard);
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });
        vm.TargetHost = "192.0.2.10";
        vm.TargetPort = "22";
        provider.InstanceDialFailure = new IOException("SOCKS5: Host unreachable.");

        await vm.RunAsync(config);

        Assert.False(vm.IsSuccess);
        Assert.Equal("Target probe failed.", vm.Status);
        Assert.Equal("Target probe failed", vm.ResultTitle);
        Assert.Contains("started, but the target could not be reached", vm.ResultMessage, StringComparison.Ordinal);
        Assert.Equal(1, provider.LastInstance!.DisposeCount);
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
    public async Task Run_ProfileRefreshed_ReportsInformationalNotice_NotFailure()
    {
        // Stormshield spent the one-time code downloading a fresh profile and needs a reconnect. The dialog
        // must render this as an informational result (not an alarming error): Succeeded == false but
        // WasInformational == true, which the InfoBar severity converter maps to Informational. The title
        // comes from the exception's NoticeTitle.
        var provider = new FakeTunnelProvider(TunnelKind.Stormshield)
        {
            EstablishFailure = new StormshieldConfigRefreshedException(
                "Downloaded an updated VPN profile for 'alpha'. This used your current one-time code, so enter "
                + "a NEW code from your authenticator and reconnect to bring up the tunnel."),
        };
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        await vm.RunAsync(config);

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsSuccess);        // the tunnel did not come up...
        Assert.True(vm.WasInformational);  // ...but this is a benign notice, NOT an error
        Assert.False(vm.WasCancelled);
        Assert.Equal("Profile downloaded", vm.ResultTitle);
        Assert.Contains("enter a NEW code", vm.ResultMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_OtpReused_ReportsInformationalNotice_NotFailure()
    {
        // A re-entered just-spent code is also a TunnelRecoverableNoticeException (different subclass): the
        // dialog must treat it as an informational notice too, NOT a red error, via the shared base-type catch.
        var provider = new FakeTunnelProvider(TunnelKind.Stormshield)
        {
            EstablishFailure = new StormshieldOtpReusedException(
                "That one-time code was just used. Wait until your authenticator shows a NEW code, then reconnect."),
        };
        var (vm, config) = CreateVm(provider, new byte[] { 1, 2, 3 });

        await vm.RunAsync(config);

        Assert.False(vm.IsBusy);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsSuccess);
        Assert.True(vm.WasInformational);
        Assert.Equal("One-time code already used", vm.ResultTitle);
        Assert.Contains("NEW code", vm.ResultMessage, StringComparison.Ordinal);
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
        public Exception? InstanceDialFailure { get; set; }
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
            LastInstance = new FakeTunnelInstance { DialFailure = InstanceDialFailure };
            return LastInstance;
        }
    }

    private sealed class FakeTunnelInstance : ITunnelInstance
    {
        public int DisposeCount { get; private set; }
        public int DialCount { get; private set; }
        public string? LastDialHost { get; private set; }
        public int LastDialPort { get; private set; }
        public Exception? DialFailure { get; set; }
        public TunnelState State { get; private set; } = TunnelState.Up;
        public event EventHandler<TunnelStateChangedEventArgs>? StateChanged;
        public IPEndPoint? Socks5Endpoint => new(IPAddress.Loopback, 0);
        public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken)
        {
            DialCount++;
            LastDialHost = host;
            LastDialPort = port;
            if (DialFailure is not null) throw DialFailure;
            return Task.FromResult<Stream>(new MemoryStream());
        }
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
