using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class HttpSessionViewModelTests
{
    // ---- Target computation (scheme / port / proxy / cert policy) -------------------------------

    [Fact]
    public void BuildTarget_Http_NoTunnel_UsesHttpSchemeAndPort()
    {
        var vm = CreateVm();
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Http, "fw.local", 80), tunnel: null);

        Assert.Equal(new Uri("http://fw.local:80/"), target!.NavigateUri);
        Assert.Null(target.Socks5Proxy);
        Assert.False(target.IgnoreCertErrors);
    }

    [Fact]
    public void BuildTarget_Https_NoTunnel_UsesHttpsScheme()
    {
        var vm = CreateVm();
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "fw.local", 443), tunnel: null);

        Assert.Equal(new Uri("https://fw.local:443/"), target!.NavigateUri);
        Assert.Null(target.Socks5Proxy);
    }

    [Fact]
    public void BuildTarget_CustomPort_Honored()
    {
        var vm = CreateVm();
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "10.0.0.1", 8443), tunnel: null);

        Assert.Equal(new Uri("https://10.0.0.1:8443/"), target!.NavigateUri);
    }

    [Fact]
    public void BuildTarget_Https_IgnoreCertErrors_FlowsThrough()
    {
        var vm = CreateVm();
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "fw.local", 443, ignoreCert: true), tunnel: null);

        Assert.True(target!.IgnoreCertErrors);
    }

    [Fact]
    public void BuildTarget_PlainHttp_NeverIgnoresCertErrors()
    {
        var vm = CreateVm();
        // The flag is HTTPS-only — a plain-HTTP connection has no certificate to ignore.
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Http, "fw.local", 80, ignoreCert: true), tunnel: null);

        Assert.False(target!.IgnoreCertErrors);
    }

    [Fact]
    public void BuildTarget_TunnelWithSocks_KeepsRealHost_CarriesProxy_NoForwarder()
    {
        var vm = CreateVm();
        var socks = new IPEndPoint(IPAddress.Loopback, 1080);
        var tunnel = new FakeWebTunnel(socks);

        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "fw.local", 443), tunnel);

        Assert.Equal(new Uri("https://fw.local:443/"), target!.NavigateUri);
        Assert.Equal(socks, target.Socks5Proxy);
        Assert.Equal(0, tunnel.BindCount); // SOCKS path must not bind a loopback forwarder
    }

    [Fact]
    public void BuildTarget_TunnelWithoutSocks_BindsLoopbackForwarder()
    {
        var vm = CreateVm();
        var tunnel = new FakeWebTunnel(socks: null) { BoundPort = 51515 };

        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "fw.local", 443), tunnel);

        Assert.Equal(new Uri("https://127.0.0.1:51515/"), target!.NavigateUri);
        Assert.Null(target.Socks5Proxy);
        Assert.Equal(1, tunnel.BindCount);
        Assert.Equal("fw.local", tunnel.LastForwardHost);
        Assert.Equal(443, tunnel.LastForwardPort);
    }

    [Fact]
    public void BuildTarget_IPv6Host_IsBracketed()
    {
        var vm = CreateVm();
        var target = vm.BuildTargetForTesting(Profile(ProtocolType.Https, "fd00::1", 443), tunnel: null);

        Assert.Equal(new Uri("https://[fd00::1]:443/"), target!.NavigateUri);
    }

    // ---- Connect flow / status -----------------------------------------------------------------

    [Fact]
    public async Task Attach_DirectConnect_RaisesNavigate_AndStaysConnectingUntilNavReports()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        HttpConnectionTarget? captured = null;
        vm.NavigateRequested += t => captured = t;

        await vm.AttachAsync();

        Assert.NotNull(captured);
        Assert.Equal(new Uri("https://fw.local:443/"), captured!.NavigateUri);
        Assert.Equal(SessionStatus.Connecting, vm.Status);

        vm.ReportNavigationSucceeded();
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task ReportNavigationFailed_SetsFailedWithMessage()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        vm.NavigateRequested += _ => { };
        await vm.AttachAsync();

        vm.ReportNavigationFailed("boom");

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("boom", vm.ErrorMessage);
    }

    [Fact]
    public async Task RoutePromptCancelled_ReportsFailed_WithoutNavigate()
    {
        var raised = false;
        var vm = CreateVm(prompter: new FakeRoutePrompter((ConnectionProfile?)null));
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443, tunnelEnabled: true));
        vm.NavigateRequested += _ => raised = true;

        await vm.AttachAsync();

        Assert.False(raised);
        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("Connection cancelled.", vm.ErrorMessage);
    }

    [Fact]
    public async Task ReAttach_AfterConnected_ReRaisesExistingTarget()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        var navigateCount = 0;
        HttpConnectionTarget? last = null;
        vm.NavigateRequested += t => { navigateCount++; last = t; };

        await vm.AttachAsync();
        vm.ReportNavigationSucceeded();
        Assert.Equal(SessionStatus.Connected, vm.Status);

        // Sessions↔Settings navigation rebuilds the view; AttachAsync should re-navigate the existing
        // target rather than start a fresh connect.
        await vm.AttachAsync();

        Assert.Equal(2, navigateCount);
        Assert.Equal(new Uri("https://fw.local:443/"), last!.NavigateUri);
    }

    [Fact]
    public async Task Attach_AfterFailed_DoesNotReconnect()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        var navigateCount = 0;
        vm.NavigateRequested += _ => navigateCount++;

        await vm.AttachAsync();             // initial connect raises one navigate, stays Connecting
        vm.ReportNavigationFailed("boom");  // -> Failed
        Assert.Equal(SessionStatus.Failed, vm.Status);

        // The view is rebuilt (Sessions<->Settings round-trip) while Failed: AttachAsync must NOT
        // auto-reconnect / re-prompt — the Retry button owns the next action.
        await vm.AttachAsync();

        Assert.Equal(1, navigateCount);
        Assert.Equal(SessionStatus.Failed, vm.Status);
    }

    [Fact]
    public async Task ReportNavigationFailed_WhenConnected_DoesNotDemote()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        vm.NavigateRequested += _ => { };
        await vm.AttachAsync();
        vm.ReportNavigationSucceeded();
        Assert.Equal(SessionStatus.Connected, vm.Status);

        // A transient reload failure after a re-navigation must not knock a healthy tab to Failed.
        vm.ReportNavigationFailed("transient reload error");

        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task ReportNavigationFailed_TunneledConnect_TearsDownTunnel()
    {
        // A tunneled web tab establishes the VPN before NavigateRequested. If the initial navigation then
        // fails (cert error with validation on, timeout, bad host), the tunnel + any loopback forwarder must
        // be released — not left running behind a "failed" tab until the user happens to Retry/Close.
        var configId = Guid.NewGuid();
        var tunnelRepo = new FakeTunnelConfigRepository();
        tunnelRepo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp", Kind = TunnelKind.WireGuard };
        var creds = new FakeCredentialService();
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };
        var tunnel = new FakeWebTunnel(new IPEndPoint(IPAddress.Loopback, 1080));
        var tunnels = BuildTunnelManager(creds, tunnelRepo, new ITunnelProvider[] { new FakeWebTunnelProvider(tunnel) });

        var vm = CreateVm(tunnels: tunnels);
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443, tunnelEnabled: true, tunnelConfigId: configId));
        vm.NavigateRequested += _ => { };

        await vm.AttachAsync();
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Equal(0, tunnel.DisposeCount);

        vm.ReportNavigationFailed("cert error");

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("cert error", vm.ErrorMessage);
        Assert.Equal(1, tunnel.DisposeCount);
    }

    [Fact]
    public void Initialize_StartsConnecting_SoUnrealizedTabIsntBlank()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Https, "fw.local", 443));
        Assert.Equal(SessionStatus.Connecting, vm.Status);
    }

    [Fact]
    public void Protocol_ReflectsProfile()
    {
        var vm = CreateVm();
        vm.Initialize(Profile(ProtocolType.Http, "fw.local", 80));
        Assert.Equal(ProtocolType.Http, vm.Protocol);
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static HttpSessionViewModel CreateVm(ITunnelRoutePrompter? prompter = null, TunnelManager? tunnels = null)
    {
        tunnels ??= BuildTunnelManager(new FakeCredentialService(), new FakeTunnelConfigRepository());
        return new HttpSessionViewModel(
            tunnels,
            prompter ?? new FakeRoutePrompter(),
            new FakeProfileResolver(),
            NullLoggerFactory.Instance);
    }

    private static TunnelManager BuildTunnelManager(
        FakeCredentialService credentials,
        FakeTunnelConfigRepository repo,
        IEnumerable<ITunnelProvider>? providers = null) =>
        new(
            providers ?? Array.Empty<ITunnelProvider>(),
            repo,
            credentials,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());

    private static ConnectionProfile Profile(
        ProtocolType protocol, string host, int port, bool ignoreCert = false,
        bool tunnelEnabled = false, Guid? tunnelConfigId = null) =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = host,
            Protocol = protocol,
            Host = host,
            Port = port,
            HttpIgnoreCertErrors = ignoreCert,
            TunnelEnabled = tunnelEnabled,
            TunnelConfigId = tunnelConfigId,
        };

    private sealed class FakeRoutePrompter : ITunnelRoutePrompter
    {
        private readonly bool _passthrough;
        private readonly ConnectionProfile? _result;
        public FakeRoutePrompter() => _passthrough = true;
        public FakeRoutePrompter(ConnectionProfile? result) => _result = result;
        public Task<ConnectionProfile?> ResolveRouteAsync(ConnectionProfile profile, CancellationToken cancellationToken) =>
            Task.FromResult(_passthrough ? profile : _result);
    }

    private sealed class FakeProfileResolver : IConnectionProfileResolver
    {
        public Task<ConnectionProfile?> ResolveAsync(Guid nodeId, CancellationToken cancellationToken = default) =>
            Task.FromResult<ConnectionProfile?>(null);
    }

    private sealed class FakeWebTunnel : ITunnelInstance
    {
        private readonly IPEndPoint? _socks;
        public FakeWebTunnel(IPEndPoint? socks) => _socks = socks;
        public int BoundPort { get; set; } = 51000;
        public int BindCount { get; private set; }
        public int DisposeCount { get; private set; }
        public string? LastForwardHost { get; private set; }
        public int? LastForwardPort { get; private set; }
        public TunnelState State => TunnelState.Up;
        public event EventHandler<TunnelStateChangedEventArgs>? StateChanged { add { } remove { } }
        public IPEndPoint? Socks5Endpoint => _socks;

        public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken)
        {
            BindCount++;
            LastForwardHost = host;
            LastForwardPort = port;
            return Task.FromResult(BoundPort);
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    // Returns a pre-built FakeWebTunnel from EstablishAsync so a test can drive a full tunneled connect
    // through TunnelManager and then assert the VM disposes the instance. Kind matches the config below.
    private sealed class FakeWebTunnelProvider : ITunnelProvider
    {
        private readonly FakeWebTunnel _instance;
        public FakeWebTunnelProvider(FakeWebTunnel instance) => _instance = instance;
        public TunnelKind Kind => TunnelKind.WireGuard;

        public Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken,
            IProgress<TunnelProgress>? progress = null) =>
            Task.FromResult<ITunnelInstance>(_instance);
    }
}
