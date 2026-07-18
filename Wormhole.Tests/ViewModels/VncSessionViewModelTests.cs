using System.Collections.Immutable;
using System.Net;
using MarcusW.VncClient;
using MarcusW.VncClient.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class VncSessionViewModelTests
{
    [Fact]
    public async Task AttachAsync_DirectConnect_SetsConnected()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        var profile = Profile();
        vm.Initialize(profile);

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Single(service.Calls);
        Assert.Same(profile, service.Calls[0].Profile);
        Assert.Null(service.Calls[0].Tunnel);
    }

    [Fact]
    public async Task PasswordProvider_UsesSavedCredentialBeforePrompting()
    {
        var credentialId = Guid.NewGuid();
        var credentials = new FakeCredentialService();
        credentials.Passwords[credentialId] = "saved-vnc";
        var dialog = new FakeDialogService { PasswordPromptResult = "prompted" };
        var repo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Name = "vnc",
            Protocol = ProtocolType.Vnc,
            Kind = CredentialKind.Password,
        });
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(service, credentials: credentials, credentialRepository: repo, dialog: dialog);
        vm.Initialize(Profile(credentialId: credentialId));

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("saved-vnc", Assert.Single(service.Passwords));
        Assert.Equal(0, dialog.PasswordPromptCount);
    }

    [Fact]
    public async Task PasswordProvider_EphemeralProfile_UsesTransientPasswordBeforePrompting()
    {
        var nodeId = Guid.NewGuid();
        var transientCredentials = new TransientSessionCredentialStore();
        transientCredentials.Store(nodeId, "session-vnc");
        var dialog = new FakeDialogService { PasswordPromptResult = "prompted" };
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(
            service,
            dialog: dialog,
            transientCredentials: transientCredentials);
        vm.Initialize(Profile(nodeId: nodeId) with { IsEphemeral = true });

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("session-vnc", Assert.Single(service.Passwords));
        Assert.Equal(0, dialog.PasswordPromptCount);
    }

    [Fact]
    public async Task PasswordProvider_EphemeralPromptedPassword_IsCachedForReconnect()
    {
        var nodeId = Guid.NewGuid();
        var transientCredentials = new TransientSessionCredentialStore();
        var dialog = new FakeDialogService { PasswordPromptResult = "prompted-vnc" };
        var profile = Profile(nodeId: nodeId) with { IsEphemeral = true };
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(service, dialog: dialog, transientCredentials: transientCredentials);
        vm.Initialize(profile);

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("prompted-vnc", transientCredentials.Read(nodeId));
        Assert.Equal(1, dialog.PasswordPromptCount);

        var reconnectedService = new FakeVncSessionService { RequestPassword = true };
        var reconnectedVm = CreateVm(
            reconnectedService,
            dialog: dialog,
            transientCredentials: transientCredentials);
        reconnectedVm.Initialize(profile);

        await reconnectedVm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("prompted-vnc", Assert.Single(reconnectedService.Passwords));
        Assert.Equal(1, dialog.PasswordPromptCount);
    }

    [Fact]
    public async Task PasswordProvider_PromptsWhenSavedCredentialHasNoPassword()
    {
        var credentialId = Guid.NewGuid();
        var dialog = new FakeDialogService { PasswordPromptResult = "typed-vnc" };
        var repo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Name = "vnc",
            Protocol = ProtocolType.Vnc,
            Kind = CredentialKind.Password,
        });
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(service, credentialRepository: repo, dialog: dialog);
        vm.Initialize(Profile(credentialId: credentialId));

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("typed-vnc", Assert.Single(service.Passwords));
        Assert.Equal(1, dialog.PasswordPromptCount);
    }

    [Fact]
    public async Task PasswordProvider_PromptsWhenCredentialProtocolDoesNotMatchVnc()
    {
        var credentialId = Guid.NewGuid();
        var credentials = new FakeCredentialService();
        credentials.Passwords[credentialId] = "ssh-secret";
        var repo = new FakeCredentialRepository(new CredentialProfile
        {
            Id = credentialId,
            Name = "ssh",
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
        });
        var dialog = new FakeDialogService { PasswordPromptResult = "typed-vnc" };
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(service, credentials: credentials, credentialRepository: repo, dialog: dialog);
        vm.Initialize(Profile(credentialId: credentialId));

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal("typed-vnc", Assert.Single(service.Passwords));
        Assert.Equal(1, dialog.PasswordPromptCount);
    }

    [Fact]
    public async Task PasswordProvider_CancelledPrompt_ReturnsToDisconnected()
    {
        var service = new FakeVncSessionService { RequestPassword = true };
        var vm = CreateVm(service, dialog: new FakeDialogService { PasswordPromptResult = null });
        vm.Initialize(Profile());

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task AttachAsync_ServiceFailure_SetsFailedStatusAndMessage()
    {
        var service = new FakeVncSessionService
        {
            ExceptionToThrow = new InvalidOperationException("unsupported security type"),
        };
        var vm = CreateVm(service);
        vm.Initialize(Profile());

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("unsupported security type", vm.ErrorMessage);
    }

    [Fact]
    public async Task ResolveRouteCancel_ReturnsToDisconnectedWithoutOpeningSession()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service, prompter: new FakeRoutePrompter(null));
        vm.Initialize(Profile());

        await vm.AttachAsync(new FakeRenderTarget());

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.Empty(service.Calls);
    }

    [Fact]
    public async Task AttachAsync_TunneledProfile_EstablishesTunnelAndPassesLeaseToService()
    {
        var tunnelId = Guid.NewGuid();
        var tunnel = new FakeTunnelInstance();
        var credentials = new FakeCredentialService();
        credentials.TunnelConfigs[tunnelId] = new byte[] { 1, 2, 3 };
        var repo = new FakeTunnelConfigRepository();
        repo.Configs[tunnelId] = new TunnelConfig
        {
            Id = tunnelId,
            Name = "office",
            Kind = TunnelKind.WireGuard,
            UpdatedAt = DateTime.UtcNow,
        };
        var service = new FakeVncSessionService();
        var vm = CreateVm(
            service,
            credentials: credentials,
            tunnels: BuildTunnelManager(credentials, repo, new[] { new FakeTunnelProvider(tunnel) }));
        vm.Initialize(Profile(tunnelEnabled: true, tunnelConfigId: tunnelId));

        await vm.AttachAsync(new FakeRenderTarget());

        var lease = service.Calls.Single().Tunnel;
        Assert.NotNull(lease);
        Assert.Equal(TunnelState.Up, lease.State);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task AttachAsync_InFlightConnectUsesLatestRenderTarget()
    {
        var service = new FakeVncSessionService
        {
            ConnectGate = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        var vm = CreateVm(service);
        vm.Initialize(Profile());
        var firstTarget = new DisposableRenderTarget();
        var secondTarget = new FakeRenderTarget();

        var firstAttach = vm.AttachAsync(firstTarget);
        await WaitForAsync(() => service.Calls.Count == 1);

        await vm.AttachAsync(secondTarget);

        service.ConnectGate.SetResult(null);
        await firstAttach;

        Assert.Same(secondTarget, Assert.Single(service.Session.RenderTargets));
        Assert.Equal(1, firstTarget.DisposeCount);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task AttachAsync_ConnectedSessionReplacesRenderTarget_DisposesPrevious()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        var firstTarget = new DisposableRenderTarget();
        var secondTarget = new DisposableRenderTarget();
        vm.Initialize(Profile());
        await vm.AttachAsync(firstTarget);

        await vm.AttachAsync(secondTarget);

        Assert.Equal(1, firstTarget.DisposeCount);
        Assert.Equal(0, secondTarget.DisposeCount);
        Assert.Same(secondTarget, service.Session.RenderTargets.Last());
    }

    [Fact]
    public async Task AttachAsync_SameRenderTarget_DoesNotDisposeTarget()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        var renderTarget = new DisposableRenderTarget();
        vm.Initialize(Profile());
        await vm.AttachAsync(renderTarget);

        await vm.AttachAsync(renderTarget);

        Assert.Equal(0, renderTarget.DisposeCount);
    }

    [Fact]
    public async Task DisconnectAsync_DisposesSessionAndTunnel()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        var renderTarget = new DisposableRenderTarget();
        vm.Initialize(Profile());
        await vm.AttachAsync(renderTarget);

        await vm.DisconnectAsync();

        Assert.Equal(1, service.Session.DisposeCount);
        Assert.Equal(0, renderTarget.DisposeCount);
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
    }

    [Fact]
    public async Task CloseAsync_DisposesRenderTargetAfterSessionTeardown()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        var renderTarget = new DisposableRenderTarget();
        vm.Initialize(Profile());
        await vm.AttachAsync(renderTarget);

        await vm.CloseAsync();

        Assert.Equal(1, service.Session.DisposeCount);
        Assert.Equal(1, renderTarget.DisposeCount);
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
    }

    [Fact]
    public async Task SessionClosed_ClearsActiveSessionSoLaterInputIsIgnored()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        vm.Initialize(Profile());
        await vm.AttachAsync(new FakeRenderTarget());

        service.Session.RaiseClosed(clean: false, message: "lost");
        await WaitForAsync(() => vm.Status == SessionStatus.Failed);
        await vm.SendKeyAsync(isDown: true, keySymbol: 0xff0d);
        await vm.SendPointerAsync(1, 2, VncPointerButtons.Left);

        Assert.Equal(1, service.Session.DisposeCount);
        Assert.Empty(service.Session.KeyInputs);
        Assert.Empty(service.Session.PointerInputs);
    }

    [Fact]
    public async Task SessionClosed_CleanRemoteClose_SetsFailedStatusAndMessage()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        vm.Initialize(Profile());
        await vm.AttachAsync(new FakeRenderTarget());

        service.Session.RaiseClosed(clean: true, message: string.Empty);
        await WaitForAsync(() => vm.Status == SessionStatus.Failed);

        Assert.Equal("VNC connection closed by the remote host.", vm.ErrorMessage);
        Assert.Equal(1, service.Session.DisposeCount);
    }

    [Fact]
    public async Task RetryAsync_RefreshesProfileBeforeReconnecting()
    {
        var first = Profile(host: "old.example.com");
        var refreshed = Profile(nodeId: first.NodeId, host: "new.example.com");
        var service = new FakeVncSessionService
        {
            ExceptionToThrow = new InvalidOperationException("first failure"),
        };
        var resolver = new FakeProfileResolver(refreshed);
        var vm = CreateVm(service, profileResolver: resolver);
        vm.Initialize(first);
        await vm.AttachAsync(new FakeRenderTarget());
        Assert.Equal(SessionStatus.Failed, vm.Status);

        service.ExceptionToThrow = null;
        await vm.RetryAsync();

        Assert.Equal(2, service.Calls.Count);
        Assert.Equal("new.example.com", service.Calls[1].Profile.Host);
        Assert.Equal(first.NodeId, resolver.LastNodeId);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task InputMethods_DelegateToConnectedSession()
    {
        var service = new FakeVncSessionService();
        var vm = CreateVm(service);
        vm.Initialize(Profile());
        await vm.AttachAsync(new FakeRenderTarget());

        await vm.SendPointerAsync(10, 20, VncPointerButtons.Left);
        await vm.SendKeyAsync(isDown: true, keySymbol: 0xff0d);

        Assert.Equal((10, 20, VncPointerButtons.Left), Assert.Single(service.Session.PointerInputs));
        Assert.Equal((true, 0xff0d), Assert.Single(service.Session.KeyInputs));
    }

    private static VncSessionViewModel CreateVm(
        FakeVncSessionService service,
        FakeCredentialService? credentials = null,
        FakeCredentialRepository? credentialRepository = null,
        FakeDialogService? dialog = null,
        ITunnelRoutePrompter? prompter = null,
        TunnelManager? tunnels = null,
        IConnectionProfileResolver? profileResolver = null,
        ITransientSessionCredentialStore? transientCredentials = null)
    {
        credentials ??= new FakeCredentialService();
        credentialRepository ??= new FakeCredentialRepository();
        tunnels ??= BuildTunnelManager(credentials, new FakeTunnelConfigRepository());
        return new VncSessionViewModel(
            service,
            new FakeCredentialPasswordResolver(credentials),
            credentialRepository,
            dialog ?? new FakeDialogService(),
            tunnels,
            prompter ?? new FakeRoutePrompter(),
            profileResolver ?? new FakeProfileResolver(null),
            NullLoggerFactory.Instance,
            transientCredentials);
    }

    private static TunnelManager BuildTunnelManager(
        FakeCredentialService credentials,
        ITunnelConfigRepository repo,
        IEnumerable<ITunnelProvider>? providers = null) =>
        new(
            providers ?? Array.Empty<ITunnelProvider>(),
            repo,
            credentials,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());

    private static ConnectionProfile Profile(
        Guid? nodeId = null,
        string host = "vnc.example.com",
        Guid? credentialId = null,
        bool tunnelEnabled = false,
        Guid? tunnelConfigId = null) =>
        new()
        {
            NodeId = nodeId ?? Guid.NewGuid(),
            Name = host,
            Protocol = ProtocolType.Vnc,
            Host = host,
            Port = 5900,
            CredentialId = credentialId,
            TunnelEnabled = tunnelEnabled,
            TunnelConfigId = tunnelConfigId,
        };

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(2));
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return;
            await Task.Delay(10);
        }
        Assert.True(condition());
    }

    private sealed class FakeVncSessionService : IVncSessionService
    {
        public List<VncCall> Calls { get; } = new();
        public List<string?> Passwords { get; } = new();
        public FakeVncSession Session { get; } = new();
        public bool RequestPassword { get; set; }
        public Exception? ExceptionToThrow { get; set; }
        public TaskCompletionSource<object?>? ConnectGate { get; set; }

        public async Task<IVncSession> ConnectAsync(
            ConnectionProfile profile,
            IVncPasswordProvider passwordProvider,
            IVncRenderTarget renderTarget,
            ITunnelInstance? tunnel = null,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(new VncCall(profile, renderTarget, tunnel));
            if (RequestPassword)
            {
                var password = await passwordProvider.GetPasswordAsync(cancellationToken);
                Passwords.Add(password);
                if (password is null) throw new VncAuthenticationCancelledException();
            }
            if (ConnectGate is not null)
            {
                await ConnectGate.Task;
            }
            if (ExceptionToThrow is not null) throw ExceptionToThrow;
            return Session;
        }
    }

    private sealed record VncCall(
        ConnectionProfile Profile,
        IVncRenderTarget RenderTarget,
        ITunnelInstance? Tunnel);

    private sealed class FakeVncSession : IVncSession
    {
        public event EventHandler<VncSessionClosedEventArgs>? Closed;
        public List<IVncRenderTarget> RenderTargets { get; } = new();
        public List<(int X, int Y, VncPointerButtons Buttons)> PointerInputs { get; } = new();
        public List<(bool IsDown, int KeySymbol)> KeyInputs { get; } = new();
        public int DisposeCount { get; private set; }

        public void SetRenderTarget(IVncRenderTarget renderTarget) => RenderTargets.Add(renderTarget);

        public Task SendPointerAsync(
            int x,
            int y,
            VncPointerButtons buttons,
            CancellationToken cancellationToken = default)
        {
            PointerInputs.Add((x, y, buttons));
            return Task.CompletedTask;
        }

        public Task SendKeyAsync(bool isDown, int keySymbol, CancellationToken cancellationToken = default)
        {
            KeyInputs.Add((isDown, keySymbol));
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }

        public void RaiseClosed(bool clean, string message) =>
            Closed?.Invoke(this, new VncSessionClosedEventArgs(clean, message));
    }

    private sealed class FakeRenderTarget : IVncRenderTarget
    {
        public IFramebufferReference GrabFramebufferReference(Size size, IImmutableSet<Screen> layout) =>
            throw new NotSupportedException();
    }

    private sealed class DisposableRenderTarget : IVncRenderTarget, IDisposable
    {
        public int DisposeCount { get; private set; }

        public IFramebufferReference GrabFramebufferReference(Size size, IImmutableSet<Screen> layout) =>
            throw new NotSupportedException();

        public void Dispose() => DisposeCount++;
    }

    private sealed class FakeRoutePrompter : ITunnelRoutePrompter
    {
        private readonly ConnectionProfile? _result;
        private readonly bool _passthrough;

        public FakeRoutePrompter()
        {
            _passthrough = true;
        }

        public FakeRoutePrompter(ConnectionProfile? result)
        {
            _result = result;
        }

        public Task<ConnectionProfile?> ResolveRouteAsync(ConnectionProfile profile, CancellationToken cancellationToken) =>
            Task.FromResult(_passthrough ? profile : _result);
    }

    private sealed class FakeProfileResolver : IConnectionProfileResolver
    {
        private readonly ConnectionProfile? _result;

        public FakeProfileResolver(ConnectionProfile? result) => _result = result;

        public Guid? LastNodeId { get; private set; }

        public Task<ConnectionProfile?> ResolveAsync(Guid nodeId, CancellationToken cancellationToken = default)
        {
            LastNodeId = nodeId;
            return Task.FromResult(_result);
        }
    }

    private sealed class FakeTunnelProvider : ITunnelProvider
    {
        private readonly ITunnelInstance _instance;

        public FakeTunnelProvider(ITunnelInstance instance) => _instance = instance;

        public TunnelKind Kind => TunnelKind.WireGuard;

        public Task<ITunnelInstance> EstablishAsync(
            TunnelConfig config,
            byte[] secretBlob,
            CancellationToken cancellationToken,
            IProgress<TunnelProgress>? progress = null) =>
            Task.FromResult(_instance);
    }

    private sealed class FakeTunnelInstance : ITunnelInstance
    {
        public TunnelState State => TunnelState.Up;
        public IPEndPoint? Socks5Endpoint => null;
        public event EventHandler<TunnelStateChangedEventArgs>? StateChanged { add { } remove { } }

        public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken) =>
            Task.FromResult(59000);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
