using Wormhole.Data;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class QuickConnectViewModelTests
{
    [Fact]
    public async Task Open_CancelledDialog_DoesNotOpenTab()
    {
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService());

        await vm.OpenCommand.ExecuteAsync(null);

        Assert.Empty(factory.Opened);
    }

    [Fact]
    public async Task Open_WhileDialogIsActive_DisablesConcurrentExecution()
    {
        var dialog = new BlockingQuickConnectDialogService();
        var vm = CreateVm(new CapturingSessionTabFactory(), dialog);

        var execution = vm.OpenCommand.ExecuteAsync(null);
        await dialog.WaitUntilPromptedAsync();

        Assert.False(vm.OpenCommand.CanExecute(null));
        Assert.Equal(1, dialog.PromptCount);

        dialog.Complete(null);
        await execution;

        Assert.True(vm.OpenCommand.CanExecute(null));
    }

    [Theory]
    [InlineData(ProtocolType.Ssh, 22)]
    [InlineData(ProtocolType.Rdp, 3389)]
    [InlineData(ProtocolType.Http, 80)]
    [InlineData(ProtocolType.Https, 443)]
    [InlineData(ProtocolType.Vnc, 5900)]
    [InlineData(ProtocolType.Serial, 0)]
    public async Task Open_AllProtocols_ProducesEphemeralProfile(ProtocolType protocol, int expectedPort)
    {
        var node = NewNode(protocol);
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, null),
        });

        await vm.OpenCommand.ExecuteAsync(null);

        var profile = Assert.Single(factory.Opened);
        Assert.True(profile.IsEphemeral);
        Assert.Equal(protocol, profile.Protocol);
        Assert.Equal(expectedPort, profile.Port);
        Assert.Equal(node.Id, profile.NodeId);
    }

    [Fact]
    public async Task Open_WithManualPassword_StoresSecretOnlyInTransientStore()
    {
        var node = NewNode(ProtocolType.Ssh);
        node.Username = "alice";
        node.UseInlinePassword = true;
        var store = new TransientSessionCredentialStore();
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, "session-secret"),
        }, store);

        await vm.OpenCommand.ExecuteAsync(null);

        Assert.Equal("session-secret", store.Read(node.Id));
        Assert.Null(node.PendingInlinePassword);
        Assert.True(Assert.Single(factory.Opened).UseInlinePassword);
    }

    [Fact]
    public async Task Open_Https_PreservesCustomPortAndCertificatePolicy()
    {
        var node = NewNode(ProtocolType.Https);
        node.Port = 8443;
        node.HttpIgnoreCertErrors = true;
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, null),
        });

        await vm.OpenCommand.ExecuteAsync(null);

        var profile = Assert.Single(factory.Opened);
        Assert.Equal(8443, profile.Port);
        Assert.True(profile.HttpIgnoreCertErrors);
    }

    [Fact]
    public async Task Open_Rdp_PreservesSavedCredentialAdvancedOptionsAndTunnel()
    {
        var credentialId = Guid.NewGuid();
        var tunnelId = Guid.NewGuid();
        var node = NewNode(ProtocolType.Rdp);
        node.Port = 3390;
        node.Username = "CORP\\alice";
        node.CredentialMode = CredentialBindingMode.Saved;
        node.CredentialId = credentialId;
        node.RdpFullScreen = true;
        node.RdpColorDepth = 24;
        node.RdpRedirectClipboard = false;
        node.RdpServerAuthentication = 1;
        node.TunnelEnabled = true;
        node.TunnelConfigId = tunnelId;
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, null),
        });

        await vm.OpenCommand.ExecuteAsync(null);

        var profile = Assert.Single(factory.Opened);
        Assert.Equal(3390, profile.Port);
        Assert.Equal(credentialId, profile.CredentialId);
        Assert.True(profile.RdpFullScreen);
        Assert.Equal(24, profile.RdpColorDepth);
        Assert.False(profile.RdpRedirectClipboard);
        Assert.Equal(1, profile.RdpServerAuthentication);
        Assert.True(profile.TunnelEnabled);
        Assert.Equal(tunnelId, profile.TunnelConfigId);
    }

    [Fact]
    public async Task Open_Serial_PreservesExplicitSettingsAndDisablesTunnel()
    {
        var node = NewNode(ProtocolType.Serial);
        node.SerialBaudRate = 115200;
        node.SerialDataBits = 7;
        node.SerialStopBits = SerialStopBitsMode.Two;
        node.SerialParity = SerialParityMode.Even;
        node.SerialFlowControl = SerialFlowControlMode.DsrDtr;
        node.TunnelEnabled = true;
        node.TunnelConfigId = Guid.NewGuid();
        var factory = new CapturingSessionTabFactory();
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, null),
        });

        await vm.OpenCommand.ExecuteAsync(null);

        var profile = Assert.Single(factory.Opened);
        Assert.Equal(115200, profile.SerialBaudRate);
        Assert.Equal(7, profile.SerialDataBits);
        Assert.Equal(SerialStopBitsMode.Two, profile.SerialStopBits);
        Assert.Equal(SerialParityMode.Even, profile.SerialParity);
        Assert.Equal(SerialFlowControlMode.DsrDtr, profile.SerialFlowControl);
        Assert.False(profile.TunnelEnabled);
        Assert.Null(profile.TunnelConfigId);
    }

    [Fact]
    public async Task Open_WhenTabFactoryThrows_RemovesTransientPassword()
    {
        var node = NewNode(ProtocolType.Vnc);
        var store = new TransientSessionCredentialStore();
        var factory = new CapturingSessionTabFactory { ThrowOnOpen = true };
        var vm = CreateVm(factory, new QuickConnectDialogService
        {
            Result = new QuickConnectResult(node, "session-secret"),
        }, store);

        await Assert.ThrowsAsync<InvalidOperationException>(() => vm.OpenCommand.ExecuteAsync(null));

        Assert.Null(store.Read(node.Id));
    }

    private static QuickConnectViewModel CreateVm(
        ISessionTabFactory factory,
        IDialogService dialogs,
        ITransientSessionCredentialStore? store = null) =>
        new(factory, dialogs, new InheritanceResolver(), store ?? new TransientSessionCredentialStore());

    private static ConnectionNode NewNode(ProtocolType protocol) => new()
    {
        Id = Guid.NewGuid(),
        Kind = NodeKind.Connection,
        Name = "quick-target",
        Protocol = protocol,
        Host = protocol == ProtocolType.Serial ? "COM3" : "target.example.com",
        CredentialMode = CredentialBindingMode.None,
        TunnelEnabled = false,
        SerialBaudRate = SerialDefaults.BaudRate,
        SerialDataBits = SerialDefaults.DataBits,
        SerialStopBits = SerialDefaults.StopBits,
        SerialParity = SerialDefaults.Parity,
        SerialFlowControl = SerialDefaults.FlowControl,
    };

    private sealed class QuickConnectDialogService : FakeDialogService
    {
        public QuickConnectResult? Result { get; init; }

        public override Task<QuickConnectResult?> PromptQuickConnectAsync() => Task.FromResult(Result);
    }

    private sealed class BlockingQuickConnectDialogService : FakeDialogService
    {
        private readonly TaskCompletionSource _prompted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<QuickConnectResult?> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int PromptCount { get; private set; }

        public override Task<QuickConnectResult?> PromptQuickConnectAsync()
        {
            PromptCount++;
            _prompted.TrySetResult();
            return _completion.Task;
        }

        public Task WaitUntilPromptedAsync() => _prompted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        public void Complete(QuickConnectResult? result) => _completion.TrySetResult(result);
    }

    private sealed class CapturingSessionTabFactory : ISessionTabFactory
    {
        public List<ConnectionProfile> Opened { get; } = new();
        public bool ThrowOnOpen { get; init; }

        public void Open(ConnectionProfile profile)
        {
            if (ThrowOnOpen) throw new InvalidOperationException("open failed");
            Opened.Add(profile);
        }
    }
}
